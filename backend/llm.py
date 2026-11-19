"""LLM client that works with Gemini or Groq free-tier keys.

Configuration (.env), any of:
  GEMINI_API_KEY=...        GROQ_API_KEY=...
  LLM_API_KEY=...           (provider auto-detected: 'gsk_' = Groq, 'AIza' = Gemini)
  LLM_PROVIDER=gemini|groq  (optional preference when both keys exist)
  GEMINI_MODEL=... / GROQ_MODEL=...  (optional model override)

Reliability: plain HTTPS calls (no SDK version issues), one retry on rate-limit /
server errors, fallback to alternate models if one is retired, and fallback to
the other provider if both keys are set. If everything fails, LLMUnavailable is
raised and the caller answers from the knowledge base instead.
"""
import os
import re
import time

import requests
import truststore

# Use the operating system's certificate store instead of requests' bundled list:
# antivirus HTTPS scanning (e.g. Avast) re-signs traffic with a root only the OS trusts.
truststore.inject_into_ssl()

TIMEOUT = 40
MAX_MODEL_ATTEMPTS = 3  # per provider, so a failing chat answers (offline) within ~2 minutes
GEMINI_URL = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
GEMINI_LIST_URL = "https://generativelanguage.googleapis.com/v1beta/models?pageSize=200"
GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"
# Used only if model discovery fails. Google retires models for new keys over time,
# so the live list from the API (see _gemini_models) is preferred.
GEMINI_FALLBACK_MODELS = ["gemini-flash-latest", "gemini-flash-lite-latest", "gemini-2.5-flash"]
GROQ_MODELS = ["llama-3.3-70b-versatile", "llama-3.1-8b-instant"]
_FLASH_RE = re.compile(r"^models/gemini-(\d+(?:\.\d+)?)-flash(-lite)?$")
_gemini_cache: list[str] | None = None


class LLMUnavailable(Exception):
    pass


# Last failure, shown in /api/status so deployment problems can be diagnosed
# without server log access. Anything that looks like an API key is removed.
_last_error: str | None = None
_KEY_RE = re.compile(r"(AIza[0-9A-Za-z_\-]{10,}|gsk_[0-9A-Za-z]{10,})")


def _redact(text: str) -> str:
    return _KEY_RE.sub("[redacted]", text)[:500]


class _ModelNotFound(Exception):
    pass


class _Busy(Exception):
    """Rate-limited or overloaded (429 / 5xx): another model may still work."""


def _keys() -> dict:
    keys = {}
    if os.getenv("GEMINI_API_KEY"):
        keys["gemini"] = os.getenv("GEMINI_API_KEY").strip()
    if os.getenv("GROQ_API_KEY"):
        keys["groq"] = os.getenv("GROQ_API_KEY").strip()
    generic = (os.getenv("LLM_API_KEY") or "").strip()
    if generic:
        if generic.startswith("gsk_"):
            keys.setdefault("groq", generic)
        elif generic.startswith("AIza"):
            keys.setdefault("gemini", generic)
        else:
            keys.setdefault((os.getenv("LLM_PROVIDER") or "gemini").lower(), generic)
    return keys


def providers() -> list[str]:
    keys = _keys()
    preferred = (os.getenv("LLM_PROVIDER") or "").lower()
    order = sorted(keys, key=lambda p: p != preferred)
    return [p for p in order if p in ("gemini", "groq")]


def status() -> dict:
    p = providers()
    return {"available": bool(p), "providers": p, "last_error": _last_error}


def _post(url, headers, body):
    for attempt in range(2):
        r = requests.post(url, headers=headers, json=body, timeout=TIMEOUT)
        if r.status_code in (429, 500, 502, 503) and attempt == 0:
            time.sleep(2)
            continue
        if r.status_code == 404 or (r.status_code == 400 and "model" in r.text.lower()
                                    and ("decommission" in r.text.lower() or "not found" in r.text.lower())):
            raise _ModelNotFound(r.text[:200])
        if r.status_code in (429, 500, 502, 503, 504):
            raise _Busy(f"HTTP {r.status_code}: {r.text[:200]}")
        if not r.ok:
            raise RuntimeError(f"HTTP {r.status_code}: {r.text[:300]}")
        return r.json()


def _gemini_models(key) -> list[str]:
    """Models this key can actually use: stable '-flash-lite' models first (fast
    replies; explaining an existing analysis doesn't need the largest model), then
    '-flash' models, newest version first within each group."""
    global _gemini_cache
    if _gemini_cache is not None:
        return _gemini_cache
    try:
        r = requests.get(GEMINI_LIST_URL, headers={"x-goog-api-key": key}, timeout=15)
        r.raise_for_status()
        found = []
        for m in r.json().get("models", []):
            match = _FLASH_RE.match(m.get("name", ""))
            if match and "generateContent" in m.get("supportedGenerationMethods", []):
                found.append((not match.group(2), -float(match.group(1)), m["name"].split("/", 1)[1]))
        _gemini_cache = [name for *_, name in sorted(found)] + GEMINI_FALLBACK_MODELS
    except Exception:
        return GEMINI_FALLBACK_MODELS  # don't cache: retry discovery on the next call
    return _gemini_cache


def _gemini(key, system, messages, model):
    body = {
        "systemInstruction": {"parts": [{"text": system}]},
        "contents": [{"role": "model" if m["role"] == "assistant" else "user", "parts": [{"text": m["content"]}]}
                     for m in messages],
        # Generous limit: newer Gemini models spend part of it on internal reasoning.
        "generationConfig": {"temperature": 0.3, "maxOutputTokens": 4096},
    }
    data = _post(GEMINI_URL.format(model=model), {"x-goog-api-key": key}, body)
    parts = data.get("candidates", [{}])[0].get("content", {}).get("parts", [])
    text = "".join(p.get("text", "") for p in parts).strip()
    if not text:
        raise RuntimeError(f"Empty Gemini response: {str(data)[:200]}")
    return text


def _groq(key, system, messages, model):
    body = {
        "model": model,
        "messages": [{"role": "system", "content": system}] + messages,
        "temperature": 0.3,
        "max_tokens": 1024,
    }
    data = _post(GROQ_URL, {"Authorization": f"Bearer {key}"}, body)
    return data["choices"][0]["message"]["content"].strip()


def chat(system: str, messages: list[dict]) -> tuple[str, str]:
    """messages: [{"role": "user"|"assistant", "content": str}, ...].
    Returns (answer, "provider/model")."""
    global _last_error
    keys = _keys()
    errors = []
    for provider in providers():
        call, models, env_model = (
            (_gemini, _gemini_models(keys["gemini"]), "GEMINI_MODEL") if provider == "gemini"
            else (_groq, GROQ_MODELS, "GROQ_MODEL")
        )
        override = os.getenv(env_model)
        candidates = list(dict.fromkeys(([override] if override else []) + models))
        for model in candidates[:MAX_MODEL_ATTEMPTS]:
            try:
                answer = call(keys[provider], system, messages, model)
                _last_error = None
                return answer, f"{provider}/{model}"
            except _ModelNotFound as e:
                errors.append(f"{provider}/{model}: model unavailable ({e})")
                continue
            except requests.exceptions.Timeout:
                errors.append(f"{provider}/{model}: timed out after {TIMEOUT}s")
                continue
            except _Busy as e:
                errors.append(f"{provider}/{model}: busy ({e})")
                continue
            except Exception as e:  # auth, quota, network: try the next provider
                errors.append(f"{provider}/{model}: {e}")
                break
    _last_error = _redact("; ".join(errors) or "No LLM API key configured")
    raise LLMUnavailable(_last_error)
