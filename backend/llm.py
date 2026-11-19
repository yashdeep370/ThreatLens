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

TIMEOUT = 30
GEMINI_URL = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"
GEMINI_MODELS = ["gemini-2.5-flash", "gemini-flash-latest", "gemini-2.0-flash"]
GROQ_MODELS = ["llama-3.3-70b-versatile", "llama-3.1-8b-instant"]


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
        if not r.ok:
            raise RuntimeError(f"HTTP {r.status_code}: {r.text[:300]}")
        return r.json()


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
            (_gemini, GEMINI_MODELS, "GEMINI_MODEL") if provider == "gemini"
            else (_groq, GROQ_MODELS, "GROQ_MODEL")
        )
        override = os.getenv(env_model)
        for model in ([override] if override else []) + models:
            try:
                answer = call(keys[provider], system, messages, model)
                _last_error = None
                return answer, f"{provider}/{model}"
            except _ModelNotFound as e:
                errors.append(f"{provider}/{model}: model unavailable ({e})")
                continue
            except Exception as e:  # network, auth, quota: try the next provider
                errors.append(f"{provider}/{model}: {e}")
                break
    _last_error = _redact("; ".join(errors) or "No LLM API key configured")
    raise LLMUnavailable(_last_error)
