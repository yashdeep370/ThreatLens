// Shared by the service worker and the popup.
const DEFAULT_BACKEND = "http://127.0.0.1:8000";

async function getSettings() {
  const s = await chrome.storage.local.get({ backend: DEFAULT_BACKEND, autoCheck: true, notify: true });
  s.backend = s.backend.replace(/\/+$/, "");
  return s;
}

// Only real web pages; skip browser pages, local files and the ThreatLens site itself.
function isCheckable(url, backend) {
  if (!url || !/^https?:\/\//i.test(url)) return false;
  try {
    const host = new URL(url).hostname;
    if (["localhost", "127.0.0.1", "0.0.0.0"].includes(host)) return false;
    return !url.startsWith(backend);
  } catch {
    return false;
  }
}

async function checkUrl(url, { live = false, save = false } = {}) {
  const { backend } = await getSettings();
  const res = await fetch(`${backend}/api/analyze/url`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url, live, save }),
  });
  if (!res.ok) throw new Error(`Backend error ${res.status}`);
  return res.json();
}

const BADGE = {
  safe: { text: "OK", color: "#16a34a" },
  warning: { text: "!", color: "#f59e0b" },
  danger: { text: "✕", color: "#dc2626" },
  error: { text: "?", color: "#64748b" },
};
