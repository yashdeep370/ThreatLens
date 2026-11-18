const $ = s => document.querySelector(s);
const target = new URLSearchParams(location.search).get("url") || "";

function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

async function load() {
  $("#url").textContent = target;
  try {
    const a = await checkUrl(target); // quick check, not saved to history
    const m = a.model;
    $("#headline").textContent = a.status.headline;
    $("#threat").textContent = a.threat ? a.threat.toLowerCase() : "malicious";
    $("#conf").textContent = `${(m.confidence * 100).toFixed(0)}%`;
    $("#conf-bar").style.width = `${(m.confidence * 100).toFixed(0)}%`;
    $("#flags").innerHTML = (m.red_flags.length ? m.red_flags : ["The URL pattern closely matches known malicious URLs"])
      .map(f => `<li>${esc(f)}</li>`).join("");
    if (a.playbook) {
      $("#impact").textContent = a.playbook.impact;
      $("#actions").innerHTML = a.playbook.recommendations.slice(0, 4).map(r => `<li>${esc(r.action)}</li>`).join("");
    }
  } catch {
    $("#flags").innerHTML = "<li>Details unavailable (ThreatLens backend not reachable)</li>";
  }
}

$("#back").addEventListener("click", async () => {
  // Going "back" could land on the dangerous URL again; a fresh new-tab page is always safe.
  const tab = await chrome.tabs.getCurrent();
  chrome.tabs.update(tab.id, { url: "chrome://newtab" });
});
$("#details-toggle").addEventListener("click", () => { $("#details").hidden = !$("#details").hidden; });
$("#proceed").addEventListener("click", async () => {
  const host = new URL(target).hostname;
  const { allowed = [] } = await chrome.storage.session.get("allowed");
  await chrome.storage.session.set({ allowed: [...new Set([...allowed, host])] });
  location.href = target;
});

load();
