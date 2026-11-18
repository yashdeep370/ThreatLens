const $ = s => document.querySelector(s);
const ICON = { safe: "🟢", warning: "🟠", danger: "🔴" };

function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

function render(a, backend) {
  const m = a.model, live = a.live;
  const flags = m.red_flags.slice(0, 4);
  let liveHtml = `<div class="note">Live check skipped: ${esc(live.reason)}</div>`;
  if (live.performed) {
    const missing = live.headers.filter(h => !h.present).map(h => h.header);
    const cert = live.certificate;
    liveHtml = `<ul class="checks">
      <li>${live.https ? '<span class="ok">✓</span> Uses HTTPS' : '<span class="bad">✕</span> No HTTPS'}</li>
      ${live.https ? `<li>${cert && cert.valid ? `<span class="ok">✓</span> Valid certificate (${cert.days_left} days left)` : '<span class="bad">✕</span> Invalid certificate'}</li>` : ""}
      <li>${missing.length ? `<span class="bad">✕</span> Missing ${missing.length} security header(s): ${esc(missing.join(", "))}` : '<span class="ok">✓</span> All key security headers present'}</li>
      ${live.cross_domain_redirect ? '<li><span class="bad">!</span> Redirects to another domain</li>' : ""}
    </ul>`;
  }
  $("#result").innerHTML = `
    <div class="banner ${a.status.level}">
      <div>${ICON[a.status.level]}</div>
      <div><b>${esc(a.status.headline)}</b><div class="note" style="margin:2px 0 0">ML verdict: ${esc(m.label)} (${(m.confidence * 100).toFixed(0)}%)</div></div>
      <div class="score">${a.score.value}<span>/100</span></div>
    </div>
    ${m.reputation && m.reputation.note ? `<div class="card"><div class="note" style="margin:0">${esc(m.reputation.note)}</div></div>` : ""}
    ${flags.length ? `<div class="card"><div class="label">Red flags</div><ul>${flags.map(f => `<li>${esc(f)}</li>`).join("")}</ul></div>` : ""}
    <div class="card"><div class="label">Site security</div>${liveHtml}</div>
    ${a.playbook ? `<div class="card"><div class="label">What to do</div><ul>${a.playbook.recommendations.slice(0, 3).map(r => `<li>${esc(r.action)}</li>`).join("")}</ul></div>` : ""}
    <button class="btn ghost" id="open-report">Open full report & ask AI</button>`;
  $("#open-report").addEventListener("click", () => chrome.tabs.create({ url: `${backend}/#analysis=${a.id}` }));
}

async function runCheck(url) {
  const { backend } = await getSettings();
  $("#target").textContent = url;
  $("#result").innerHTML = "";
  $("#loading").hidden = false;
  try {
    render(await checkUrl(url, { live: true, save: true }), backend);
  } catch (e) {
    $("#result").innerHTML = `<div class="error">Can't reach the ThreatLens backend at <b>${esc(backend)}</b>.<br>
      Start it with <code>python -m uvicorn backend.app:app</code> in the project folder.</div>`;
  } finally {
    $("#loading").hidden = true;
  }
}

async function init() {
  const s = await getSettings();
  $("#backend").value = s.backend;
  $("#auto").checked = s.autoCheck;
  $("#notify").checked = s.notify;
  $("#block").checked = s.block;

  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (tab && isCheckable(tab.url, s.backend)) runCheck(tab.url);
  else $("#target").textContent = "This page can't be checked (browser or local page). Enter a link below.";
}

$("#settings-btn").addEventListener("click", () => { $("#settings").hidden = !$("#settings").hidden; });
$("#save").addEventListener("click", async () => {
  await chrome.storage.local.set({ backend: $("#backend").value.trim() || DEFAULT_BACKEND,
                                   autoCheck: $("#auto").checked, notify: $("#notify").checked,
                                   block: $("#block").checked });
  $("#settings").hidden = true;
});
$("#manual").addEventListener("submit", e => {
  e.preventDefault();
  const url = $("#manual-url").value.trim();
  if (url) runCheck(url);
});

init();
