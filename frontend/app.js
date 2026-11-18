// ThreatLens frontend - plain JS, talks to the FastAPI backend.
const $ = (s, el = document) => el.querySelector(s);
const $$ = (s, el = document) => [...el.querySelectorAll(s)];

const state = { chatAnalysis: null, chatHistory: [], chart: null };

const LABELS = { Benign: "Benign", DoS: "DoS", DDoS: "DDoS", BruteForce: "Brute force", PortScan: "Port scan", Anomaly: "Anomaly" };
const CLASS_COLORS = { Benign: "#22c55e", DoS: "#ef4444", DDoS: "#b91c1c", BruteForce: "#f97316", PortScan: "#eab308", Anomaly: "#a855f7" };
const BAND_COLORS = { low: "var(--safe)", moderate: "var(--moderate)", high: "var(--high)", critical: "var(--critical)" };
const STATUS_ICON = { safe: "🟢", warning: "🟠", danger: "🔴" };

// ---------- helpers ----------
function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}
const pct = (v, d = 1) => `${(v * 100).toFixed(d)}%`;
const num = v => Number(v).toLocaleString();
const fmtTime = iso => new Date(iso).toLocaleString([], { dateStyle: "medium", timeStyle: "short" });

function bandOf(score) {
  if (score >= 90) return ["low", "Low observed risk"];
  if (score >= 70) return ["moderate", "Moderate risk"];
  if (score >= 40) return ["high", "High risk"];
  return ["critical", "Critical risk"];
}

// Minimal, safe markdown: escape first, then bold / lists / paragraphs.
function md(text) {
  const lines = esc(text).replace(/\*\*(.+?)\*\*/g, "<b>$1</b>").replace(/`([^`]+)`/g, "<code>$1</code>").split("\n");
  let html = "", list = null;
  for (const raw of lines) {
    const line = raw.trim();
    const ul = line.match(/^[-*•]\s+(.*)/), ol = line.match(/^\d+[.)]\s+(.*)/);
    const type = ul ? "ul" : ol ? "ol" : null;
    if (list && list !== type) { html += `</${list}>`; list = null; }
    if (type) {
      if (!list) { html += `<${type}>`; list = type; }
      html += `<li>${(ul || ol)[1]}</li>`;
    } else if (line) html += `<p>${line}</p>`;
  }
  return html + (list ? `</${list}>` : "");
}

async function api(path, opts = {}) {
  const res = await fetch(path, opts);
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.detail ? (typeof data.detail === "string" ? data.detail : JSON.stringify(data.detail)) : `Request failed (${res.status})`);
  return data;
}

function gauge(score, size = 220) {
  const [band, label] = bandOf(score);
  const r = 80, c = Math.PI * r, filled = c * score / 100;
  return `<svg viewBox="0 0 200 120" width="${size}" style="max-width:100%">
      <path d="M20 100 A80 80 0 0 1 180 100" fill="none" stroke="var(--panel-2)" stroke-width="16" stroke-linecap="round"/>
      <path d="M20 100 A80 80 0 0 1 180 100" fill="none" stroke="${BAND_COLORS[band]}" stroke-width="16" stroke-linecap="round"
            stroke-dasharray="${filled} ${c}"/>
    </svg>
    <div class="gauge-num" style="margin-top:-62px">${score}<span class="muted" style="font-size:16px">/100</span></div>
    <div class="gauge-band" style="color:${BAND_COLORS[band]}">${label}</div>`;
}

function banner(status, sub = "") {
  return `<div class="banner ${status.level}"><div class="icon">${STATUS_ICON[status.level]}</div>
    <div><h2>${esc(status.headline)}</h2>${sub ? `<div class="muted">${sub}</div>` : ""}</div>
    <div style="margin-left:auto" class="no-print"><button class="btn small" data-action="print">Print report</button></div></div>`;
}

function mitreTags(ids) {
  return (ids || []).map(id => `<a class="mitre-tag" target="_blank" rel="noopener"
      href="https://attack.mitre.org/techniques/${esc(id.replace(".", "/"))}/">${esc(id)}</a>`).join("") || '<span class="muted">-</span>';
}

function recList(recs) {
  return `<ol>${(recs || []).map(r => `<li>${esc(r.action)}<div class="rec-why">${esc(r.why)}</div></li>`).join("")}</ol>`;
}

// ---------- navigation ----------
function show(view) {
  $$(".view").forEach(v => v.classList.toggle("active", v.id === `view-${view}`));
  $$(".nav-item").forEach(n => n.classList.toggle("active", n.dataset.view === view));
  if (view === "dashboard") loadDashboard();
  if (view === "history") loadHistory();
  window.scrollTo(0, 0);
}
$$(".nav-item").forEach(n => n.addEventListener("click", () => show(n.dataset.view)));
document.addEventListener("click", e => {
  const go = e.target.closest("[data-goto]");
  if (go) show(go.dataset.goto);
  if (e.target.closest("[data-action=print]")) window.print();
  const head = e.target.closest(".incident-head");
  if (head) head.parentElement.classList.toggle("open");
  const ask = e.target.closest("[data-ask]");
  if (ask) openChat(ask.dataset.ask);
});

// ---------- status ----------
async function loadStatus() {
  try {
    const s = await api("/api/status");
    $("#dot-model").className = "dot ok";
    $("#sys-model").textContent = `Models ready · ${s.flow_model}`;
    $("#dot-llm").className = `dot ${s.llm.available ? "ok" : "warn"}`;
    $("#sys-llm").textContent = s.llm.available ? `AI: ${s.llm.providers.join(" → ")}` : "AI: offline mode (no API key)";
    $("#about-models").innerHTML = `Flow classifier: <b>${esc(s.flow_model)}</b> · classes: ${s.flow_classes.map(esc).join(", ")} ·
      knowledge base: ${s.knowledge_chunks} chunks (MITRE ATT&amp;CK + playbooks) · chatbot: ${s.llm.available ? esc(s.llm.providers.join(", ")) : "offline knowledge-base mode"}`;
  } catch {
    $("#sys-model").textContent = "Backend unreachable";
  }
}

// ---------- traffic ----------
async function loadSamples() {
  const names = await api("/api/samples").catch(() => []);
  $("#samples").innerHTML = names.length
    ? names.map(n => `<button class="btn" data-sample="${esc(n)}">▶ ${esc(n.replace(/^\d+_/, "").replace(".csv", "").replace(/_/g, " "))}</button>`).join("")
    : '<span class="muted small">No samples found. Run <code>python -m src.make_demo_samples</code></span>';
  $$("[data-sample]").forEach(b => b.addEventListener("click", () => runTraffic(() =>
    api(`/api/analyze/sample/${encodeURIComponent(b.dataset.sample)}`, { method: "POST" }))));
}

async function runTraffic(request) {
  $("#traffic-result").innerHTML = "";
  $("#traffic-loading").hidden = false;
  try {
    const a = await request();
    renderTraffic(a);
    setChatAnalysis(a);
  } catch (e) {
    $("#traffic-result").innerHTML = `<div class="error">${esc(e.message)}</div>`;
  } finally {
    $("#traffic-loading").hidden = true;
  }
}

function uploadFile(file) {
  const fd = new FormData();
  fd.append("file", file);
  runTraffic(() => api("/api/analyze/flows", { method: "POST", body: fd }));
}
$("#file-input").addEventListener("change", e => e.target.files[0] && uploadFile(e.target.files[0]));
const dz = $("#dropzone");
["dragenter", "dragover"].forEach(ev => dz.addEventListener(ev, e => { e.preventDefault(); dz.classList.add("drag"); }));
["dragleave", "drop"].forEach(ev => dz.addEventListener(ev, e => { e.preventDefault(); dz.classList.remove("drag"); }));
dz.addEventListener("drop", e => e.dataTransfer.files[0] && uploadFile(e.dataTransfer.files[0]));

function incidentCard(i, open) {
  return `<div class="incident ${open ? "open" : ""}">
    <div class="incident-head">
      <div><h3>${esc(i.title)}</h3>
        <div class="incident-meta"><span class="sev ${i.severity}">${i.severity}</span>
          <span>Confidence <b>${pct(i.confidence)}</b></span><span>${num(i.flows)} flows (${pct(i.share)})</span>
          <span>Score impact −${i.penalty}</span></div></div>
      <span class="chev">▶</span>
    </div>
    <div class="incident-body">
      <p class="muted" style="margin:0">${esc(i.summary)}</p>
      <div class="report-section"><h4>Evidence</h4><ul>${i.evidence.map(e => `<li>${esc(e)}</li>`).join("")}</ul></div>
      <div class="report-section"><h4>Potential impact</h4><div>${esc(i.impact)}</div></div>
      <div class="report-section"><h4>Threat intelligence (MITRE ATT&amp;CK)</h4>${mitreTags(i.mitre)}</div>
      <div class="report-section"><h4>Recommended actions</h4>${recList(i.recommendations)}</div>
      <div class="report-section no-print"><button class="btn small" data-ask="Why was this classified as ${esc(i.title)} and what should I do first?">💬 Ask AI about this incident</button></div>
    </div></div>`;
}

function renderTraffic(a) {
  const ev = a.evaluation;
  const iso = a.isolated_detections || [];
  const dist = Object.entries(a.class_distribution).sort((x, y) => y[1] - x[1]);
  $("#traffic-result").innerHTML = `
    ${banner(a.status, `${esc(a.filename)} · ${num(a.total_flows)} flows · analyzed ${fmtTime(a.analyzed_at)}`)}
    <div class="grid-hero">
      <div class="card score-card"><div class="card-label">Security posture</div>${gauge(a.score.value)}
        <div class="score-note">Observed-risk score · not a guarantee of security</div></div>
      <div class="card"><div class="card-label">Traffic classification</div>
        <div style="display:grid;grid-template-columns:170px 1fr;gap:18px;align-items:center">
          <div style="height:170px"><canvas id="dist-chart"></canvas></div>
          <div>${dist.map(([c, n]) => `<div class="bar-row"><span>${LABELS[c] || esc(c)}</span>
            <div class="bar"><span style="width:${(n / a.total_flows * 100).toFixed(1)}%;background:${CLASS_COLORS[c] || "var(--accent)"}"></span></div>
            <span class="mono small">${num(n)}</span></div>`).join("")}</div>
        </div></div>
    </div>
    <div class="tiles">
      <div class="tile"><div class="l">Flows analyzed</div><div class="v">${num(a.total_flows)}</div></div>
      <div class="tile"><div class="l">Threats detected</div><div class="v">${a.threats_detected}</div></div>
      <div class="tile"><div class="l">Malicious / unusual flows</div><div class="v">${num(a.malicious_flows)}</div></div>
      <div class="tile"><div class="l">Mean model confidence</div><div class="v">${pct(a.mean_confidence)}</div></div>
    </div>
    <div class="card"><div class="card-label">Security incidents</div>
      ${a.incidents.length ? a.incidents.map((i, n) => incidentCard(i, n === 0)).join("")
        : '<p class="muted" style="margin:0">No incidents. Traffic matches normal patterns learned by the model.</p>'}
      ${iso.length ? `<p class="muted small" style="margin:10px 0 0">Isolated detections (below the ${5}-flow incident threshold, likely misclassifications, no score impact):
        ${iso.map(d => `${esc(LABELS[d.threat] || d.threat)} × ${d.flows}`).join(", ")}</p>` : ""}
    </div>
    <div class="grid-2">
      <div class="card"><div class="card-label">Anomaly detector (Isolation Forest)</div>
        <p style="margin:0 0 6px">${num(a.anomaly.flagged)} of ${num(a.anomaly.checked)} benign-classified flows look unusual
          (<b>${pct(a.anomaly.rate)}</b>, expected noise ≈ ${pct(a.anomaly.expected_rate, 0)}).</p>
        <p class="muted small" style="margin:0">${a.anomaly.reported ? "Rate is well above the noise level, so it is reported as an incident."
          : "Within the expected noise level, so not reported as an incident."}</p></div>
      <div class="card"><div class="card-label">Score breakdown</div>
        ${a.score.breakdown.length ? `<table class="table">${a.score.breakdown.map(b => `<tr><td>${esc(b.threat)}</td><td class="mono">−${b.penalty}</td></tr>`).join("")}
          <tr><td><b>Final score</b></td><td class="mono"><b>${a.score.value}</b></td></tr></table>`
          : '<p class="muted" style="margin:0">No deductions. Starting score 100.</p>'}
        <p class="muted small" style="margin:8px 0 0">Penalty = severity weight × confidence × volume factor</p></div>
    </div>
    ${ev ? `<div class="card"><div class="card-label">Validation against ground-truth labels in this file</div>
      <div class="tiles" style="margin:0">
        <div class="tile"><div class="l">Accuracy</div><div class="v">${pct(ev.accuracy, 2)}</div></div>
        <div class="tile"><div class="l">Attack detection rate</div><div class="v">${ev.attack_detection_rate == null ? "-" : pct(ev.attack_detection_rate, 2)}</div></div>
        <div class="tile"><div class="l">False alarm rate</div><div class="v">${ev.false_alarm_rate == null ? "-" : pct(ev.false_alarm_rate, 2)}</div></div>
        <div class="tile"><div class="l">Labelled flows</div><div class="v">${num(ev.labelled_flows)}</div></div>
      </div></div>` : ""}`;

  if (state.chart) state.chart.destroy();
  state.chart = new Chart($("#dist-chart"), {
    type: "doughnut",
    data: { labels: dist.map(([c]) => LABELS[c] || c),
            datasets: [{ data: dist.map(([, n]) => n), backgroundColor: dist.map(([c]) => CLASS_COLORS[c] || "#4f8cff"), borderWidth: 0 }] },
    options: { cutout: "68%", plugins: { legend: { display: false } }, maintainAspectRatio: false },
  });
}

// ---------- website check ----------
$("#url-form").addEventListener("submit", async e => {
  e.preventDefault();
  const url = $("#url-input").value.trim();
  if (!url) return;
  $("#url-result").innerHTML = "";
  $("#url-loading").hidden = false;
  try {
    const a = await api("/api/analyze/url", { method: "POST", headers: { "Content-Type": "application/json" },
                                              body: JSON.stringify({ url, live: $("#url-live").checked }) });
    renderUrl(a);
    setChatAnalysis(a);
  } catch (err) {
    $("#url-result").innerHTML = `<div class="error">${esc(err.message)}</div>`;
  } finally {
    $("#url-loading").hidden = true;
  }
});
$$("[data-url]").forEach(b => b.addEventListener("click", () => { $("#url-input").value = b.dataset.url; $("#url-form").requestSubmit(); }));

function renderUrl(a) {
  const m = a.model, live = a.live;
  const probs = Object.entries(m.probabilities).sort((x, y) => y[1] - x[1]);
  const probColor = { benign: "var(--safe)", phishing: "var(--high)", malware: "var(--critical)", defacement: "var(--moderate)" };
  let liveHtml;
  if (!live.performed) {
    liveHtml = `<p class="muted" style="margin:0">Live check not performed: ${esc(live.reason)}</p>`;
  } else {
    const cert = live.certificate;
    const certLine = !live.https ? `<li><span class="bad">✕</span><div>No HTTPS. Traffic to this site is not encrypted.</div></li>`
      : cert && cert.valid && live.certificate_verified
        ? `<li><span class="${cert.days_left < 14 ? "warn" : "ok"}">${cert.days_left < 14 ? "!" : "✓"}</span><div>Valid certificate from <b>${esc(cert.issuer)}</b> · ${esc(cert.tls_version)} · expires ${esc(cert.expires)} (${cert.days_left} days)</div></li>`
        : `<li><span class="bad">✕</span><div>Invalid or untrusted certificate${cert && cert.error ? `: ${esc(cert.error)}` : ""}</div></li>`;
    liveHtml = `<ul class="check-list">
      <li><span class="ok">→</span><div>Final URL: <span class="mono small">${esc(live.final_url)}</span> (HTTP ${live.status_code})</div></li>
      ${certLine}
      ${live.headers.map(h => `<li><span class="${h.present ? "ok" : "bad"}">${h.present ? "✓" : "✕"}</span>
        <div><b>${esc(h.header)}</b> <span class="muted small">- ${esc(h.why)}</span></div></li>`).join("")}
      ${live.redirects.length ? `<li><span class="${live.cross_domain_redirect ? "warn" : "ok"}">↪</span><div>${live.redirects.length} redirect(s)${live.cross_domain_redirect ? " across domains" : ""}</div></li>` : ""}
      ${live.server_disclosure ? `<li><span class="warn">!</span><div>Server version disclosed: <span class="mono small">${esc(live.server_disclosure)}</span></div></li>` : ""}
    </ul>`;
  }
  $("#url-result").innerHTML = `
    ${banner(a.status, `<span class="mono">${esc(a.url)}</span> · ${fmtTime(a.analyzed_at)}`)}
    <div class="grid-hero">
      <div class="card score-card"><div class="card-label">Website safety score</div>${gauge(a.score.value)}
        <div class="score-note">URL model + passive checks · not a guarantee</div></div>
      <div class="card"><div class="card-label">URL threat classification (${esc(m.model_name || "ML model")})</div>
        ${m.reputation && m.reputation.note ? `<div class="banner ${m.label === "benign" ? "safe" : "warning"}" style="padding:10px 12px;margin-bottom:12px">
          <div class="icon" style="font-size:18px">${m.label === "benign" ? "✓" : "!"}</div><div class="small">${esc(m.reputation.note)}</div></div>` : ""}
        ${probs.map(([c, p]) => `<div class="bar-row"><span style="text-transform:capitalize">${esc(c)}</span>
          <div class="bar"><span style="width:${(p * 100).toFixed(1)}%;background:${probColor[c] || "var(--accent)"}"></span></div>
          <span class="mono small">${pct(p)}</span></div>`).join("")}
        <div class="report-section"><h4>Red flags in the URL</h4>
          ${m.red_flags.length ? `<ul>${m.red_flags.map(f => `<li>${esc(f)}</li>`).join("")}</ul>` : '<span class="muted">None found</span>'}</div>
      </div>
    </div>
    <div class="grid-2">
      <div class="card"><div class="card-label">Live security checks</div>${liveHtml}</div>
      <div class="card"><div class="card-label">Score deductions</div>
        ${a.score.deductions.length ? `<table class="table">${a.score.deductions.map(d => `<tr><td>${esc(d.reason)}</td><td class="mono">−${d.points}</td></tr>`).join("")}
          <tr><td><b>Final score</b></td><td class="mono"><b>${a.score.value}</b></td></tr></table>` : '<p class="muted" style="margin:0">No deductions.</p>'}
      </div>
    </div>
    ${a.playbook ? `<div class="card"><div class="card-label">Threat report · ${esc(a.playbook.title)}</div>
      <p class="muted" style="margin:0">${esc(a.playbook.summary)}</p>
      <div class="report-section"><h4>Potential impact</h4>${esc(a.playbook.impact)}</div>
      <div class="report-section"><h4>Threat intelligence (MITRE ATT&amp;CK)</h4>${mitreTags(a.playbook.mitre)}</div>
      <div class="report-section"><h4>Recommended actions</h4>${recList(a.playbook.recommendations)}</div></div>` : ""}
    <div class="no-print"><button class="btn" data-ask="Explain this website check result and what I should do.">💬 Ask AI about this result</button></div>`;
}

// ---------- dashboard ----------
async function loadDashboard() {
  const hist = await api("/api/history").catch(() => []);
  $("#dash-empty").hidden = hist.length > 0;
  $("#dash-content").hidden = hist.length === 0;
  if (!hist.length) return;
  const latestFlow = hist.find(h => h.type === "flows");
  const latest = latestFlow ? await api(`/api/analysis/${latestFlow.id}`) : null;
  const shown = latest || await api(`/api/analysis/${hist[0].id}`);

  $("#dash-gauge").innerHTML = gauge(shown.score.value);
  const sc = $("#dash-status");
  sc.className = `card status-card ${shown.status.level}`;
  sc.innerHTML = `<div class="card-label" style="margin:0">Security status</div>
    <div class="status-title">${STATUS_ICON[shown.status.level]} ${esc(shown.status.headline)}</div>
    <div class="status-meta">
      ${shown.type === "flows" ? `<span>Traffic analyzed: <b>${num(shown.total_flows)}</b> flows</span>
        <span>Threats detected: <b>${shown.threats_detected}</b></span>
        <span>Mean confidence: <b>${pct(shown.mean_confidence)}</b></span>` : `<span>${esc(shown.url)}</span>`}
      <span>Last analysis: <b>${fmtTime(shown.analyzed_at)}</b></span>
    </div>
    <div><button class="btn small" data-open="${shown.id}">Open full report</button></div>`;

  const flows = hist.filter(h => h.type === "flows"), urls = hist.filter(h => h.type === "url");
  const totalThreats = hist.reduce((s, h) => s + h.threats, 0);
  const risky = urls.filter(u => u.status.level !== "safe").length;
  $("#dash-tiles").innerHTML = `
    <div class="tile"><div class="l">Traffic analyses</div><div class="v">${flows.length}</div></div>
    <div class="tile"><div class="l">Websites checked</div><div class="v">${urls.length}</div></div>
    <div class="tile"><div class="l">Threats found (all analyses)</div><div class="v">${totalThreats}</div></div>
    <div class="tile"><div class="l">Risky websites</div><div class="v">${risky}</div></div>`;

  $("#dash-incidents").innerHTML = latest && latest.incidents.length
    ? latest.incidents.map(i => `<div class="mini-incident"><div><b>${esc(i.title)}</b>
        <div class="small muted">${num(i.flows)} flows · confidence ${pct(i.confidence)}</div></div><span class="sev ${i.severity}">${i.severity}</span></div>`).join("")
    : '<p class="muted" style="margin:0">No active incidents.</p>';
  $("#dash-recent").innerHTML = historyTable(hist.slice(0, 6), true);
}

// ---------- history ----------
function historyTable(rows, compact = false) {
  if (!rows.length) return '<p class="muted" style="margin:0">Nothing yet.</p>';
  return `<div class="table-wrap"><table class="table"><tr><th>Type</th><th>Target</th><th>Status</th><th>Score</th>${compact ? "" : "<th>When</th>"}</tr>
    ${rows.map(h => `<tr class="click" data-open="${h.id}"><td>${h.type === "flows" ? "Traffic" : "Website"}</td>
      <td class="mono small" style="max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(h.name)}</td>
      <td>${STATUS_ICON[h.status.level]} <span class="small">${esc(h.status.headline)}</span></td>
      <td class="mono" style="color:${BAND_COLORS[bandOf(h.score)[0]]}">${h.score}</td>
      ${compact ? "" : `<td class="small muted">${fmtTime(h.analyzed_at)}</td>`}</tr>`).join("")}</table></div>`;
}

async function loadHistory() {
  $("#history-table").innerHTML = historyTable(await api("/api/history").catch(() => []));
}

document.addEventListener("click", async e => {
  const row = e.target.closest("[data-open]");
  if (!row) return;
  const a = await api(`/api/analysis/${row.dataset.open}`);
  if (a.type === "flows") { show("traffic"); renderTraffic(a); }
  else { show("website"); renderUrl(a); $("#url-input").value = a.url; }
  setChatAnalysis(a);
});

// ---------- chat ----------
function setChatAnalysis(a) {
  state.chatAnalysis = a;
  state.chatHistory = [];
  $("#chat-context").textContent = `Context: ${a.type === "flows" ? a.filename : a.url} · ${a.status.headline}`;
}

function openChat(question) {
  $("#chat").hidden = false;
  $("#chat-fab").hidden = true;
  if (question) sendChat(question);
  else $("#chat-text").focus();
}
$("#chat-fab").addEventListener("click", () => openChat());
$("#chat-close").addEventListener("click", () => { $("#chat").hidden = true; $("#chat-fab").hidden = false; });
$$(".chip").forEach(c => c.addEventListener("click", () => sendChat(c.textContent)));
$("#chat-form").addEventListener("submit", e => {
  e.preventDefault();
  const t = $("#chat-text").value.trim();
  if (t) { $("#chat-text").value = ""; sendChat(t); }
});

function addMsg(role, html) {
  const div = document.createElement("div");
  div.className = `msg ${role}`;
  div.innerHTML = html;
  $("#chat-body").appendChild(div);
  $("#chat-body").scrollTop = $("#chat-body").scrollHeight;
  return div;
}

async function sendChat(text) {
  addMsg("user", esc(text));
  const pending = addMsg("bot", '<span class="muted">Thinking…</span>');
  try {
    const r = await api("/api/chat", { method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ message: text, analysis_id: state.chatAnalysis?.id || null, history: state.chatHistory }) });
    const sources = [...new Set(r.sources.map(s => s.source))];
    pending.innerHTML = md(r.answer) + `<div class="msg-meta">${esc(r.provider)}${sources.length ? ` · sources: ${sources.map(esc).join(", ")}` : ""}</div>`;
    state.chatHistory.push({ role: "user", content: text }, { role: "assistant", content: r.answer });
  } catch (e) {
    pending.innerHTML = `<span style="color:var(--critical)">${esc(e.message)}</span>`;
  }
  $("#chat-body").scrollTop = $("#chat-body").scrollHeight;
}

// ---------- init ----------
loadStatus();
loadSamples();
loadDashboard();
