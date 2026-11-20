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

// ---------- animated visuals (gauge, count-up numbers, icon tiles, chart defaults) ----------
const GAUGE_GRADIENTS = {
  low: ["#2dd4bf", "#22c55e"], moderate: ["#fde047", "#f59e0b"],
  high: ["#fb923c", "#ef4444"], critical: ["#f87171", "#b91c1c"],
};
let gaugeSeq = 0;

// Semicircle score gauge: gradient arc that sweeps in while the number counts up.
// animate=false for gauges that refresh every second (Live Monitor).
function gauge(score, size = 220, { animate = true } = {}) {
  const [band, label] = bandOf(score);
  const [c1, c2] = GAUGE_GRADIENTS[band];
  const id = `g${++gaugeSeq}`;
  return `<div class="gauge ${animate ? "gauge-anim" : ""}">
    <svg viewBox="0 0 200 120" width="${size}" style="max-width:100%">
      <defs><linearGradient id="${id}" x1="0" x2="1" y1="0" y2="0"><stop offset="0" stop-color="${c1}"/><stop offset="1" stop-color="${c2}"/></linearGradient></defs>
      <path d="M20 100 A80 80 0 0 1 180 100" fill="none" stroke="rgba(255,255,255,.08)" stroke-width="15" stroke-linecap="round"/>
      <path class="gauge-arc" d="M20 100 A80 80 0 0 1 180 100" fill="none" stroke="url(#${id})" stroke-width="15" stroke-linecap="round"
            pathLength="100" stroke-dasharray="${score} 100" style="--score:${score};filter:drop-shadow(0 0 8px ${c2}88)"/>
    </svg>
    <div class="gauge-num" style="margin-top:-62px">${animate ? cnt(score) : score}<span class="muted" style="font-size:16px">/100</span></div>
    <div class="gauge-band" style="color:${BAND_COLORS[band]}">${label}</div></div>`;
}

// <span> that animateIn() counts up from 0 to `value` (final value shown if JS animation is skipped).
function cnt(value, dec = 0, suf = "") {
  const shown = dec ? Number(value).toFixed(dec) : Math.round(value).toLocaleString();
  return `<span data-count="${value}" data-dec="${dec}" data-suf="${suf}">${shown}${suf}</span>`;
}
function animateIn(root) {
  if (!root || matchMedia("(prefers-reduced-motion: reduce)").matches) return;
  root.querySelectorAll("[data-count]").forEach(el => {
    const target = parseFloat(el.dataset.count), dec = +el.dataset.dec, suf = el.dataset.suf || "";
    const fmt = v => (dec ? v.toFixed(dec) : Math.round(v).toLocaleString()) + suf;
    const start = performance.now(), dur = 1100;
    const tick = t => {
      const p = Math.min(1, (t - start) / dur), e = 1 - Math.pow(1 - p, 3);
      el.textContent = fmt(target * e);
      if (p < 1) requestAnimationFrame(tick);
    };
    el.textContent = fmt(0);
    requestAnimationFrame(tick);
  });
}

const ICONS = {
  activity: '<path d="M3 12h4l3-8 4 16 3-8h4"/>',
  globe: '<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18"/>',
  alert: '<path d="M12 3 2 20h20L12 3Z"/><path d="M12 10v4M12 17h.01"/>',
  shield: '<path d="M12 2 4 5v6c0 5 3.4 9.7 8 11 4.6-1.3 8-6 8-11V5l-8-3Z"/>',
  layers: '<path d="m12 3 9 5-9 5-9-5 9-5Z"/><path d="m3 13 9 5 9-5"/>',
  target: '<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="5"/><circle cx="12" cy="12" r="1"/>',
  check: '<circle cx="12" cy="12" r="9"/><path d="m8 12 3 3 5-6"/>',
  gauge: '<path d="M4 18a8 8 0 1 1 16 0"/><path d="m12 14 4-5"/>',
};
// KPI tile with a coloured glass icon square (like the reference designs).
function tile(label, valueHtml, icon, tone = "violet") {
  return `<div class="tile"><div class="t-icon t-${tone}"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">${ICONS[icon]}</svg></div>
    <div class="l">${label}</div><div class="v">${valueHtml}</div></div>`;
}

// Chart.js look: theme font and colours, smooth easing, rounded spaced donut segments.
if (window.Chart) {
  Chart.defaults.font.family = '"Plus Jakarta Sans", system-ui, sans-serif';
  Chart.defaults.color = "#aab3c9";
  Chart.defaults.animation.duration = 1200;
  Chart.defaults.animation.easing = "easeOutQuart";
  Chart.defaults.elements.arc.borderRadius = 8;
  Chart.defaults.elements.arc.borderWidth = 0;
  Chart.defaults.plugins.tooltip.backgroundColor = "rgba(12, 15, 28, .92)";
  Chart.defaults.plugins.tooltip.borderColor = "rgba(255, 255, 255, .12)";
  Chart.defaults.plugins.tooltip.borderWidth = 1;
  Chart.defaults.plugins.tooltip.padding = 10;
  Chart.defaults.plugins.tooltip.cornerRadius = 10;
}
const DONUT_OPTIONS = { cutout: "74%", spacing: 3, maintainAspectRatio: false, animation: { animateRotate: true, animateScale: true, duration: 1400 } };
// Vertical gradient fill for line/area charts.
function areaFill(color) {
  return ctx => {
    const { chart } = ctx, area = chart.chartArea;
    if (!area) return color + "44";
    const g = chart.ctx.createLinearGradient(0, area.top, 0, area.bottom);
    g.addColorStop(0, color + "99");
    g.addColorStop(1, color + "08");
    return g;
  };
}

function banner(status, sub = "", analysisId = null) {
  return `<div class="banner ${status.level}"><div class="icon">${STATUS_ICON[status.level]}</div>
    <div><h2>${esc(status.headline)}</h2>${sub ? `<div class="muted">${sub}</div>` : ""}</div>
    <div style="margin-left:auto;display:flex;gap:8px" class="no-print">
      ${analysisId ? `<a class="btn small primary" href="/api/analysis/${esc(analysisId)}/report.pdf">⬇ PDF report</a>` : ""}
      <button class="btn small" data-action="print">Print</button></div></div>`;
}

function mitreTags(ids) {
  return (ids || []).map(id => `<a class="mitre-tag" target="_blank" rel="noopener"
      href="https://attack.mitre.org/techniques/${esc(id.replace(".", "/"))}/">${esc(id)}</a>`).join("") || '<span class="muted">-</span>';
}

function recList(recs) {
  return `<ol>${(recs || []).map(r => `<li>${esc(r.action)}<div class="rec-why">${esc(r.why)}</div></li>`).join("")}</ol>`;
}

// ---------- navigation (real URLs: /app, /app/dashboard, /app/live, ...) ----------
const ROUTES = {
  home: "/app", dashboard: "/app/dashboard", live: "/app/live", browsing: "/app/browsing",
  traffic: "/app/traffic", website: "/app/website", history: "/app/history",
  how: "/app/how-it-works", about: "/app/about", library: "/app/library",
};
const viewFromPath = p => Object.keys(ROUTES).find(k => ROUTES[k] === p.replace(/\/+$/, "")) || "home";

// Page transition: the current page fades out briefly, then the new one rises in.
const PAGE_OUT_MS = 180;
let navToken = 0;

function show(view, { push = true, animate = true } = {}) {
  if (!$(`#view-${view}`)) view = "home";
  const current = $(".view.active");
  const next = $(`#view-${view}`);
  // nav state updates immediately, so the pill slides while the page changes
  $$("[data-view]").forEach(n => n.classList.toggle("active", n.dataset.view === view));
  if (push && location.pathname !== ROUTES[view]) history.pushState({ view }, "", ROUTES[view]);
  movePill();
  closeMenu();

  const token = ++navToken;
  const swap = () => {
    if (token !== navToken) return;   // a newer click won
    $$(".view").forEach(v => v.classList.remove("active", "leaving", "entering"));
    next.classList.add("active");
    document.body.dataset.view = view;
    window.scrollTo(0, 0);
    afterShow(view);
    if (animate && current && current !== next && !matchMedia("(prefers-reduced-motion: reduce)").matches) {
      next.classList.add("entering");
      next.addEventListener("animationend", function done(e) {
        if (e.target !== next) return;
        next.classList.remove("entering");
        next.removeEventListener("animationend", done);
      });
    }
  };
  const motion = animate && current && current !== next && !matchMedia("(prefers-reduced-motion: reduce)").matches;
  if (motion) {
    current.classList.add("leaving");
    setTimeout(swap, PAGE_OUT_MS);
  } else {
    swap();
  }
}

// Page titles type themselves in italic serif each time a page opens (like the landing tagline).
// Only the title's text is typed; badges inside it (e.g. the LIVE pill) stay in place.
function prepareTitles() {
  $$(".view .page-head h1").forEach(h1 => {
    const node = [...h1.childNodes].find(n => n.nodeType === Node.TEXT_NODE && n.textContent.trim());
    if (!node) return;
    const text = node.textContent.trim();
    const wrap = document.createElement("span");
    wrap.className = "tt";
    wrap.setAttribute("aria-label", text);
    wrap.innerHTML = `<span class="tt-ghost" aria-hidden="true">${esc(text)}</span><span class="tt-live" aria-hidden="true"><span class="tt-out">${esc(text)}</span><span class="tt-caret"></span></span>`;
    wrap.dataset.text = text;
    h1.replaceChild(wrap, node);
    h1.insertBefore(document.createTextNode(""), wrap.nextSibling);
  });
}
let titleTimer = null;
function typeTitle(view) {
  const wrap = $(`#view-${view} .page-head h1 .tt`);
  clearTimeout(titleTimer);
  $$(".tt-caret.on").forEach(c => c.classList.remove("on", "done"));
  if (!wrap || matchMedia("(prefers-reduced-motion: reduce)").matches) return;
  const text = wrap.dataset.text, out = wrap.querySelector(".tt-out"), caret = wrap.querySelector(".tt-caret");
  let i = 0;
  out.textContent = "";
  caret.classList.remove("done");
  caret.classList.add("on");
  const step = () => {
    out.textContent = text.slice(0, ++i);
    if (i >= text.length) { caret.classList.add("done"); return; }
    titleTimer = setTimeout(step, text[i - 1] === " " ? 55 : 32 + Math.random() * 28);
  };
  titleTimer = setTimeout(step, 260);
}

function afterShow(view) {
  typeTitle(view);
  if (view === "dashboard") loadDashboard();
  if (view === "history") loadHistory();
  libraryVisibility(view === "library");
  homeVisibility(view === "home");
  window.scrollTo(0, 0);
}

// Sliding highlight behind the active item in the pill navbar.
function movePill() {
  const nav = $("#pill-nav"), pill = $("#pill-indicator");
  const active = nav && nav.querySelector("a.active");
  if (!active) { pill.style.opacity = "0"; return; }
  pill.style.opacity = "1";
  pill.style.width = `${active.offsetWidth}px`;
  pill.style.transform = `translateX(${active.offsetLeft}px)`;
}
addEventListener("resize", movePill);
addEventListener("popstate", () => show(viewFromPath(location.pathname), { push: false }));

// Burger menu
function closeMenu() {
  $("#menu").hidden = true;
  $("#burger").setAttribute("aria-expanded", "false");
  $("#burger").setAttribute("aria-label", "Open menu");
  $("#burger").classList.remove("open");
}
$("#burger").addEventListener("click", e => {
  e.stopPropagation();
  const open = $("#menu").hidden;
  $("#menu").hidden = !open;
  $("#burger").setAttribute("aria-expanded", String(open));
  $("#burger").setAttribute("aria-label", open ? "Close menu" : "Open menu");
  $("#burger").classList.toggle("open", open);
});
document.addEventListener("click", e => {
  if (!$("#menu").hidden && !e.target.closest("#menu") && !e.target.closest("#burger")) closeMenu();
});
document.addEventListener("keydown", e => {
  if (e.key === "Escape" && !$("#menu").hidden) { closeMenu(); $("#burger").focus(); }
});

document.addEventListener("click", e => {
  // In-app links: switch view without reloading (Ctrl/Cmd-click still opens a new tab).
  const link = e.target.closest("a[data-view]");
  if (link && !e.ctrlKey && !e.metaKey && !e.shiftKey && e.button === 0) {
    e.preventDefault();
    show(link.dataset.view);
  }
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
    if (s.multi_user && s.session) {
      $("#br-pair").hidden = false;
      $("#br-code").textContent = s.session;
      $("#br-origin").textContent = location.origin;
    }
    $("#about-models").innerHTML =`Flow classifier: <b>${esc(s.flow_model)}</b> · classes: ${s.flow_classes.map(esc).join(", ")} ·
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

async function loadTestUploads() {
  const files = await api("/api/test-uploads").catch(() => []);
  $("#test-uploads").innerHTML = files.length
    ? files.map(f => `<a class="test-file" href="${esc(f.url)}" download>
        <div><div class="small"><b>${esc(f.note || f.name)}</b></div><div class="small muted mono">${esc(f.name)} · ${f.size_mb} MB</div></div>
        <span class="dl">⬇</span></a>`).join("")
    : '<span class="muted small">No test files found. Run <code>python -m src.make_upload_tests</code></span>';
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
    ${banner(a.status, `${esc(a.filename)} · ${num(a.total_flows)} flows · analyzed ${fmtTime(a.analyzed_at)}`, a.id)}
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
      ${tile("Flows analyzed", cnt(a.total_flows), "activity", "violet")}
      ${tile("Threats detected", cnt(a.threats_detected), "alert", a.threats_detected ? "red" : "green")}
      ${tile("Malicious / unusual flows", cnt(a.malicious_flows), "target", "orange")}
      ${tile("Mean model confidence", cnt(a.mean_confidence * 100, 1, "%"), "gauge", "cyan")}
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
        ${tile("Accuracy", cnt(ev.accuracy * 100, 2, "%"), "check", "green")}
        ${tile("Attack detection rate", ev.attack_detection_rate == null ? "-" : cnt(ev.attack_detection_rate * 100, 2, "%"), "target", "cyan")}
        ${tile("False alarm rate", ev.false_alarm_rate == null ? "-" : cnt(ev.false_alarm_rate * 100, 2, "%"), "alert", "orange")}
        ${tile("Labelled flows", cnt(ev.labelled_flows), "layers", "violet")}
      </div></div>` : ""}`;

  if (state.chart) state.chart.destroy();
  state.chart = new Chart($("#dist-chart"), {
    type: "doughnut",
    data: { labels: dist.map(([c]) => LABELS[c] || c),
            datasets: [{ data: dist.map(([, n]) => n), backgroundColor: dist.map(([c]) => CLASS_COLORS[c] || "#4f8cff") }] },
    options: { ...DONUT_OPTIONS, plugins: { legend: { display: false } } },
  });
  animateIn($("#traffic-result"));
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
    ${banner(a.status, `<span class="mono">${esc(a.url)}</span> · ${fmtTime(a.analyzed_at)}`, a.id)}
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
  animateIn($("#url-result"));
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
    ${tile("Traffic analyses", cnt(flows.length), "activity", "violet")}
    ${tile("Websites checked", cnt(urls.length), "globe", "cyan")}
    ${tile("Threats found (all analyses)", cnt(totalThreats), "alert", "red")}
    ${tile("Risky websites", cnt(risky), "shield", "orange")}`;

  // Traffic-mix donut from the latest traffic analysis.
  if (dash.donut) { dash.donut.destroy(); dash.donut = null; }
  if (latest) {
    const dist = Object.entries(latest.class_distribution).sort((x, y) => y[1] - x[1]);
    const total = dist.reduce((s, [, n]) => s + n, 0);
    const benign = latest.class_distribution.Benign || 0;
    $("#dash-mix-center").innerHTML = `<div class="mix-big">${cnt(benign / total * 100, 1, "%")}</div><div class="small muted">benign</div>`;
    $("#dash-mix-legend").innerHTML = dist.map(([c, n]) => `<div class="legend-row"><span class="legend-dot" style="background:${CLASS_COLORS[c] || "#4f8cff"}"></span>
      <span>${LABELS[c] || esc(c)}</span><span class="mono small muted">${pct(n / total)}</span></div>`).join("");
    dash.donut = new Chart($("#dash-donut"), {
      type: "doughnut",
      data: { labels: dist.map(([c]) => LABELS[c] || c), datasets: [{ data: dist.map(([, n]) => n), backgroundColor: dist.map(([c]) => CLASS_COLORS[c] || "#4f8cff") }] },
      options: { ...DONUT_OPTIONS, plugins: { legend: { display: false } } },
    });
  } else {
    $("#dash-mix-center").innerHTML = "";
    $("#dash-mix-legend").innerHTML = '<p class="muted small" style="margin:0">Run a traffic analysis to see its traffic mix.</p>';
  }

  $("#dash-incidents").innerHTML = latest && latest.incidents.length
    ? latest.incidents.map(i => `<div class="mini-incident"><div><b>${esc(i.title)}</b>
        <div class="small muted">${num(i.flows)} flows · confidence ${pct(i.confidence)}</div></div><span class="sev ${i.severity}">${i.severity}</span></div>`).join("")
    : '<p class="muted" style="margin:0">No active incidents.</p>';
  $("#dash-recent").innerHTML = historyTable(hist.slice(0, 6), true);
  animateIn($("#dash-content"));
}
const dash = { donut: null };

// ---------- history ----------
function historyTable(rows, compact = false) {
  if (!rows.length) return '<p class="muted" style="margin:0">Nothing yet.</p>';
  return `<div class="table-wrap"><table class="table"><tr><th>Type</th><th>Target</th><th>Status</th><th>Score</th>${compact ? "" : "<th>When</th>"}</tr>
    ${rows.map(h => `<tr class="click" data-open="${h.id}"><td>${h.type === "flows" ? "Traffic" : "Website"}</td>
      <td class="mono small" style="max-width:${compact ? 150 : 260}px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(h.name)}</td>
      <td title="${esc(h.status.headline)}">${STATUS_ICON[h.status.level]}${compact ? "" : ` <span class="small">${esc(h.status.headline)}</span>`}</td>
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

// ---------- live monitor ----------
const live = { source: null, chart: null, alerts: 0, total: 0 };
const LIVE_SERIES = ["Benign", "PortScan", "BruteForce", "DoS", "DDoS"];
const LIVE_POINTS = 60;

async function loadScenarios() {
  const list = await api("/api/live/scenarios").catch(() => []);
  $("#live-scenario").innerHTML = list.map(s => `<option value="${esc(s.id)}">${esc(s.title)} · ${s.seconds}s</option>`).join("");
  $("#live-gauge").innerHTML = gauge(100);
}

function initLiveChart() {
  if (live.chart) live.chart.destroy();
  live.chart = new Chart($("#live-chart"), {
    type: "line",
    data: { labels: [], datasets: LIVE_SERIES.map(c => ({
      label: LABELS[c], data: [], borderColor: CLASS_COLORS[c], backgroundColor: areaFill(CLASS_COLORS[c]),
      fill: true, tension: .4, pointRadius: 0, borderWidth: 2 })) },
    options: {
      maintainAspectRatio: false, animation: { duration: 400, easing: "easeOutCubic" },
      interaction: { mode: "index", intersect: false },
      scales: { x: { ticks: { color: "#8b97b0", maxTicksLimit: 8 }, grid: { color: "rgba(255,255,255,.05)" }, border: { display: false } },
                y: { stacked: true, beginAtZero: true, ticks: { color: "#8b97b0" }, grid: { color: "rgba(255,255,255,.05)" }, border: { display: false } } },
      plugins: { legend: { labels: { color: "#c6cfe0", boxWidth: 10, usePointStyle: true, pointStyle: "circle" } } },
    },
  });
}

function setLiveRunning(running) {
  $("#live-start").hidden = running;
  $("#live-stop").hidden = !running;
  $("#live-pill").hidden = !running;
  $("#live-scenario").disabled = running;
  $("#live-speed").disabled = running;
}

function startLive() {
  stopLive();
  initLiveChart();
  Object.assign(live, { alerts: 0, total: 0 });
  $("#live-alerts").innerHTML = '<p class="muted" style="margin:0">Monitoring… no alerts yet.</p>';
  $("#live-done").innerHTML = "";
  $("#live-alert-count").textContent = "0";
  const params = new URLSearchParams({ scenario: $("#live-scenario").value, speed: $("#live-speed").value });
  live.source = new EventSource(`/api/live/stream?${params}`);
  setLiveRunning(true);

  live.source.addEventListener("tick", e => {
    const d = JSON.parse(e.data);
    live.total += d.flows;
    const c = live.chart;
    c.data.labels.push(clock(d.time));
    c.data.datasets.forEach((ds, i) => ds.data.push(d.counts[LIVE_SERIES[i]] || 0));
    if (c.data.labels.length > LIVE_POINTS) { c.data.labels.shift(); c.data.datasets.forEach(ds => ds.data.shift()); }
    c.update();

    $("#live-bar").style.width = `${(d.tick / d.of * 100).toFixed(1)}%`;
    $("#live-progress-text").textContent = `${d.tick} / ${d.of} seconds · mean model confidence ${pct(d.mean_confidence)}`;
    $("#live-gauge").innerHTML = gauge(d.score, 220, { animate: false });
    $("#live-total").textContent = num(live.total);
    $("#live-rate").textContent = `${d.flows} /s`;
    $("#live-active").textContent = d.active.length;
    $("#live-active").style.color = d.active.length ? "var(--critical)" : "";
    $("#live-totals").innerHTML = Object.entries(d.totals).sort((a, b) => b[1] - a[1]).map(([k, v]) =>
      `<div class="bar-row"><span>${LABELS[k] || esc(k)}</span><div class="bar"><span style="width:${(v / live.total * 100).toFixed(1)}%;background:${CLASS_COLORS[k] || "var(--accent)"}"></span></div><span class="mono small">${num(v)}</span></div>`).join("");

    $$("#live-alerts .alert-item").forEach(el => el.classList.toggle("ended", !d.active.includes(el.dataset.threat)));
    for (const a of d.alerts) {
      if (!live.alerts) $("#live-alerts").innerHTML = "";
      live.alerts++;
      $("#live-alert-count").textContent = live.alerts;
      $("#live-alerts").insertAdjacentHTML("afterbegin", `<div class="alert-item ${a.severity}" data-threat="${esc(a.threat)}">
        <div class="alert-top"><b>${esc(a.title)}</b><span class="sev ${a.severity}">${a.severity}</span></div>
        <div class="small muted">${esc(clock(a.time))} · ${a.flows} flows/s · confidence ${pct(a.confidence)}</div>
        ${a.evidence.length ? `<ul class="small" style="margin:6px 0 0;padding-left:18px">${a.evidence.map(x => `<li>${esc(x)}</li>`).join("")}</ul>` : ""}
        ${a.action ? `<div class="small" style="margin-top:6px">→ <b>Recommended:</b> ${esc(a.action)}</div>` : ""}</div>`);
    }
  });

  live.source.addEventListener("done", e => {
    const d = JSON.parse(e.data);
    stopLive();
    $("#live-progress-text").textContent = "Session complete. Full analysis saved to history.";
    $("#live-done").innerHTML = `<div class="small muted" style="margin-bottom:8px">Whole session: ${esc(d.headline)} · score ${d.score}/100</div>
      <button class="btn primary small" data-open="${esc(d.analysis_id)}">Open full session report</button>
      <a class="btn small" href="/api/analysis/${esc(d.analysis_id)}/report.pdf">⬇ PDF</a>
      <button class="btn small" data-ask="Summarize this live monitoring session and what I should do.">💬 Ask AI</button>`;
    api(`/api/analysis/${d.analysis_id}`).then(setChatAnalysis).catch(() => {});
  });

  live.source.onerror = () => {
    if (!live.source) return;
    stopLive();
    $("#live-progress-text").textContent = "Stream stopped (connection closed).";
  };
}

function stopLive() {
  if (live.source) { live.source.close(); live.source = null; }
  setLiveRunning(false);
}

$("#live-start").addEventListener("click", startLive);
$("#live-stop").addEventListener("click", () => { stopLive(); $("#live-progress-text").textContent = "Stopped."; });

// ---------- browsing activity (real, from the extension) ----------
const br = { events: [], source: null, donut: null, timeline: null };
const LEVEL_COLORS = { safe: "#22c55e", warning: "#eab308", danger: "#ef4444" };
const LEVEL_NAMES = { safe: "Safe", warning: "Caution", danger: "Dangerous" };
const TIMELINE_MINUTES = 20;
const clock = iso => new Date(iso).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
const minuteKey = d => d.toTimeString().slice(0, 5);

function connectBrowsing() {
  if (br.source) return;
  br.source = new EventSource("/api/browsing/stream");
  br.source.onopen = () => { $("#br-pill").hidden = false; };
  br.source.onerror = () => { $("#br-pill").hidden = true; };  // EventSource reconnects by itself
  br.source.addEventListener("init", e => { br.events = JSON.parse(e.data).events; renderBrowsing(); });
  br.source.addEventListener("event", e => { br.events.push(JSON.parse(e.data)); renderBrowsing(true); });
  br.source.addEventListener("clear", () => { br.events = []; renderBrowsing(); });
}

function renderBrowsing(fresh = false) {
  const ev = br.events;
  $("#br-empty").hidden = ev.length > 0;
  const count = lvl => ev.filter(e => e.level === lvl).length;
  const domains = {};
  ev.forEach(e => { domains[e.host] = (domains[e.host] || 0) + 1; });
  $("#br-total").textContent = num(ev.length);
  $("#br-safe").textContent = num(count("safe"));
  $("#br-warn").textContent = num(count("warning"));
  $("#br-danger").textContent = num(count("danger"));
  $("#br-domains").textContent = num(Object.keys(domains).length);

  const recent = ev.slice(-60).reverse();
  $("#br-feed").innerHTML = recent.length ? `<table class="table"><tr><th>Time</th><th>Site</th><th>Verdict</th><th>Reason</th></tr>
    ${recent.map((e, i) => `<tr class="click feed-row" data-check-url="${esc(e.url)}" ${fresh && i === 0 ? "" : 'style="animation:none"'}>
      <td class="small muted mono">${esc(clock(e.time))}</td>
      <td><div class="host">${esc(e.host)}</div><div class="url">${esc(e.url)}</div></td>
      <td><span class="lvl ${e.level}"></span>${e.blocked ? "<b>Blocked</b>" : LEVEL_NAMES[e.level]}<div class="small muted">${esc(e.label)} ${(e.confidence * 100).toFixed(0)}%</div></td>
      <td class="small">${e.trusted ? `Reputable domain (${esc(e.trusted)})` : esc(e.flag || e.headline)}</td></tr>`).join("")}</table>`
    : '<p class="muted" style="margin:0">No sites yet.</p>';

  const dangerous = ev.filter(e => e.level === "danger").slice(-8).reverse();
  $("#br-blocked").innerHTML = dangerous.length ? dangerous.map(e => `<div class="mini-incident"><div><b>${esc(e.host)}</b>
      <div class="small muted">${esc(e.headline)} · ${esc(clock(e.time))}</div></div>
      <span class="sev Critical">${e.blocked ? "Blocked" : "Danger"}</span></div>`).join("")
    : '<p class="muted" style="margin:0">None so far.</p>';
  const top = Object.entries(domains).sort((a, b) => b[1] - a[1]).slice(0, 6);
  $("#br-top").innerHTML = top.length ? top.map(([d, n]) => `<div class="bar-row" style="grid-template-columns:150px 1fr 34px">
      <span style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(d)}</span>
      <div class="bar"><span style="width:${(n / top[0][1] * 100).toFixed(0)}%"></span></div><span class="mono small">${n}</span></div>`).join("")
    : '<p class="muted" style="margin:0">-</p>';

  renderBrowsingCharts(count);
}

function renderBrowsingCharts(count) {
  const levels = ["safe", "warning", "danger"];
  const donutData = levels.map(count);
  if (!br.donut) {
    br.donut = new Chart($("#br-donut"), {
      type: "doughnut",
      data: { labels: levels.map(l => LEVEL_NAMES[l]), datasets: [{ data: donutData, backgroundColor: levels.map(l => LEVEL_COLORS[l]) }] },
      options: { ...DONUT_OPTIONS, plugins: { legend: { position: "right", labels: { color: "#c6cfe0", boxWidth: 10, usePointStyle: true, pointStyle: "circle" } } } },
    });
  } else {
    br.donut.data.datasets[0].data = donutData;
    br.donut.update();
  }

  const now = new Date();
  const minutes = [...Array(TIMELINE_MINUTES)].map((_, i) => new Date(now.getTime() - (TIMELINE_MINUTES - 1 - i) * 60000));
  const buckets = Object.fromEntries(minutes.map(m => [minuteKey(m), { safe: 0, warning: 0, danger: 0 }]));
  br.events.forEach(e => { const b = buckets[minuteKey(new Date(e.time))]; if (b) b[e.level]++; });
  const labels = Object.keys(buckets);
  const datasets = levels.map(l => ({ label: LEVEL_NAMES[l], data: labels.map(k => buckets[k][l]), backgroundColor: LEVEL_COLORS[l], borderRadius: 6, borderSkipped: false, maxBarThickness: 22 }));
  if (!br.timeline) {
    br.timeline = new Chart($("#br-timeline"), {
      type: "bar", data: { labels, datasets },
      options: { maintainAspectRatio: false, animation: { duration: 700, easing: "easeOutQuart" },
        scales: { x: { stacked: true, ticks: { color: "#8b97b0", maxTicksLimit: 10 }, grid: { display: false }, border: { display: false } },
                  y: { stacked: true, beginAtZero: true, ticks: { color: "#8b97b0", precision: 0 }, grid: { color: "rgba(255,255,255,.05)" }, border: { display: false } } },
        plugins: { legend: { labels: { color: "#c6cfe0", boxWidth: 10, usePointStyle: true, pointStyle: "circle" } } } },
    });
  } else {
    br.timeline.data.labels = labels;
    br.timeline.data.datasets.forEach((ds, i) => { ds.data = datasets[i].data; });
    br.timeline.update();
  }
}

$("#br-clear").addEventListener("click", () => api("/api/browsing", { method: "DELETE" }).catch(() => {}));
$("#br-copy").addEventListener("click", async () => {
  try {
    await navigator.clipboard.writeText($("#br-code").textContent);
    $("#br-copy").textContent = "Copied ✓";
    setTimeout(() => { $("#br-copy").textContent = "Copy"; }, 1500);
  } catch { /* clipboard blocked: the code is still visible to copy by hand */ }
});
document.addEventListener("click", e => {
  const row = e.target.closest("[data-check-url]");
  if (!row) return;
  show("website");
  $("#url-input").value = row.dataset.checkUrl;
  $("#url-form").requestSubmit();
});
setInterval(() => { if (br.timeline) renderBrowsingCharts(l => br.events.filter(e => e.level === l).length); }, 30000);

// ---------- home page: typed headline, parallax quote section, video footer ----------
const REDUCED_MOTION = matchMedia("(prefers-reduced-motion: reduce)").matches;
let homeTyped = false;

function typeHomeHeadline() {
  if (homeTyped) return;
  homeTyped = true;
  const TEXT = "with Intelligent Security.";
  const out = $("#home-typed"), caret = $("#home-caret");
  if (REDUCED_MOTION) { out.textContent = TEXT; return; }
  let i = 0;
  const step = () => {
    out.textContent = TEXT.slice(0, ++i);
    if (i >= TEXT.length) { caret.classList.add("done"); return; }
    const ch = TEXT[i - 1];
    setTimeout(step, ch === "." ? 420 : ch === " " ? 75 : 45 + Math.random() * 40);
  };
  const begin = () => {
    setTimeout(() => caret.classList.add("on"), 700);   // after the first line has risen
    setTimeout(step, 900);
  };
  if (document.fonts && document.fonts.ready) document.fonts.ready.then(begin, begin); else begin();
}

// Pause the home video on other pages (saves CPU and battery); start typing on first view.
function homeVisibility(onHome) {
  const v = $("#home-video");
  if (!v) return;
  if (onHome && !REDUCED_MOTION) { const p = v.play(); if (p && p.catch) p.catch(() => {}); typeHomeHeadline(); }
  else if (onHome) { v.pause(); typeHomeHeadline(); }
  else v.pause();
}

// Parallax: progress = how far the quote section has travelled through the viewport (0..1).
// Each layer eases toward its target with linear interpolation (lerp) every frame.
(function quoteParallax() {
  const section = $("#quote-section");
  if (!section || REDUCED_MOTION) {
    if (section) $$(".q-cloud", section).forEach(c => { c.style.opacity = "1"; c.style.transform = c.classList.contains("q-cloud-right") ? "scaleX(-1)" : "none"; });
    return;
  }
  const left = $("#q-cloud-left"), right = $("#q-cloud-right");
  const lerp = (a, b, f) => a + (b - a) * f;
  const cur = { cloudX: 200, cloudY: 0 };
  let visible = false, raf = null;

  function frame() {
    const rect = section.getBoundingClientRect(), vh = innerHeight;
    const progress = Math.min(1, Math.max(0, (vh - rect.top) / (vh + rect.height)));
    const inView = progress > 0.12 && progress < 0.92;
    cur.cloudX = lerp(cur.cloudX, inView ? 0 : 200, 0.04);            // slide in / back out
    cur.cloudY = lerp(cur.cloudY, progress * -50, 0.04);              // gentle upward drift
    const opacity = Math.max(0, 1 - cur.cloudX / 200);
    left.style.transform = `translate3d(${(-cur.cloudX).toFixed(2)}px, ${cur.cloudY.toFixed(2)}px, 0)`;
    right.style.transform = `translate3d(${cur.cloudX.toFixed(2)}px, ${cur.cloudY.toFixed(2)}px, 0) scaleX(-1)`;
    left.style.opacity = right.style.opacity = opacity.toFixed(3);
    raf = visible ? requestAnimationFrame(frame) : null;
  }
  // Only animate while the section is near the screen.
  new IntersectionObserver(([entry]) => {
    visible = entry.isIntersecting;
    if (visible && !raf) raf = requestAnimationFrame(frame);
  }, { rootMargin: "200px 0px" }).observe(section);
})();

// Footer video loads only when the footer scrolls into view (it's 14 MB).
(function footerVideo() {
  const v = $("#footer-video");
  if (!v || REDUCED_MOTION) return;
  new IntersectionObserver(([entry], obs) => {
    if (!entry.isIntersecting) { if (v.src) v.pause(); return; }
    if (!v.src) {
      v.src = v.dataset.src;
      v.addEventListener("loadeddata", () => v.classList.add("ready"), { once: true });
    }
    const p = v.play(); if (p && p.catch) p.catch(() => {});
  }, { rootMargin: "100px 0px" }).observe($("#site-footer"));
})();

// Headline: once the masked rise ends, release the mask so the glow isn't clipped into a band.
$(".home-title .ln-i").addEventListener("animationend", () => $(".home-title").classList.add("risen"));
if (REDUCED_MOTION) $(".home-title").classList.add("risen");

// Typing helper shared by the footer tagline (same rhythm as the landing page).
function typeInto(out, caret, text, startDelay = 0) {
  if (REDUCED_MOTION) { out.textContent = text; return; }
  let i = 0;
  const step = () => {
    out.textContent = text.slice(0, ++i);
    if (i >= text.length) { caret.classList.add("done"); return; }
    const ch = text[i - 1];
    setTimeout(step, ch === "." ? 420 : ch === " " ? 70 : 38 + Math.random() * 34);
  };
  setTimeout(() => caret.classList.add("on"), startDelay);
  setTimeout(step, startDelay + 200);
}

// Quote: words reveal one after another (blur -> sharp) when the section scrolls into view.
(function quoteReveal() {
  const fig = $(".q-content"), quote = fig && fig.querySelector("blockquote");
  if (!quote || REDUCED_MOTION) return;
  const words = quote.textContent.trim().split(/\s+/);
  quote.setAttribute("aria-label", quote.textContent.trim());
  quote.innerHTML = words.map((w, i) => `<span class="w" aria-hidden="true" style="--i:${i}">${esc(w)}</span>`).join(" ");
  fig.style.setProperty("--sig-delay", `${words.length * 55 + 450}ms`);
  fig.classList.add("arm");
  new IntersectionObserver(([entry], obs) => {
    if (entry.isIntersecting) { fig.classList.add("go"); obs.disconnect(); }
  }, { threshold: 0.35 }).observe(fig);
})();

// Footer tagline types itself the first time the footer is reached.
(function footerTagline() {
  const out = $("#footer-typed"), caret = $("#footer-caret");
  if (!out) return;
  new IntersectionObserver(([entry], obs) => {
    if (!entry.isIntersecting) return;
    obs.disconnect();
    typeInto(out, caret, "See the Threat. Understand the Risk. Secure the Future.", 400);
  }, { threshold: 0.4 }).observe($(".footer-hero"));
})();

$("#back-to-top").addEventListener("click", e => { e.preventDefault(); scrollTo({ top: 0, behavior: REDUCED_MOTION ? "auto" : "smooth" }); });

// Footer "Check a website" box runs a real website check.
$("#footer-check").addEventListener("submit", e => {
  e.preventDefault();
  const url = $("#footer-url").value.trim();
  if (!url) return;
  show("website");
  $("#url-input").value = url;
  $("#footer-url").value = "";
  $("#url-form").requestSubmit();
});

// ---------- Scam Library (wiki of real scams, cases, cyber laws + globe) ----------
const GLOBE_SRC = "https://cdn.jsdelivr.net/npm/globe.gl@2.41.6/dist/globe.gl.min.js";
const lib = { data: null, loading: null, globe: null, cat: "All", query: "", openId: null };

function loadScript(src) {
  return new Promise((res, rej) => {
    const s = document.createElement("script");
    s.src = src; s.onload = res; s.onerror = rej;
    document.head.appendChild(s);
  });
}

async function libraryVisibility(visible) {
  if (!visible) { lib.globe && lib.globe.pauseAnimation(); return; }
  if (!lib.loading) lib.loading = initLibrary();
  await lib.loading;
  if (lib.globe) { lib.globe.resumeAnimation(); sizeGlobe(); }
}

async function initLibrary() {
  try {
    lib.data = await api("/api/library");
  } catch {
    $("#lib-list").innerHTML = `<p class="muted">Could not load the library. Please refresh.</p>`;
    return;
  }
  renderLibChips();
  renderLibList();
  renderLaws();
  renderReport();
  // not awaited: the cards are usable while the globe downloads. Started after the page title has
  // typed, so WebGL setup doesn't stutter the entrance animation on slower machines.
  setTimeout(initGlobe, 1300);
}

// every case with coordinates becomes a point on the globe
function libCases() {
  return lib.data.scams.flatMap(s => s.cases.filter(c => c.lat != null).map(c => ({ ...c, scamId: s.id, scamName: s.name })));
}

function renderLibChips() {
  const cats = ["All", ...lib.data.categories];
  $("#lib-chips").innerHTML = cats.map(c =>
    `<button class="lib-chip${c === lib.cat ? " active" : ""}" data-cat="${esc(c)}">${esc(c)}</button>`).join("");
}

function scamMatches(s) {
  if (lib.cat !== "All" && s.category !== lib.cat) return false;
  if (!lib.query) return true;
  const hay = [s.name, s.summary, s.region, ...s.how, ...s.red_flags, ...s.cases.map(c => `${c.title} ${c.place} ${c.story}`)]
    .join(" ").toLowerCase();
  return lib.query.split(/\s+/).every(w => hay.includes(w));
}

function caseHtml(c) {
  const where = c.lat != null ? `<button class="link lib-locate" data-lat="${c.lat}" data-lng="${c.lng}">📍 Show on globe</button>` : "";
  return `<div class="lib-case">
    <div class="lib-case-head"><b>${esc(c.title)}</b><span class="muted">${esc(c.place)} · ${esc(c.year)}</span></div>
    <p>${esc(c.story)}</p>
    <div class="lib-case-src">Source: ${c.url ? `<a href="${esc(c.url)}" target="_blank" rel="noopener">${esc(c.source)} ↗</a>` : esc(c.source)} ${where}</div>
  </div>`;
}

function scamCard(s) {
  const open = s.id === lib.openId;
  return `<article class="lib-card${open ? " open" : ""}" id="scam-${s.id}">
    <button class="lib-card-head" data-scam="${s.id}" aria-expanded="${open}">
      <div>
        <div class="lib-card-meta"><span class="lib-cat">${esc(s.category)}</span><span class="muted">${esc(s.region)}</span>${s.cases.length ? `<span class="lib-case-count">${s.cases.length} real case${s.cases.length > 1 ? "s" : ""}</span>` : ""}</div>
        <h3>${esc(s.name)}</h3>
        <p class="muted">${esc(s.summary)}</p>
      </div>
      <span class="chev">⌄</span>
    </button>
    <div class="lib-card-body">
      <div class="lib-cols">
        <div><h4>How it works</h4><ol>${s.how.map(x => `<li>${esc(x)}</li>`).join("")}</ol></div>
        <div><h4 class="warn">Red flags</h4><ul>${s.red_flags.map(x => `<li>${esc(x)}</li>`).join("")}</ul></div>
      </div>
      <div class="lib-do"><h4>What to do if it happens to you</h4><ol>${s.do_now.map(x => `<li>${esc(x)}</li>`).join("")}</ol></div>
      ${s.fact ? `<p class="lib-fact">📊 ${esc(s.fact)}</p>` : ""}
      ${s.cases.length ? `<h4>Real cases</h4>${s.cases.map(caseHtml).join("")}` : ""}
      <button class="btn small" data-ask="${esc(`I think I'm facing a ${s.name} scam. What should I do right now?`)}">💬 Ask AI about this scam</button>
    </div>
  </article>`;
}

function renderLibList() {
  const items = lib.data.scams.filter(scamMatches);
  $("#lib-list").innerHTML = items.length ? items.map(scamCard).join("")
    : `<p class="muted">No scams match “${esc(lib.query)}”. Try another word, or ask the AI assistant.</p>`;
}

function renderLaws() {
  const L = lib.data.laws;
  const row = l => `<div class="lib-law"><div><b>${esc(l.name)}</b><p class="muted">${esc(l.about)}</p></div>${l.penalty ? `<span class="lib-penalty">${esc(l.penalty)}</span>` : ""}</div>`;
  $("#lib-pane-laws").innerHTML = `
    <p class="lib-disclaimer">⚖️ ${esc(L.disclaimer)}</p>
    <div class="card"><div class="card-label">India</div>${L.india.map(row).join("")}</div>
    <div class="card"><div class="card-label">International</div>${L.global.map(row).join("")}</div>
    <a class="btn" href="https://www.indiacode.nic.in" target="_blank" rel="noopener">Read the official IT Act on India Code ↗</a>`;
}

function renderReport() {
  const R = lib.data.report;
  const row = r => `<${r.url ? `a href="${esc(r.url)}"${r.url.startsWith("http") ? ' target="_blank" rel="noopener"' : ""}` : "div"} class="lib-report">
    <b>${esc(r.name)}${r.url && r.url.startsWith("http") ? " ↗" : ""}</b><span class="muted">${esc(r.about)}</span></${r.url ? "a" : "div"}>`;
  $("#lib-pane-report").innerHTML = `
    <div class="card"><div class="card-label">India</div><div class="lib-report-grid">${R.india.map(row).join("")}</div></div>
    <div class="card"><div class="card-label">Outside India</div><div class="lib-report-grid">${R.global.map(row).join("")}</div></div>
    <div class="card prose"><div class="card-label">Before you report, keep</div>
      <ul><li>Screenshots of chats, call logs and profiles</li><li>Phone numbers, UPI IDs, bank account numbers and websites used</li><li>Transaction IDs and the date and time of each payment</li></ul></div>`;
}

function openScam(id, { scroll = true } = {}) {
  lib.openId = id;
  if (!lib.data.scams.filter(scamMatches).some(s => s.id === id)) { lib.cat = "All"; lib.query = ""; $("#lib-search").value = ""; renderLibChips(); }
  switchLibTab("scams");
  renderLibList();
  const card = $(`#scam-${id}`);
  if (card && scroll) {
    card.scrollIntoView({ behavior: "smooth", block: "start" });
    card.classList.add("flash");
    setTimeout(() => card.classList.remove("flash"), 1600);
  }
}

function switchLibTab(tab) {
  $$(".lib-tab").forEach(t => t.classList.toggle("active", t.dataset.tab === tab));
  $$(".lib-pane").forEach(p => { p.hidden = p.id !== `lib-pane-${tab}`; });
}

$("#view-library").addEventListener("click", e => {
  const tab = e.target.closest(".lib-tab");
  if (tab) return switchLibTab(tab.dataset.tab);
  const chip = e.target.closest(".lib-chip");
  if (chip) { lib.cat = chip.dataset.cat; renderLibChips(); renderLibList(); return; }
  const head = e.target.closest(".lib-card-head");
  if (head) {
    const id = head.dataset.scam;
    lib.openId = lib.openId === id ? null : id;
    $$(".lib-card").forEach(c => {
      const on = c.id === `scam-${lib.openId}`;
      c.classList.toggle("open", on);
      c.querySelector(".lib-card-head").setAttribute("aria-expanded", on);
    });
    const s = lib.data.scams.find(x => x.id === lib.openId);
    const c = s && s.cases.find(x => x.lat != null);
    if (c) focusGlobe(c);
    return;
  }
  const loc = e.target.closest(".lib-locate");
  if (loc) focusGlobe({ lat: +loc.dataset.lat, lng: +loc.dataset.lng }, true);
});
$("#lib-search").addEventListener("input", e => { lib.query = e.target.value.trim().toLowerCase(); renderLibList(); });

// ----- globe -----
function globeArcs(cases) {
  const arcs = [];
  // documented money flows from the case data (e.g. Dhaka -> New York Fed -> Manila)
  cases.forEach(c => {
    let from = c;
    (c.flows || []).forEach(f => { arcs.push({ startLat: from.lat, startLng: from.lng, endLat: f.lat, endLng: f.lng, real: true }); from = f; });
  });
  // illustrative links between cases (cybercrime crosses borders), clearly labelled in the legend
  cases.forEach((c, i) => {
    const d = cases[(i + 3) % cases.length];
    if (d !== c) arcs.push({ startLat: c.lat, startLng: c.lng, endLat: d.lat, endLng: d.lng, real: false });
  });
  return arcs;
}

function showGlobeInfo(c) {
  $("#lib-globe-info").innerHTML = `<div class="card-label">${esc(c.place)} · ${esc(c.year)}</div>
    <b>${esc(c.title)}</b>
    <p class="muted">${esc(c.story.length > 170 ? c.story.slice(0, 170) + "…" : c.story)}</p>
    <button class="btn small" data-open-scam="${c.scamId}">Read about ${esc(c.scamName)} →</button>`;
}
$("#lib-globe-info").addEventListener("click", e => {
  const b = e.target.closest("[data-open-scam]");
  if (b) openScam(b.dataset.openScam);
});

function focusGlobe(c, pause = false) {
  if (!lib.globe) return;
  lib.globe.controls().autoRotate = false;
  // look slightly north of the case so it lands below the info panel, not under it (desktop only:
  // on small screens the panel sits below the globe)
  const lift = matchMedia("(max-width: 980px)").matches ? 0 : 12;
  lib.globe.pointOfView({ lat: Math.min(c.lat + lift, 80), lng: c.lng, altitude: 2.1 }, 1200);
  const full = libCases().find(x => x.lat === c.lat && x.lng === c.lng);
  if (full) showGlobeInfo(full);
  clearTimeout(lib.resume);
  const ms = pause ? 12000 : 8000;
  lib.focusUntil = Date.now() + ms;
  lib.resume = setTimeout(() => { if (lib.globe && !lib.hover) lib.globe.controls().autoRotate = true; }, ms);
}

function sizeGlobe() {
  const el = $("#lib-globe");
  if (lib.globe && el.clientWidth) lib.globe.width(el.clientWidth).height(el.clientHeight);
}
addEventListener("resize", () => { if (document.body.dataset.view === "library") sizeGlobe(); });

// hotspot look; called again on hover so the hovered point grows and turns white
function stylePoints(g) {
  const h = lib.hover;
  g.pointColor(c => c === h ? "#ffffff" : "#f472b6")
    .pointAltitude(c => c === h ? 0.08 : 0.035)
    .pointRadius(c => c === h ? 1.3 : 1.0);
}

async function initGlobe() {
  const el = $("#lib-globe");
  try {
    if (!window.Globe) await loadScript(GLOBE_SRC);
  } catch {
    el.innerHTML = `<p class="muted lib-globe-fallback">The 3D globe couldn't load (offline?). All cases are listed on the left.</p>`;
    return;
  }
  const cases = libCases();
  const g = window.Globe()(el)
    .backgroundColor("rgba(0,0,0,0)")
    .globeImageUrl("/static/assets/earth-night.webp")
    .showAtmosphere(true).atmosphereColor("#8b7bff").atmosphereAltitude(0.2)
    .pointsData(cases).pointLat("lat").pointLng("lng")
    // big hit area + hover highlight; the globe holds still while a hotspot is hovered
    .pointResolution(16)
    .pointsTransitionDuration(250)
    .pointLabel(c => `<div class="globe-tip"><b>${esc(c.title)}</b><br>${esc(c.place)} · ${esc(c.year)}<br><span class="globe-tip-cta">Click to read →</span></div>`)
    .onPointHover(c => {
      lib.hover = c || null;
      el.style.cursor = c ? "pointer" : "";
      stylePoints(g);
      clearTimeout(lib.resume);
      if (c) { g.controls().autoRotate = false; return; }
      // resume rotation shortly after leaving, but never cut short the longer pause after a click
      const wait = Math.max(2500, (lib.focusUntil || 0) - Date.now());
      lib.resume = setTimeout(() => { if (lib.globe && !lib.hover) lib.globe.controls().autoRotate = true; }, wait);
    })
    .onPointClick(c => { focusGlobe(c, true); })
    .ringsData(cases).ringLat("lat").ringLng("lng")
    .ringColor(() => t => `rgba(244,114,182,${1 - t})`).ringMaxRadius(4).ringPropagationSpeed(1.6).ringRepeatPeriod(1600)
    .arcsData(globeArcs(cases))
    .arcColor(a => a.real ? ["#fde68a", "#f59e0b"] : ["rgba(167,139,250,.55)", "rgba(34,211,238,.55)"])
    .arcStroke(a => a.real ? 0.7 : 0.35)
    .arcAltitudeAutoScale(0.45)
    .arcDashLength(a => a.real ? 0.5 : 0.3).arcDashGap(a => a.real ? 0.4 : 1.4)
    .arcDashAnimateTime(a => a.real ? 2200 : 4200);
  stylePoints(g);
  g.renderer().setPixelRatio(Math.min(devicePixelRatio || 1, 1.5));   // sharp enough, much cheaper on 4K / phones
  const ctl = g.controls();
  ctl.autoRotate = true; ctl.autoRotateSpeed = 0.45; ctl.enableZoom = false;
  // slow right down while the mouse is over the globe, so hotspots are easy to catch
  el.addEventListener("mouseenter", () => { ctl.autoRotateSpeed = 0.12; });
  el.addEventListener("mouseleave", () => { ctl.autoRotateSpeed = 0.45; });
  g.pointOfView({ lat: 20, lng: 78, altitude: 2.3 }, 0);   // start over India
  lib.globe = g;
  sizeGlobe();
  if (document.body.dataset.view !== "library") g.pauseAnimation();
}

// ---------- init ----------
connectBrowsing();
loadStatus();
loadSamples();
loadTestUploads();
loadScenarios();

prepareTitles();
// Open the page named by the URL (/app/live, /app/traffic, ...).
show(viewFromPath(location.pathname), { push: false, animate: false });
history.replaceState({ view: viewFromPath(location.pathname) }, "", location.pathname + location.hash);
document.fonts && document.fonts.ready.then(movePill);  // re-measure once the nav font has loaded

// Deep link from the browser extension: /app#analysis=<id> opens that report.
const deepLink = location.hash.match(/^#analysis=([\w-]+)$/);
if (deepLink) {
  api(`/api/analysis/${deepLink[1]}`).then(a => {
    if (a.type === "flows") { show("traffic"); renderTraffic(a); }
    else { show("website"); renderUrl(a); $("#url-input").value = a.url; }
    setChatAnalysis(a);
  }).catch(() => {});
}
