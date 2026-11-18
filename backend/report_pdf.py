"""Dashboard-style PDF reports (KPI cards, gauge, donut and bar charts, incident
pages) rendered with matplotlib, so no extra dependencies are needed."""
import io
import textwrap
from datetime import datetime

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.backends.backend_pdf import PdfPages
from matplotlib.patches import FancyBboxPatch, Rectangle, Wedge

PAGE = (11.69, 8.27)  # A4 landscape, inches
NAVY, ACCENT, BG, CARD = "#1b2540", "#4f8cff", "#f3f5fa", "#ffffff"
TEXT, MUTED, BORDER = "#1f2937", "#6b7280", "#e3e8f2"
SEV_COLOR = {"Critical": "#dc2626", "High": "#f97316", "Medium": "#eab308", "None": "#16a34a"}
CLASS_COLOR = {"Benign": "#22c55e", "DoS": "#ef4444", "DDoS": "#991b1b", "BruteForce": "#f97316",
               "PortScan": "#eab308", "Anomaly": "#a855f7"}
CLASS_LABEL = {"BruteForce": "Brute force", "PortScan": "Port scan"}
URL_COLOR = {"benign": "#22c55e", "phishing": "#f97316", "malware": "#dc2626", "defacement": "#eab308"}
STATUS_COLOR = {"safe": "#16a34a", "warning": "#d97706", "danger": "#dc2626"}

plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 9, "text.color": TEXT})


def band(score):
    if score >= 90:
        return "Low observed risk", "#16a34a"
    if score >= 70:
        return "Moderate risk", "#ca8a04"
    if score >= 40:
        return "High risk", "#ea580c"
    return "Critical risk", "#dc2626"


class Report:
    def __init__(self, title):
        self.title = title
        self.buf = io.BytesIO()
        self.pdf = PdfPages(self.buf)
        self.page_no = 0
        self.generated = datetime.now().strftime("%d %b %Y, %H:%M")

    # ---------- page & primitives ----------
    def page(self, heading, sub=""):
        self.page_no += 1
        fig = plt.figure(figsize=PAGE, facecolor=BG)
        fig.add_artist(Rectangle((0, 0.915), 1, 0.085, transform=fig.transFigure, color=NAVY))
        fig.add_artist(Rectangle((0, 0.912), 1, 0.004, transform=fig.transFigure, color=ACCENT))
        fig.text(0.03, 0.957, "ThreatLens", color="#7dd3fc", fontsize=10, weight="bold", va="center")
        fig.text(0.115, 0.957, heading, color="white", fontsize=16, weight="bold", va="center")
        if sub:
            fig.text(0.97, 0.957, sub, color="#c7d2fe", fontsize=9, ha="right", va="center")
        fig.text(0.03, 0.02, f"{self.title} · generated {self.generated}", color=MUTED, fontsize=7.5)
        fig.text(0.97, 0.02, f"Observed-risk assessment, not a guarantee of security · page {self.page_no}",
                 color=MUTED, fontsize=7.5, ha="right")
        return fig

    def card(self, fig, x, y, w, h, title=None):
        # zorder below 0 so charts (axes, zorder 0) are drawn on top of the card
        fig.add_artist(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0,rounding_size=0.008", zorder=-5,
                                      transform=fig.transFigure, facecolor=CARD, edgecolor=BORDER, lw=0.8))
        if title:
            fig.text(x + 0.012, y + h - 0.03, title.upper(), fontsize=8, color=MUTED, weight="bold")

    def kpi(self, fig, x, y, w, h, label, value, color=ACCENT, note=""):
        self.card(fig, x, y, w, h)
        fig.add_artist(Rectangle((x, y), 0.005, h, transform=fig.transFigure, color=color, zorder=-4))
        fig.text(x + 0.016, y + h - 0.032, label.upper(), fontsize=7.5, color=MUTED, weight="bold")
        fig.text(x + 0.016, y + h * 0.36, str(value), fontsize=20, weight="bold", color=color, va="center")
        if note:
            fig.text(x + 0.016, y + 0.016, note, fontsize=7.5, color=MUTED)

    def banner(self, fig, status):
        color = STATUS_COLOR.get(status["level"], ACCENT)
        fig.add_artist(FancyBboxPatch((0.03, 0.845), 0.94, 0.05, boxstyle="round,pad=0,rounding_size=0.008", zorder=-5,
                                      transform=fig.transFigure, facecolor=color, alpha=0.12, edgecolor=color, lw=1))
        fig.text(0.045, 0.87, status["headline"], fontsize=13, weight="bold", color=color, va="center")

    def lines(self, fig, x, y, items, width=60, size=8.5, gap=0.026, bullet="•", color=TEXT, sub=None):
        """Wrapped bullet list; returns the y below the last line."""
        for i, item in enumerate(items):
            wrapped = textwrap.wrap(str(item), width) or [""]
            for j, line in enumerate(wrapped):
                fig.text(x, y, (f"{bullet} " if j == 0 and bullet else "   ") + line, fontsize=size, color=color)
                y -= gap * 0.82
            if sub and sub[i]:
                for line in textwrap.wrap(sub[i], width + 4):
                    fig.text(x + 0.012, y, line, fontsize=size - 1, color=MUTED)
                    y -= gap * 0.75
            y -= gap * 0.25
        return y

    @staticmethod
    def _axes(fig, rect):
        ax = fig.add_axes(rect)
        ax.set_facecolor("none")
        return ax

    def gauge(self, fig, rect, score):
        ax = self._axes(fig, rect)
        ax.set_aspect("equal")
        ax.axis("off")
        label, color = band(score)
        ax.add_patch(Wedge((0, 0), 1, 0, 180, width=0.28, color="#e5e7eb"))
        ax.add_patch(Wedge((0, 0), 1, 180 - 180 * score / 100, 180, width=0.28, color=color))
        ax.text(0, 0.12, f"{score}", ha="center", fontsize=30, weight="bold", color=TEXT)
        ax.text(0, -0.16, label, ha="center", fontsize=10, weight="bold", color=color)
        ax.set_xlim(-1.1, 1.1)
        ax.set_ylim(-0.3, 1.05)

    def donut(self, fig, rect, labels, values, colors):
        ax = self._axes(fig, rect)
        total = sum(values)
        ax.pie(values, colors=colors, startangle=90, counterclock=False,
               wedgeprops={"width": 0.36, "edgecolor": "white", "linewidth": 1.5})
        ax.text(0, 0, f"{total:,}", ha="center", va="center", fontsize=13, weight="bold")
        ax.legend([f"{l}  {v:,} ({v / total:.1%})" for l, v in zip(labels, values)], loc="center left",
                  bbox_to_anchor=(1.0, 0.5), frameon=False, fontsize=8)

    def hbars(self, fig, rect, names, values, colors, fmt="{:,}"):
        ax = self._axes(fig, rect)
        y = range(len(names))[::-1]
        ax.barh(list(y), values, color=colors, height=0.55)
        ax.set_yticks(list(y), names, fontsize=8)
        for yi, v in zip(y, values):
            ax.text(v, yi, "  " + fmt.format(v), va="center", fontsize=8, color=TEXT)
        ax.set_xlim(0, max(values) * 1.3 if values else 1)
        for s in ("top", "right", "bottom"):
            ax.spines[s].set_visible(False)
        ax.spines["left"].set_color(BORDER)
        ax.tick_params(axis="x", colors=MUTED, labelsize=7)
        ax.tick_params(axis="y", length=0)

    def close(self, fig):
        self.pdf.savefig(fig, facecolor=BG)
        plt.close(fig)

    def bytes(self):
        d = self.pdf.infodict()
        d["Title"], d["Author"] = self.title, "ThreatLens"
        self.pdf.close()
        return self.buf.getvalue()


# ---------- flow analysis ----------
def _methodology(r, extra=()):
    fig = r.page("Methodology & limitations")
    r.card(fig, 0.03, 0.07, 0.455, 0.82, "How the assessment works")
    r.lines(fig, 0.045, 0.80, [
        "Network flows (CICFlowMeter format, 69 features) are classified by an XGBoost model trained on "
        "CIC-IDS2017 into Benign, DoS, DDoS, Brute force and Port scan. It was selected over Random Forest "
        "on macro F1 (0.9994 on 71,830 held-out flows).",
        "Flows classified as benign are also checked by an Isolation Forest trained only on normal traffic. "
        "It is calibrated to flag ~1% of normal flows and only raises an incident above 2%.",
        "Detections of fewer than 5 flows are isolated detections, not incidents, to avoid alert fatigue.",
        "Evidence compares each incident's median feature values with statistics of normal training traffic.",
        "Threat intelligence and recommendations come from MITRE ATT&CK and curated playbooks.",
        *extra,
    ], width=62)
    r.card(fig, 0.515, 0.47, 0.455, 0.42, "Security score")
    r.lines(fig, 0.53, 0.80, [
        "Starts at 100. Each incident subtracts: severity weight (Critical 40, High 25, Medium 10) x mean "
        "confidence x volume factor (0.5 below 10 flows, 0.75 below 100, 1.0 otherwise).",
        "90-100 low observed risk · 70-89 moderate · 40-69 high · 0-39 critical.",
    ], width=62)
    r.card(fig, 0.515, 0.07, 0.455, 0.37, "Limitations")
    r.lines(fig, 0.53, 0.37, [
        "Models were trained on lab traffic; performance on other networks may be lower.",
        "Flow data shows behaviour, not packet contents, and cannot confirm whether a login succeeded.",
        "This report is an observed-risk assessment, not a guarantee that a system is secure.",
        "Nothing is blocked automatically: all actions are recommendations for a human to decide.",
    ], width=62)
    r.close(fig)


def _flow_report(a, mitre_names):
    r = Report(f"Traffic report · {a['filename']}")
    incidents = a["incidents"]
    score = a["score"]["value"]
    blabel, bcolor = band(score)

    # ---- page 1: executive dashboard ----
    fig = r.page("Security Assessment Dashboard", f"{a['filename']} · {a['analyzed_at'].replace('T', ' ')}")
    r.banner(fig, a["status"])
    kpis = [("Security score", f"{score}/100", bcolor, blabel),
            ("Flows analyzed", f"{a['total_flows']:,}", ACCENT, f"model: {a['model']}"),
            ("Threats detected", a["threats_detected"], SEV_COLOR["Critical"] if incidents else SEV_COLOR["None"], "incidents"),
            ("Malicious flows", f"{a['malicious_flows']:,}", "#ea580c", f"{a['malicious_flows'] / a['total_flows']:.1%} of traffic"),
            ("Mean confidence", f"{a['mean_confidence']:.1%}", "#7c3aed", "model probability")]
    w = 0.94 / 5 - 0.01
    for i, (label, value, color, note) in enumerate(kpis):
        r.kpi(fig, 0.03 + i * (w + 0.0125), 0.70, w, 0.125, label, value, color, note)

    r.card(fig, 0.03, 0.36, 0.25, 0.32, "Security posture")
    r.gauge(fig, [0.045, 0.385, 0.22, 0.24], score)
    r.card(fig, 0.295, 0.36, 0.36, 0.32, "Traffic classification")
    dist = sorted(a["class_distribution"].items(), key=lambda kv: -kv[1])
    r.donut(fig, [0.30, 0.38, 0.17, 0.25], [CLASS_LABEL.get(c, c) for c, _ in dist], [n for _, n in dist],
            [CLASS_COLOR.get(c, ACCENT) for c, _ in dist])
    r.card(fig, 0.67, 0.36, 0.30, 0.32, "Score impact by incident")
    if incidents:
        r.hbars(fig, [0.76, 0.395, 0.18, 0.235], [CLASS_LABEL.get(i["threat"], i["threat"]) for i in incidents],
                [i["penalty"] for i in incidents], [SEV_COLOR[i["severity"]] for i in incidents], fmt="-{:.1f}")
    else:
        fig.text(0.82, 0.52, "No deductions", ha="center", color=MUTED, fontsize=11)

    r.card(fig, 0.03, 0.07, 0.62, 0.27, "Incident summary")
    cols = [(0.045, "Threat"), (0.30, "Severity"), (0.39, "Confidence"), (0.48, "Flows"), (0.56, "Share")]
    for x, h in cols:
        fig.text(x, 0.275, h, fontsize=8, color=MUTED, weight="bold")
    y = 0.245
    for i in incidents[:5]:
        fig.text(0.045, y, i["title"][:42], fontsize=8.5)
        fig.text(0.30, y, i["severity"], fontsize=8.5, color=SEV_COLOR[i["severity"]], weight="bold")
        fig.text(0.39, y, f"{i['confidence']:.1%}", fontsize=8.5)
        fig.text(0.48, y, f"{i['flows']:,}", fontsize=8.5)
        fig.text(0.56, y, f"{i['share']:.1%}", fontsize=8.5)
        y -= 0.033
    if not incidents:
        fig.text(0.045, 0.2, "No incidents: traffic matches normal patterns learned by the model.", color=MUTED)

    r.card(fig, 0.665, 0.07, 0.305, 0.27, "Validation & anomaly detection")
    ev, an = a.get("evaluation"), a["anomaly"]
    rows = []
    if ev:
        fmt = lambda v: "-" if v is None else f"{v:.2%}"  # noqa: E731
        rows += [f"Accuracy vs file labels: {ev['accuracy']:.2%}",
                 f"Attack detection rate: {fmt(ev['attack_detection_rate'])}",
                 f"False alarm rate: {fmt(ev['false_alarm_rate'])}"]
    rows += [f"Anomaly rate: {an['rate']:.1%} (expected ~{an['expected_rate']:.0%})",
             "Anomaly incident raised" if an["reported"] else "Within normal noise level"]
    r.lines(fig, 0.68, 0.275, rows, width=44, size=8.5, gap=0.034)
    r.close(fig)

    # ---- one page per incident ----
    for n, inc in enumerate(incidents, 1):
        fig = r.page(f"Incident {n} of {len(incidents)}: {inc['title']}", a["filename"])
        sev = SEV_COLOR[inc["severity"]]
        for k, (label, value, color) in enumerate([
                ("Severity", inc["severity"], sev), ("Confidence", f"{inc['confidence']:.1%}", "#7c3aed"),
                ("Flows", f"{inc['flows']:,}", ACCENT), ("Share of traffic", f"{inc['share']:.1%}", "#0891b2"),
                ("Score impact", f"-{inc['penalty']}", "#ea580c")]):
            r.kpi(fig, 0.03 + k * (w + 0.0125), 0.755, w, 0.12, label, value, color)
        r.card(fig, 0.03, 0.07, 0.455, 0.665, "Summary & evidence")
        y = r.lines(fig, 0.045, 0.675, [inc["summary"]], width=64, bullet="")
        fig.text(0.045, y - 0.005, "EVIDENCE", fontsize=8, color=sev, weight="bold")
        y = r.lines(fig, 0.045, y - 0.035, inc["evidence"], width=62)
        fig.text(0.045, y - 0.005, "POTENTIAL IMPACT", fontsize=8, color=sev, weight="bold")
        y = r.lines(fig, 0.045, y - 0.035, [inc["impact"]], width=64, bullet="")
        if inc["top_ports"] and y > 0.25:
            ports = inc["top_ports"]
            r.hbars(fig, [0.12, 0.10, 0.30, min(0.13, y - 0.16)], [f"{p['port']} ({p['service']})" for p in ports],
                    [p["flows"] for p in ports], [sev] * len(ports))
        r.card(fig, 0.515, 0.07, 0.455, 0.665, "Threat intelligence & recommended actions")
        fig.text(0.53, 0.675, "MITRE ATT&CK", fontsize=8, color=ACCENT, weight="bold")
        y = r.lines(fig, 0.53, 0.645, [f"{t}: {mitre_names.get(t, '')}" for t in inc["mitre"]] or ["-"], width=60)
        fig.text(0.53, y - 0.005, "RECOMMENDED ACTIONS", fontsize=8, color=ACCENT, weight="bold")
        recs = inc["recommendations"]
        r.lines(fig, 0.53, y - 0.035, [f"{k}. {x['action']}" for k, x in enumerate(recs, 1)], width=60, bullet="",
                sub=[x["why"] for x in recs], gap=0.027)
        r.close(fig)

    _methodology(r)
    return r.bytes()


# ---------- URL check ----------
def _url_report(a):
    r = Report(f"Website report · {a['url'][:60]}")
    m, live = a["model"], a["live"]
    score = a["score"]["value"]
    blabel, bcolor = band(score)
    fig = r.page("Website Security Report", a["analyzed_at"].replace("T", " "))
    r.banner(fig, a["status"])
    fig.text(0.03, 0.815, a["url"][:120], fontsize=9, color=MUTED, family="DejaVu Sans Mono")

    cert = (live.get("certificate") or {}) if live.get("performed") else {}
    kpis = [("Safety score", f"{score}/100", bcolor, blabel),
            ("ML verdict", m["label"].capitalize(), URL_COLOR.get(m["label"], ACCENT), m.get("model_name", "")[:30]),
            ("Confidence", f"{m['confidence']:.0%}", "#7c3aed", "model probability"),
            ("HTTPS", "Yes" if live.get("https") else ("No" if live.get("performed") else "n/a"),
             "#16a34a" if live.get("https") else ("#dc2626" if live.get("performed") else MUTED),
             "encrypted connection"),
            ("Certificate", f"{cert['days_left']} days" if cert.get("valid") else ("Invalid" if cert else "n/a"),
             "#16a34a" if cert.get("valid") else MUTED, cert.get("issuer", "")[:28])]
    w = 0.94 / 5 - 0.01
    for i, (label, value, color, note) in enumerate(kpis):
        r.kpi(fig, 0.03 + i * (w + 0.0125), 0.66, w, 0.125, label, value, color, note)

    r.card(fig, 0.03, 0.33, 0.25, 0.31, "Safety score")
    r.gauge(fig, [0.045, 0.355, 0.22, 0.23], score)
    r.card(fig, 0.295, 0.33, 0.33, 0.31, "URL classification probabilities")
    probs = sorted(m["probabilities"].items(), key=lambda kv: -kv[1])
    r.hbars(fig, [0.37, 0.36, 0.22, 0.22], [c.capitalize() for c, _ in probs], [round(p * 100, 1) for _, p in probs],
            [URL_COLOR.get(c, ACCENT) for c, _ in probs], fmt="{:.1f}%")
    r.card(fig, 0.64, 0.33, 0.33, 0.31, "Red flags in the URL")
    notes = ([m["reputation"]["note"]] if m.get("reputation", {}).get("note") else []) + (m["red_flags"] or ["None found"])
    r.lines(fig, 0.655, 0.575, notes[:7], width=46)

    r.card(fig, 0.03, 0.07, 0.455, 0.245, "Live security checks")
    if live.get("performed"):
        y = 0.25
        for h in live["headers"]:
            fig.text(0.045, y, "PASS" if h["present"] else "FAIL", fontsize=8, weight="bold",
                     color="#16a34a" if h["present"] else "#dc2626")
            fig.text(0.085, y, f"{h['header']} - {h['why']}", fontsize=8.5)
            y -= 0.027
    else:
        fig.text(0.045, 0.24, f"Not performed: {live.get('reason', '')}", color=MUTED)
    r.card(fig, 0.515, 0.07, 0.455, 0.245, "Recommended actions" if a.get("playbook") else "Score deductions")
    if a.get("playbook"):
        r.lines(fig, 0.53, 0.25, [x["action"] for x in a["playbook"]["recommendations"]], width=62, gap=0.027)
    else:
        r.lines(fig, 0.53, 0.25, [f"-{d['points']}  {d['reason']}" for d in a["score"]["deductions"]] or ["No deductions"],
                width=62, gap=0.027)
    r.close(fig)
    _methodology(r, extra=["URLs are classified by a character n-gram + lexical-feature model (macro F1 0.919), "
                           "after a reputation check against a curated list of well-known domains. Live checks make "
                           "one normal request to assess HTTPS, certificate and security headers."])
    return r.bytes()


def build_pdf(analysis: dict, mitre_names: dict) -> bytes:
    return _url_report(analysis) if analysis["type"] == "url" else _flow_report(analysis, mitre_names)
