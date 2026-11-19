# ThreatLens: AI-Assisted Threat Detection & Security Assessment

Detect → Explain → Recommend → Human decides.

ThreatLens analyzes network flows and URLs with machine learning. It reports detected threats with
confidence, evidence, MITRE ATT&CK threat intelligence and recommended mitigations, plus a
context-aware AI assistant (RAG). It gives an **observed-risk assessment**, not a guarantee of security.

## Run locally

Requires Python 3.10+. All commands run from the **project root** (the folder containing
`backend/`, `frontend/`, `src/`), not from inside `backend/`.

```bash
git clone <repo-url> threatlens
cd threatlens

# 1. (recommended) virtual environment
python -m venv .venv
.venv\Scripts\activate          # Windows
# source .venv/bin/activate     # macOS / Linux

# 2. dependencies
pip install -r requirements.txt

# 3. AI assistant key (optional - without it the chatbot answers from the knowledge base)
copy .env.example .env          # Windows  (macOS/Linux: cp .env.example .env)
#    then edit .env and set GEMINI_API_KEY=... or GROQ_API_KEY=...

# 4. start
python -m uvicorn backend.app:app --reload
```
Open http://127.0.0.1:8000. Stop the server with `Ctrl+C`.

Trained models and demo samples are included in the repo, so the datasets are only needed to retrain.

## Chrome extension

1. Start the backend (above).
2. Open `chrome://extensions`, turn on **Developer mode** (top right).
3. Click **Load unpacked** and select the `extension/` folder.
4. Pin the ThreatLens icon. Every site you visit gets a badge: **OK** (safe), **!** (caution),
   **✕** (dangerous), **?** (backend not running). Click the icon for a full check.

Automatic checks use the URL model and reputation layer only (fast, not saved to history); the popup runs
the full check, including live HTTPS and header checks.

## Deploy (Render, free plan)

[`render.yaml`](render.yaml) describes the whole service.

1. Sign in at https://dashboard.render.com with GitHub.
2. **New → Blueprint**, select this repository, then **Apply**.
3. When asked, paste `GEMINI_API_KEY` or `GROQ_API_KEY` (leave the other empty).
4. Wait for the first build (~5 min), then open `https://threatlens-xxxx.onrender.com`.

Every push to `main` redeploys automatically. Free services sleep after 15 minutes without traffic and take
about a minute to wake up, so open the site a minute before a demo.

Deployed mode (`THREATLENS_MULTI_USER=1`) gives every visitor a private session (history and browsing feed),
rate-limits chat, uploads and website checks, and caps uploads at 10 MB (`THREATLENS_MAX_UPLOAD_MB`).
To use the extension with the deployed site, set its **Backend URL** to the Space URL and paste the
**pairing code** shown on the Browsing Activity page.

## Datasets (only for retraining)

| Dataset | Put it in | Source |
|---|---|---|
| CIC-IDS2017 `MachineLearningCSV.zip` (extract all CSVs) | `data/raw/cicids2017/` | https://www.unb.ca/cic/datasets/ids-2017.html |
| Malicious URLs dataset (`malicious_phish.csv`) | `data/raw/urls/` | Kaggle: "Malicious URLs dataset" |
| MITRE ATT&CK `enterprise-attack.json` | `data/raw/mitre/` | https://github.com/mitre-attack/attack-stix-data |

## Rebuild from scratch (only if data or models change)

```bash
pip install -r requirements-train.txt
python -m src.prepare_flows       # clean CIC-IDS2017 -> data/processed/flows.parquet
python -m src.train_flows         # RF vs XGBoost + Isolation Forest -> models/, reports/
python -m src.train_urls          # URL model comparison -> models/url_classifier.joblib
python -m src.build_knowledge     # MITRE ATT&CK + playbooks -> knowledge/kb.json
python -m src.make_demo_samples   # demo CSVs from the held-out test split -> data/samples/
```

## Architecture

```
Flow CSV ──► XGBoost classifier ──► incidents (≥5 flows) ──► evidence vs benign baseline
          └► Isolation Forest (benign-classified flows) ──► anomaly incident if rate > 2x noise
URL ──► reputation layer ──► char-n-gram + lexical ML model ──► passive live checks (HTTPS, cert, headers)
Result ──► security score ──► playbook + MITRE ATT&CK ──► AI assistant (TF-IDF retrieval + Gemini/Groq)
```

| Folder | Contents |
|---|---|
| `src/` | data preparation, training, knowledge-base builder |
| `backend/` | FastAPI app, detector, URL checker, retrieval, LLM client |
| `frontend/` | website (HTML/CSS/JS, served by FastAPI) |
| `knowledge/` | playbooks, trusted domains, generated knowledge base |
| `reports/` | metrics, confusion matrices, feature importance (for the report) |

## Results

**Network flows (CIC-IDS2017):** 2.8M raw flows → removed 329,851 duplicates (11.7%) → 359,150 balanced
flows, 69 features, 80/20 stratified split (287,320 / 71,830).

| Model | Accuracy | Macro F1 | Train time |
|---|---|---|---|
| Random Forest | 99.90% | 0.9990 | 49 s |
| **XGBoost (selected)** | **99.94%** | **0.9994** | 31 s |

Isolation Forest: 1.04% false alarms on benign traffic (calibrated to 1%).

**URLs (Malicious URLs dataset):** 641,119 unique URLs, 80/20 split. URLs are normalized (scheme and
`www.` removed) because 97% of benign URLs in the dataset have no scheme, a shortcut the model would
otherwise learn. The training split is augmented with 74,328 benign bare domains.

| Model | Accuracy | Macro F1 | Phishing F1 |
|---|---|---|---|
| Lexical features + XGBoost | 85.7% | 0.801 | 0.490 |
| **Char n-grams (hashed) + lexical + SGD (selected)** | **93.2%** | **0.920** | **0.778** |

Character n-grams use feature hashing (2^19 buckets) instead of a stored vocabulary, which cut the URL
model's memory from ~106 MB to ~10 MB with no loss of accuracy, so the app fits free hosting tiers.

## Limitations (say these in the viva)

- CIC-IDS2017 is lab traffic. Near-perfect scores reflect a clean, separable dataset; real networks will be harder.
- Flow data shows behavior, not content: it cannot tell whether a login succeeded.
- The URL dataset's benign class does not represent modern popular sites, hence the reputation layer.
- Nothing is blocked automatically; recommendations are for a human to act on.
