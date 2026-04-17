# Architecture Document — Phishing Detection System

High-level **system design**, **data flow**, and **module responsibilities** for the project.

---

## System overview

```text
┌─────────────────┐     HTTP POST /predict      ┌──────────────────┐
│  Browser (UI)   │ ──────────────────────────► │  Flask (app.py)  │
│  index.html     │ ◄────────────────────────── │  loads classifier│
└─────────────────┘     JSON: verdict, prob,   └────────┬─────────┘
                        top_features, raw_feat            │
                                                            ▼
                                                  ┌──────────────────┐
                                                  │ utils.extract_   │
                                                  │ features(url)    │
                                                  └────────┬─────────┘
                                                           │
                                                           ▼
                                                  ┌──────────────────┐
                                                  │ GradientBoosting │
                                                  │ (classifier.pkl) │
                                                  └──────────────────┘
```

**Offline (training):**

```text
Dataset (CSV) → train_model.py → engineered features → train/test split
    → GradientBoostingClassifier.fit → metrics (classification report)
    → classifier.pkl (model + feature column list)
```

---

## Components

### `utils.py`

- **Role:** Single source of truth for **feature definitions** and **extraction**.
- **Exports:** `FEATURE_COLUMNS`, `extract_features(url)` returning `(feature_vector, feature_dict)`.
- **Why separate:** Training and inference must use **identical** features to avoid train/serve skew.

### `train_model.py`

- **Role:** Ingest real-world data, map labels to binary (0 benign, 1 malicious), apply `extract_features` per URL row, build a training table, **75/25 stratified split**, train `GradientBoostingClassifier`, print **classification report**, persist artifact to **`classifier.pkl`**.

### `app.py`

- **Role:** Production-style **inference server**.
- **Startup:** Change working directory to project root, load `classifier.pkl`, unwrap model + feature names.
- **Routes:**
  - `GET /` → serve `templates/index.html`.
  - `POST /predict` → parse JSON `url`, run `extract_features`, `predict_proba` with a **pandas DataFrame** (feature names aligned with training), compute **verdict** from probability thresholds, compute **top_features** from global importances × feature magnitude.

### `templates/index.html`

- **Role:** Client-only dashboard; calls `/predict` with **Fetch**, renders verdict, bar, and technical details.

---

## Data flow (inference)

1. Client sends `{ "url": "<string>" }`.
2. Server normalizes URL in `extract_features` (scheme default, malformed IPv6 handling).
3. Feature vector is built in **`FEATURE_COLUMNS`** order.
4. Model outputs class probabilities; **class 1** probability = malicious score in `[0, 1]`.
5. **Verdict thresholds** (in `app.py`):
   - `≥ 0.75` → Malicious  
   - `≥ 0.40` → Suspicious  
   - else → Safe  
6. **top_features:** Rank features by `|value| × feature_importance` (explainability heuristic).

---

## Model artifact

`classifier.pkl` stores a dict:

- `model`: fitted `GradientBoostingClassifier`
- `feature_columns`: list matching `FEATURE_COLUMNS` at train time

This keeps inference aligned even if column order changes in code (as long as training is re-run).

---

## Scalability & deployment notes (for judges)

- **Current:** Single-process Flask; suitable for demos and low traffic.
- **Scale-out:** Put behind Gunicorn/uWSGI + reverse proxy; stateless API allows horizontal scaling.
- **Security:** Add rate limiting, input length caps, and HTTPS termination at the proxy for public deployment.

---

## Failure modes

- Missing `classifier.pkl` → app fails at import (intentional: train first).
- Bad or empty URL → API should return `400` with a clear error (client validates non-empty URL).

---

## Related documents

- **README.md** — setup and run instructions  
- **DESIGN.md** — UI/UX decisions for the dashboard  
