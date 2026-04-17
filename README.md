# Phishing URL Detection System

End-to-end **machine learning** pipeline that classifies URLs as **Safe**, **Suspicious**, or **Malicious**, with a **Flask API** and a **Tailwind CSS** security dashboard.

---

## What this project does

1. **Train** a `GradientBoostingClassifier` on a real phishing dataset (URL + label).
2. **Extract** URL-based features (length, symbols, HTTPS, punycode, subdomain depth, etc.).
3. **Serve** predictions via `POST /predict` with verdict, probability, and top contributing features.
4. **Display** results in a dark-themed web UI with loading state and probability bar.

---

## Repository layout

| Path | Purpose |
|------|---------|
| `utils.py` | Feature extraction (`extract_features`) and `FEATURE_COLUMNS` |
| `train_model.py` | Data load, 75/25 split, training, classification report, `classifier.pkl` |
| `app.py` | Flask app, model load, `/` and `/predict` |
| `templates/index.html` | Dashboard UI (Tailwind + Fetch API) |
| `classifier.pkl` | Trained model artifact (generate with training; optional to commit) |

See **DESIGN.md** for UI/UX and **ARCHITECTURE.md** for system design.

---

## Requirements

- Python 3.10+ recommended  
- Dependencies: see `requirements.txt`

```bash
pip install -r requirements.txt
```

---

## Quick start

### 1. Train the model

From this folder:

```bash
python train_model.py
```

This loads data (local `malicious_phish.csv` if present, otherwise a public CSV URL), prints a **classification report**, and writes **`classifier.pkl`**.

### 2. Run the web app

```bash
python app.py
```

Open **http://127.0.0.1:5000** in a browser. Enter a URL and click **Analyze**.

### 3. API (optional)

`POST /predict` with JSON body:

```json
{ "url": "https://example.com/path" }
```

Response includes `verdict`, `probability` (0.0–1.0 malicious score), `top_features`, and `raw_features`.

---

## Tech stack

| Layer | Technology |
|-------|------------|
| ML | scikit-learn `GradientBoostingClassifier`, pandas |
| Features | `tldextract`, `urllib.parse`, `re` |
| API | Flask |
| UI | HTML, Tailwind CSS (CDN), Fetch API |

---

## For judges

- **Design decisions:** `DESIGN.md`
- **Architecture & data flow:** `ARCHITECTURE.md`

---

## License

Use for education and demonstration unless your institution specifies otherwise.
