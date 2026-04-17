import os
import pickle

import numpy as np
import pandas as pd
from flask import Flask, jsonify, render_template, request

from utils import FEATURE_COLUMNS, extract_features

app = Flask(__name__)


def load_artifact():
    with open("classifier.pkl", "rb") as file:
        saved = pickle.load(file)
    if isinstance(saved, dict) and "model" in saved:
        return saved["model"], saved.get("feature_columns", FEATURE_COLUMNS)
    return saved, FEATURE_COLUMNS


try:
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    model, feature_columns = load_artifact()
except FileNotFoundError:
    raise RuntimeError("classifier.pkl missing. Run train_model.py first.")


def probability_to_verdict(phish_probability: float) -> str:
    if phish_probability >= 0.75:
        return "Malicious"
    if phish_probability >= 0.40:
        return "Suspicious"
    return "Safe"


def feature_influence(feature_list):
    values = np.array(feature_list, dtype=float)
    importances = getattr(model, "feature_importances_", np.ones_like(values))
    scores = np.abs(values) * importances
    ranked_idx = np.argsort(scores)[::-1]
    top = []
    for idx in ranked_idx[:3]:
        top.append(
            {
                "name": feature_columns[idx],
                "value": float(values[idx]),
                "influence": float(scores[idx]),
            }
        )
    return top


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/predict", methods=["POST"])
def predict():
    payload = request.get_json(silent=True) or {}
    url = str(payload.get("url", "")).strip()
    if not url:
        return jsonify({"error": "No URL provided"}), 400

    feature_list, feature_dict = extract_features(url)
    feature_frame = pd.DataFrame([feature_list], columns=feature_columns)
    probabilities = model.predict_proba(feature_frame)[0]
    malicious_probability = float(probabilities[1])
    verdict = probability_to_verdict(malicious_probability)
    top_features = feature_influence(feature_list)

    return jsonify(
        {
            "verdict": verdict,
            "probability": round(malicious_probability, 4),
            "top_features": top_features,
            "raw_features": feature_dict,
        }
    )


if __name__ == "__main__":
    app.run(debug=True, port=5000)