import os
import pickle
from io import StringIO

import pandas as pd
import requests
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split

from utils import FEATURE_COLUMNS, extract_features

#Dataset Sources - KAGGLE
DATA_SOURCES = [
    "malicious_phish.csv",
    "https://raw.githubusercontent.com/mango-cat/ECS171-Project/main/malicious_phish.csv",
    "https://archive.ics.uci.edu/ml/machine-learning-databases/00327/Training%20Dataset.arff",
]

# Dataset Used for Trianig ML Model using Scikit-Learn
def load_dataset():
    for source in DATA_SOURCES:
        try:
            if source.lower().endswith(".arff"):
                continue
            if source.startswith("http"):
                response = requests.get(source, timeout=20)
                response.raise_for_status()
                df = pd.read_csv(StringIO(response.text))
            else:
                df = pd.read_csv(source)
            print(f"Loaded dataset from: {source}")
            return df
        except Exception:
            continue
    raise RuntimeError(
        "Could not load phishing dataset. Place 'malicious_phish.csv' in this directory."
    )


def map_label(raw_label):
    value = str(raw_label).strip().lower()
    if value in {"benign", "safe", "legitimate", "good", "0"}:
        return 0
    return 1


def prepare_training_frame(df):
    possible_url_cols = ["url", "URL", "domain", "link", "website"]
    possible_label_cols = ["type", "label", "status", "class", "result"]

    url_col = next((c for c in possible_url_cols if c in df.columns), None)
    label_col = next((c for c in possible_label_cols if c in df.columns), None)
    if url_col is None or label_col is None:
        raise ValueError(
            f"Dataset must contain URL and label columns. Found columns: {list(df.columns)}"
        )

    working = df[[url_col, label_col]].dropna().copy()
    working.columns = ["url", "raw_label"]
    working["label"] = working["raw_label"].apply(map_label).astype(int)

    engineered = working["url"].apply(lambda x: pd.Series(extract_features(x)[1]))
    training_df = pd.concat([engineered[FEATURE_COLUMNS], working["label"]], axis=1)
    return training_df

# Actual Trainig Function for ML model Using Sci-Kit learn
def train():
    raw_df = load_dataset()
    train_df = prepare_training_frame(raw_df)

    X = train_df[FEATURE_COLUMNS]
    y = train_df["label"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y
    )

    model = GradientBoostingClassifier(random_state=42)
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, digits=4))

    artifact = {
        "model": model,
        "feature_columns": FEATURE_COLUMNS,
    }
    with open("classifier.pkl", "wb") as file:
        pickle.dump(artifact, file)
    print("\nSaved model artifact: classifier.pkl")


if __name__ == "__main__":
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    train()
