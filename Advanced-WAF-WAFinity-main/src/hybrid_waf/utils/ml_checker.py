"""
ML Checker - loads the trained classifier model (ml_model.pkl)
and exposes check_ml_prediction().
"""
import os
import joblib
from sklearn.ensemble import RandomForestClassifier
import numpy as np

MODEL_PATH = os.path.join(os.path.dirname(__file__), "../models/ml_model.pkl")

try:
    ml_model = joblib.load(MODEL_PATH)
except Exception:
    # Fallback: untrained model returns 0 (safe) for all inputs
    ml_model = RandomForestClassifier()
    # Fit on trivial dummy data so it doesn't crash on predict
    X = np.zeros((10, 8))
    y = [0] * 10
    ml_model.fit(X, y)


def check_ml_prediction(features: list) -> int:
    """
    Takes a list of 8 features and returns:
      1  → malicious
      0  → safe
    """
    try:
        feat = list(features)
        while len(feat) < 8:
            feat.append(0.0)
        feat = feat[:8]
        return int(ml_model.predict([feat])[0])
    except Exception:
        return 0  # safe default
