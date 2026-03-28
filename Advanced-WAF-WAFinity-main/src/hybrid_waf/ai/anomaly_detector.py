"""
AI Anomaly Detector using Isolation Forest.
Loads pre-trained model; falls back to a default model if missing.
"""
import os
import joblib
from sklearn.ensemble import IsolationForest

MODEL_PATH = os.path.join(os.path.dirname(__file__), "../../../../models/anomaly_model.pkl")

# Try to load pre-trained model; if not found, create a default one
try:
    _model = joblib.load(MODEL_PATH)
except Exception:
    _model = IsolationForest(contamination=0.05, random_state=42)
    # Fit on dummy data so it's usable immediately
    import numpy as np
    dummy = np.random.rand(100, 5)
    _model.fit(dummy)


def predict(features):
    """
    Returns -1 if anomaly detected, 1 if normal.
    Handles feature list of any length by padding/truncating to 5.
    """
    try:
        feat = list(features)
        # Pad or truncate to 5 features (model was trained on 5)
        while len(feat) < 5:
            feat.append(0.0)
        feat = feat[:5]
        result = _model.predict([feat])
        return result[0]  # -1 = anomaly, 1 = normal
    except Exception:
        return 1  # safe default: don't flag on error
