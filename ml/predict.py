import os
import joblib
import numpy as np
import pandas as pd
MODEL_PATH = os.path.join(os.path.dirname(__file__), "..", "models", "nids_rf.joblib")
_bundle = joblib.load(MODEL_PATH)
MODEL = _bundle["model"]
FEATURES = _bundle["features"]
MAPPING = _bundle["mapping"]
TIME_SCALE = _bundle["time_scale"]
TIME_FEATURES = [
    f for f in FEATURES
    if any(k in f for k in ("Duration", "IAT", "Active", "Idle"))
]
def predict_flows(flows):
    """Take the extractor's table of flows, return it with predictions added."""
    X = pd.DataFrame({feat: flows[col] for feat, col in MAPPING.items()})[FEATURES]
    for feat in TIME_FEATURES:
        X[feat] = X[feat] * TIME_SCALE
    X = X.replace([np.inf, -np.inf], np.nan).fillna(0)
    result = flows.copy()
    result["prediction"] = MODEL.predict(X)
    result["attack_probability"] = MODEL.predict_proba(X)[:, 1]
    return result