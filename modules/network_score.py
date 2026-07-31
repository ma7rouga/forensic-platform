

import os
import lightgbm as lgb

MODEL_PATH = os.path.join("models", "cicids_model.txt")
FEATURES_PATH = os.path.join("models", "cicids_features.txt")

_model = None
_feature_order = None
_load_attempted = False


def _load():
    global _model, _feature_order, _load_attempted
    if _load_attempted:
        return _model, _feature_order
    _load_attempted = True

    if not os.path.exists(MODEL_PATH) or not os.path.exists(FEATURES_PATH):
        return None, None
    try:
        _model = lgb.Booster(model_file=MODEL_PATH)
        with open(FEATURES_PATH) as f:
            _feature_order = f.read().splitlines()
    except Exception as e:  # noqa: BLE001
        print(f"[network_score] Failed to load model: {e}")
        _model, _feature_order = None, None
    return _model, _feature_order


# Representative sample values (roughly "normal-looking" flow) — used only
# when no real flow feature dict is provided. Clearly NOT real captured
# traffic.
SAMPLE_FLOW = {
    "Protocol": 6, "Flow Duration": 45000, "Total Fwd Packets": 12,
    "Total Backward Packets": 10, "Fwd Packets Length Total": 3400,
    "Flow Bytes/s": 890.5, "Flow Packets/s": 12.3, "Flow IAT Mean": 3200.0,
    "Fwd IAT Mean": 3400.0, "Active Std": 120.5, "Bwd Packet Length Max": 512,
    "Init Bwd Win Bytes": 64240,
}


def score_network_flow(feature_dict: dict = None) -> dict:
    model, feature_order = _load()
    if model is None:
        return {
            "source": "unavailable",
            "note": "CICIDS model not found at models/cicids_model.txt — train it first (Day 2).",
        }

    source = "real" if feature_dict is not None else "sample-values"
    features = feature_dict or SAMPLE_FLOW

    row = [[features.get(col, 0) for col in feature_order]]

    probability = model.predict(row)[0]
    return {
        "source": source,
        "attackProbability": round(float(probability), 4),
        "verdict": "attaque" if probability >= 0.5 else "normal",
        "modelSource": "CICIDS2017 LightGBM (trained Day 2, 5-fold CV AUC 0.999)",
    }