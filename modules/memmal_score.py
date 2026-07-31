

import os
import lightgbm as lgb

MODEL_PATH = os.path.join("models", "memmal_model.txt")
FEATURES_PATH = os.path.join("models", "memmal_features.txt")

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
        print(f"[memmal_score] Failed to load model: {e}")
        _model, _feature_order = None, None
    return _model, _feature_order


# Representative sample values (roughly plausible "normal-looking" process
# snapshot) — used only when no real feature dict is provided yet (i.e.
# before Day 4's real Volatility wiring is done). Clearly NOT a real
# memory dump's output.
SAMPLE_FEATURES = {
    "pslist.nproc": 52, "pslist.nppid": 19, "pslist.avg_threads": 11.4,
    "pslist.nprocs64bit": 48, "pslist.avg_handlers": 210.5,
    "dlllist.ndlls": 980, "dlllist.avg_dlls_per_proc": 18.8,
    "handles.nhandles": 9800, "handles.avg_handles_per_proc": 188.4,
    "handles.nport": 12, "handles.nfile": 340, "handles.nevent": 890,
    "handles.ndesktop": 8, "handles.nkey": 420, "handles.nthread": 610,
    "handles.ndirectory": 60, "handles.nsemaphore": 210, "handles.ntimer": 90,
    "handles.nsection": 410, "handles.nmutant": 180,
    "ldrmodules.not_in_load": 2, "ldrmodules.not_in_init": 1,
    "ldrmodules.not_in_mem": 0, "ldrmodules.not_in_load_avg": 0.02,
    "ldrmodules.not_in_init_avg": 0.01, "ldrmodules.not_in_mem_avg": 0.0,
    "malfind.ninjections": 0, "malfind.commitCharge": 0,
    "malfind.protection": 0, "malfind.uniqueInjections": 0,
    "psxview.not_in_pslist": 0, "psxview.not_in_eprocess_pool": 0,
    "psxview.not_in_ethread_pool": 0, "psxview.not_in_pspcid_list": 0,
    "psxview.not_in_csrss_handles": 0, "psxview.not_in_session": 0,
    "psxview.not_in_deskthrd": 0, "psxview.not_in_pslist_false_avg": 0.0,
    "psxview.not_in_eprocess_pool_false_avg": 0.0,
    "psxview.not_in_ethread_pool_false_avg": 0.0,
    "psxview.not_in_pspcid_list_false_avg": 0.0,
    "psxview.not_in_csrss_handles_false_avg": 0.0,
    "psxview.not_in_session_false_avg": 0.0,
    "psxview.not_in_deskthrd_false_avg": 0.0,
    "modules.nmodules": 140, "svcscan.kernel_drivers": 190,
    "svcscan.fs_drivers": 28, "svcscan.interactive_process_services": 4,
    "svcscan.nactive": 118, "callbacks.ncallbacks": 87,
    "callbacks.nanonymous": 0, "callbacks.ngeneric": 8,
}


def score_memory_features(feature_dict: dict = None) -> dict:
    model, feature_order = _load()
    if model is None:
        return {
            "source": "unavailable",
            "note": "MemMal model not found at models/memmal_model.txt — train it first (Day 1).",
        }

    source = "real" if feature_dict is not None else "sample-values"
    features = feature_dict or SAMPLE_FEATURES

    # Build the row in the EXACT column order the model was trained on —
    # missing keys default to 0 rather than crashing, so partial real
    # Volatility output (not every plugin run) still produces a score.
    row = [[features.get(col, 0) for col in feature_order]]

    probability = model.predict(row)[0]
    return {
        "source": source,
        "maliciousProbability": round(float(probability), 4),
        "verdict": "malveillant" if probability >= 0.5 else "sain",
        "modelSource": "MemMal-D2024 LightGBM (trained Day 1, 5-fold CV AUC 0.9999)",
    }