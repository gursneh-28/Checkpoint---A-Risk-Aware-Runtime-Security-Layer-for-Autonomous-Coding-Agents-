"""
Loads the trained risk model and predicts a risk tier for a command.
Used only as a FALLBACK by risk_classifier.py when no hardcoded rule matches.

Returns (tier, confidence, source), where source is one of:
  "ml"                -> model prediction, confident enough to use as-is
  "ml_low_confidence" -> model was unsure about a LOW prediction, bumped to MEDIUM
  "default"           -> model file missing/unreadable, safe default MEDIUM
"""
import os
import pickle

MODEL_PATH = os.path.join(os.path.dirname(__file__), "..", "storage", "risk_model.pkl")
CONFIDENCE_THRESHOLD = 0.6

_bundle = None


def _load_model():
    global _bundle
    if _bundle is None:
        with open(MODEL_PATH, "rb") as f:
            _bundle = pickle.load(f)
    return _bundle


def predict_risk(command: str):
    try:
        bundle = _load_model()
    except (OSError, pickle.UnpicklingError, EOFError, ImportError):
        return "MEDIUM", 0.0, "default"

    vec = bundle["vectorizer"].transform([command])
    probs = bundle["model"].predict_proba(vec)[0]
    best = probs.argmax()
    tier = str(bundle["model"].classes_[best])
    confidence = float(probs[best])

    # Never let an unsure model wave a command through as LOW.
    if tier == "LOW" and confidence < CONFIDENCE_THRESHOLD:
        return "MEDIUM", confidence, "ml_low_confidence"
    return tier, confidence, "ml"