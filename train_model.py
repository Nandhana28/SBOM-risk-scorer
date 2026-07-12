"""Offline trainer for the (legacy) gradient-boosted risk classifier.

NOTE: the live application uses the deterministic engine in `sbom/` and does NOT
load this model. This script exists so the ML variant in `detector.py` can be
trained once, offline, and persisted — instead of retraining from scratch on every
process start. Run it whenever the labelled data changes:

    python train_model.py

It writes models/risk_model.pkl, which detector.get_model() will load if present.
"""
import os
import pickle
import sklearn

from detector import train_risk_model, FEATURE_COLUMNS

MODELS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "models")
MODEL_PATH = os.path.join(MODELS_DIR, "risk_model.pkl")


def main():
    print("Training GradientBoostingClassifier on dependency_labels.csv ...")
    model = train_risk_model()

    # Bundle the model with the exact feature order and provenance. sklearn pickles are
    # version-sensitive, so we record the training version to detect mismatches on load.
    payload = {
        "model": model,
        "features": FEATURE_COLUMNS,
        "sklearn_version": sklearn.__version__,
        "estimator": type(model).__name__,
    }
    os.makedirs(MODELS_DIR, exist_ok=True)
    with open(MODEL_PATH, "wb") as f:
        pickle.dump(payload, f, protocol=pickle.HIGHEST_PROTOCOL)

    size_kb = os.path.getsize(MODEL_PATH) / 1024
    print(f"Saved {MODEL_PATH} ({size_kb:.1f} KB)")
    print(f"  estimator={payload['estimator']}  features={len(FEATURE_COLUMNS)}  "
          f"sklearn={payload['sklearn_version']}")


if __name__ == "__main__":
    main()
