"""Phishing detector web API.

Wraps project 2's classifier into a small Flask API that accepts a URL
and returns a verdict with confidence and feature explanations.

Usage:
    python app.py                   # starts on http://localhost:5000
    curl -X POST http://localhost:5000/predict -H 'Content-Type: application/json' \
         -d '{"url": "http://paypa1-verify.xyz/login"}'

Docker:
    docker build -t phishing-api .
    docker run -p 5000:5000 phishing-api
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

from flask import Flask, jsonify, request

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "02-phishing-detector"))
from url_features import extract  # noqa: E402

app = Flask(__name__)

MODEL = None
FEATURE_NAMES = None


def load_model():
    global MODEL, FEATURE_NAMES
    model_path = os.environ.get("MODEL_PATH",
                                str(Path(__file__).resolve().parents[1]
                                    / "02-phishing-detector" / "model" / "phishing_rf.joblib"))
    if not Path(model_path).exists():
        return False
    import joblib
    bundle = joblib.load(model_path)
    MODEL = bundle["model"]
    FEATURE_NAMES = bundle["features"]
    return True


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "model_loaded": MODEL is not None})


@app.route("/predict", methods=["POST"])
def predict():
    data = request.get_json(silent=True)
    if not data or "url" not in data:
        return jsonify({"error": "JSON body with 'url' field required."}), 400

    if MODEL is None:
        return jsonify({"error": "Model not loaded. Run train.py first."}), 503

    url = data["url"]
    threshold = data.get("threshold", 0.5)

    features = extract(url)
    import numpy as np
    vals = [features.get(f, 0) for f in FEATURE_NAMES]
    x = np.array(vals).reshape(1, -1)

    prob = float(MODEL.predict_proba(x)[0][1])
    verdict = "phishing" if prob >= threshold else "safe"

    importances = sorted(
        zip(FEATURE_NAMES, MODEL.feature_importances_),
        key=lambda x: -x[1]
    )
    top_features = [
        {"feature": name, "value": features.get(name, 0), "importance": round(imp, 4)}
        for name, imp in importances[:8]
    ]

    return jsonify({
        "url": url,
        "verdict": verdict,
        "confidence": round(prob, 4),
        "threshold": threshold,
        "top_features": top_features,
        "all_features": features,
    })


@app.route("/batch", methods=["POST"])
def batch_predict():
    data = request.get_json(silent=True)
    if not data or "urls" not in data:
        return jsonify({"error": "JSON body with 'urls' array required."}), 400

    if MODEL is None:
        return jsonify({"error": "Model not loaded."}), 503

    urls = data["urls"][:100]
    threshold = data.get("threshold", 0.5)
    results = []

    import numpy as np
    for url in urls:
        features = extract(url)
        vals = [features.get(f, 0) for f in FEATURE_NAMES]
        x = np.array(vals).reshape(1, -1)
        prob = float(MODEL.predict_proba(x)[0][1])
        results.append({
            "url": url,
            "verdict": "phishing" if prob >= threshold else "safe",
            "confidence": round(prob, 4),
        })

    return jsonify({"results": results, "count": len(results)})


if __name__ == "__main__":
    if load_model():
        print("Model loaded successfully.")
    else:
        print("Warning: model not found. /predict will return 503.")
        print("Run: cd 02-phishing-detector && python train.py")
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=False)
