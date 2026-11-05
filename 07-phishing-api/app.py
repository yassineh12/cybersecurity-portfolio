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

import logging
import os
import sys
import time
import uuid
from collections import defaultdict
from pathlib import Path

from flask import Flask, jsonify, request

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "02-phishing-detector"))
from url_features import extract  # noqa: E402

VERSION = "1.1.0"

log = logging.getLogger(__name__)

app = Flask(__name__)

MODEL = None
FEATURE_NAMES = None

_rate_limits: dict[str, list[float]] = defaultdict(list)
RATE_LIMIT_MAX = 60
RATE_LIMIT_WINDOW = 60.0

_metrics = {
    "total_requests": 0,
    "total_response_time_ms": 0.0,
}


def _check_rate_limit(ip: str) -> bool:
    now = time.monotonic()
    timestamps = _rate_limits[ip]
    _rate_limits[ip] = [t for t in timestamps if now - t < RATE_LIMIT_WINDOW]
    if len(_rate_limits[ip]) >= RATE_LIMIT_MAX:
        return False
    _rate_limits[ip].append(now)
    return True


@app.before_request
def _before():
    request._start_time = time.monotonic()
    request._request_id = uuid.uuid4().hex


@app.after_request
def _after(response):
    elapsed = (time.monotonic() - getattr(request, "_start_time", time.monotonic())) * 1000
    _metrics["total_requests"] += 1
    _metrics["total_response_time_ms"] += elapsed

    req_id = getattr(request, "_request_id", uuid.uuid4().hex)
    response.headers["X-Request-ID"] = req_id
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type"

    log.info("%s %s %s %.1fms", request.method, request.path,
             response.status_code, elapsed)
    return response


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
    return jsonify({"status": "ok", "model_loaded": MODEL is not None,
                    "version": VERSION})


@app.route("/predict", methods=["POST"])
def predict():
    if not _check_rate_limit(request.remote_addr or "unknown"):
        return jsonify({"error": "Rate limit exceeded. Max 60 requests per minute."}), 429

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
    if not _check_rate_limit(request.remote_addr or "unknown"):
        return jsonify({"error": "Rate limit exceeded."}), 429

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

    return jsonify({"results": results, "count": len(results),
                    "truncated": len(data["urls"]) > 100})


@app.route("/docs", methods=["GET"])
def docs():
    return jsonify({
        "openapi": "3.0.0",
        "info": {"title": "Phishing Detector API", "version": VERSION},
        "paths": {
            "/health": {
                "get": {
                    "summary": "Health check",
                    "responses": {"200": {"description": "Status and model info"}},
                }
            },
            "/predict": {
                "post": {
                    "summary": "Classify a single URL",
                    "requestBody": {
                        "required": True,
                        "content": {"application/json": {
                            "schema": {
                                "type": "object",
                                "required": ["url"],
                                "properties": {
                                    "url": {"type": "string"},
                                    "threshold": {"type": "number", "default": 0.5},
                                },
                            }
                        }},
                    },
                    "responses": {
                        "200": {"description": "Verdict with confidence and features"},
                        "400": {"description": "Missing or invalid input"},
                        "429": {"description": "Rate limit exceeded"},
                        "503": {"description": "Model not loaded"},
                    },
                }
            },
            "/batch": {
                "post": {
                    "summary": "Classify up to 100 URLs",
                    "requestBody": {
                        "required": True,
                        "content": {"application/json": {
                            "schema": {
                                "type": "object",
                                "required": ["urls"],
                                "properties": {
                                    "urls": {"type": "array", "items": {"type": "string"}},
                                    "threshold": {"type": "number", "default": 0.5},
                                },
                            }
                        }},
                    },
                    "responses": {
                        "200": {"description": "Array of verdicts"},
                        "400": {"description": "Missing or invalid input"},
                        "429": {"description": "Rate limit exceeded"},
                        "503": {"description": "Model not loaded"},
                    },
                }
            },
            "/docs": {
                "get": {"summary": "This API documentation"}
            },
            "/metrics": {
                "get": {"summary": "Request metrics"}
            },
        },
    })


@app.route("/metrics", methods=["GET"])
def metrics():
    total = _metrics["total_requests"]
    avg_ms = (_metrics["total_response_time_ms"] / total) if total else 0
    return jsonify({
        "total_requests": total,
        "average_response_time_ms": round(avg_ms, 2),
        "model_loaded": MODEL is not None,
        "version": VERSION,
    })


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO,
                        format="%(levelname)s %(message)s")
    log.info("Phishing Detector API v%s", VERSION)
    if load_model():
        log.info("Model loaded successfully.")
    else:
        log.warning("Model not found. /predict will return 503.")
        log.info("Run: cd 02-phishing-detector && python train.py")
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=False)
