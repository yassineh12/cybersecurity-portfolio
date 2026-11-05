# Project 7: Phishing detector API (Docker)

Wraps project 2's classifier into a REST API. Send a URL, get back a verdict with confidence score and feature explanations.

## Quick start

```bash
# Train the model first (if not already done)
cd 02-phishing-detector
python train.py --data data/urls.csv

# Run the API
cd 07-phishing-api
python app.py
```

## API endpoints

### `POST /predict`
Classify a single URL.

```bash
curl -X POST http://localhost:5000/predict \
  -H 'Content-Type: application/json' \
  -d '{"url": "http://paypa1-verify.xyz/login"}'
```

Response:
```json
{
  "url": "http://paypa1-verify.xyz/login",
  "verdict": "phishing",
  "confidence": 0.92,
  "threshold": 0.5,
  "top_features": [
    {"feature": "suspicious_tld", "value": 1, "importance": 0.15},
    {"feature": "num_suspicious_words", "value": 2, "importance": 0.12}
  ]
}
```

### `POST /batch`
Classify up to 100 URLs at once.

```bash
curl -X POST http://localhost:5000/batch \
  -H 'Content-Type: application/json' \
  -d '{"urls": ["https://google.com", "http://evil.xyz/login"]}'
```

### `GET /health`
Liveness check. Reports whether the model is loaded.

## Docker

```bash
docker build -t phishing-api -f 07-phishing-api/Dockerfile .
docker run -p 5000:5000 phishing-api
```

## How it builds on project 2

The API imports `url_features.extract()` directly from project 2 and loads the trained Random Forest model. No code is duplicated — the portfolio is one connected system.

## What I learned

- Shipping a model means more than training it. The API needs input validation, error handling for missing models, health checks for orchestrators, and batch endpoints for throughput.
- Docker makes the environment reproducible. The same model that scores 95% in a notebook scores 95% in production, because the dependencies are pinned.
- Feature extraction at request time adds latency. URL-only features are fast (sub-millisecond). Page-content features would require fetching the page, which adds seconds — a trade-off between accuracy and response time.
