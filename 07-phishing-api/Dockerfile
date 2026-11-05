FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . /portfolio
WORKDIR /portfolio/07-phishing-api

ENV MODEL_PATH=/portfolio/02-phishing-detector/model/phishing_rf.joblib
ENV PORT=5000

EXPOSE 5000

CMD ["python", "app.py"]
