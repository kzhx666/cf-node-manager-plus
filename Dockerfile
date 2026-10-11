# syntax=docker/dockerfile:1
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Basic runtime deps
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py ./app.py
COPY templates ./templates

# Persisted runtime data (data.json / cache / logs / GeoIP mmdb)
RUN mkdir -p /app/data \
 && useradd -m -u 10001 appuser \
 && chown -R appuser:appuser /app

USER appuser
EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5000/api/status').read()" || exit 1

CMD ["gunicorn","-w","1","-k","gthread","--threads","8","-b","0.0.0.0:5000","app:app","--access-logfile","-","--error-logfile","-"]
