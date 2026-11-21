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

# 面板启用「私密路径 + 鉴权」后 /api/status 对未带凭据的请求返回 401，
# 这属于「服务正常但需登录」，必须视为存活；仅 5xx/连接失败才算不健康。
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import http.client,sys; c=http.client.HTTPConnection('127.0.0.1',5000,timeout=4); c.request('GET','/api/status'); r=c.getresponse(); r.read(); sys.exit(0 if r.status in (200,401,403) else 1)"

CMD ["gunicorn","-w","1","-k","gthread","--threads","8","-b","0.0.0.0:5000","app:app","--access-logfile","-","--error-logfile","-"]
