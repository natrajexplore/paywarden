# Pinned patch release (re-pin to a digest with `docker pull` + `docker inspect` before production).
FROM python:3.12.10-slim-bookworm
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /app
RUN useradd --create-home --uid 10001 warden
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY --chown=warden:warden . .
USER warden
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8000/healthz')"
# FORWARDED_ALLOW_IPS: only trust X-Forwarded-For from the platform proxy (set in render.yaml).
CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000} --proxy-headers --no-server-header"]
