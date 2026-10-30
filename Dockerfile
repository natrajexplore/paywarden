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
HEALTHCHECK --interval=30s --timeout=3s CMD python -c "import os,urllib.request;urllib.request.urlopen('http://127.0.0.1:%s/healthz' % os.environ.get('PORT', '8000'))"
# Client IPs for rate limiting come from TRUSTED_PROXY_HOPS (see middleware.py), not from uvicorn's
# proxy-header rewriting, so no FORWARDED_ALLOW_IPS wildcard is needed.
CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000} --no-server-header"]
