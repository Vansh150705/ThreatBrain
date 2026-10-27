# ThreatBrain backend. Works on Hugging Face Spaces (Docker SDK, port 7860) and
# anywhere else: `docker build -t threatbrain-backend backend/`.
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Hugging Face Spaces requires user 1000 with write access to /code
RUN useradd -m -u 1000 user
WORKDIR /code

# Dependencies first so code changes don't invalidate the layer cache.
# All pinned wheels: no compiler toolchain is needed in the image.
COPY --chown=user:user requirements.txt /code/requirements.txt
RUN pip install -r /code/requirements.txt

COPY --chown=user:user app /code/app

USER user

# Hugging Face routes traffic to 7860 by default; override PORT elsewhere.
ENV PORT=7860 \
    APP_ENV=production \
    LOG_FORMAT=json
EXPOSE 7860

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import os,urllib.request as u; u.urlopen(f'http://127.0.0.1:{os.environ.get(\"PORT\",\"7860\")}/api/v1/health', timeout=4)" || exit 1

# One worker on purpose: rate limiting and the background pipeline pool are
# in-process. Scale out with replicas behind a shared limiter if you need more.
CMD ["sh", "-c", "exec uvicorn app.main:app --host 0.0.0.0 --port ${PORT} --proxy-headers --forwarded-allow-ips='*'"]
