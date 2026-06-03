# Dockerfile for ThreatBrain backend on Hugging Face Spaces

FROM python:3.11-slim

# System deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Hugging Face Spaces requires user 1000 with write access to /code
RUN useradd -m -u 1000 user
WORKDIR /code

# Install Python deps
COPY --chown=user:user requirements.txt /code/requirements.txt
RUN pip install --no-cache-dir --upgrade pip \
 && pip install --no-cache-dir -r /code/requirements.txt

# Copy app code
COPY --chown=user:user . /code

USER user

# Hugging Face routes traffic to port 7860 by default
ENV PORT=7860
EXPOSE 7860

CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT}"]