# ---- Base ----
ARG PY_VER=3.10
FROM python:${PY_VER}-slim AS base

ENV PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# System deps that make scientific wheels happy if a wheel isn't available
RUN apt-get update -y && apt-get install -y --no-install-recommends \
    build-essential gcc g++ \
    # optional but nice-to-have; safe to leave in
    libssl-dev libffi-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# ---- Dependencies layer (better caching) ----
COPY requirements.txt /app/requirements.txt
RUN python -m pip install --upgrade pip && \
    pip install -r requirements.txt

# ---- App code ----
COPY . /app

# Default command: print CLI help 
CMD ["python", "main.py", "--help"]
