# ---------- Base image ----------
FROM python:3.11-slim AS base

# ---------- System setup ----------
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# ---------- App setup ----------
WORKDIR /app

# Copy dependencies first (for caching)
COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

# Copy source code
COPY app.py .

# ---------- Environment ----------
ENV PORT=7860 \
    PYTHONUNBUFFERED=1 \
    EXTRACT_TIMEOUT_SEC=300

# ---------- Run ----------
EXPOSE 7860
CMD ["python", "app.py"]
