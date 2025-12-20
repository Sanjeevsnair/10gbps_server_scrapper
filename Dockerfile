# ===============================
# Base image
# ===============================
FROM python:3.10-slim

ENV PYTHONUNBUFFERED=1 \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright

# ===============================
# System dependencies
# ===============================
RUN apt-get update && apt-get install -y --no-install-recommends \
    # build deps
    build-essential \
    gcc \
    libssl-dev \
    libffi-dev \
    libxml2-dev \
    libxslt1-dev \
    ca-certificates \
    git \
    # playwright / chromium runtime deps
    wget \
    curl \
    libnss3 \
    libatk-bridge2.0-0 \
    libatk1.0-0 \
    libcups2 \
    libdrm2 \
    libxkbcommon0 \
    libxcomposite1 \
    libxdamage1 \
    libxfixes3 \
    libxrandr2 \
    libgbm1 \
    libasound2 \
    libpangocairo-1.0-0 \
    libpango-1.0-0 \
    libgtk-3-0 \
    libx11-6 \
    libxcb1 \
    libxext6 \
    libxi6 \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# ===============================
# Python deps
# ===============================
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# Install playwright browser (CRITICAL)
RUN python -m playwright install chromium

# ===============================
# App code
# ===============================
COPY . /app

# ===============================
# Security: non-root user
# ===============================
RUN useradd -m appuser \
    && chown -R appuser:appuser /app /ms-playwright

USER appuser

# ===============================
# Runtime
# ===============================
EXPOSE 7860

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "7860", "--proxy-headers", "--loop", "asyncio", "--timeout-keep-alive", "30"]
