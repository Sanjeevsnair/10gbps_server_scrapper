# Lightweight base with Python
FROM python:3.10-slim

# avoid Python buffering, keep small image
ENV PYTHONUNBUFFERED=1 \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8

# Install OS deps needed for cryptography, lxml/bs4, and building wheels
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    gcc \
    libssl-dev \
    libffi-dev \
    libxml2-dev \
    libxslt1-dev \
    ca-certificates \
    git \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy requirements and install (use --no-cache-dir to keep image small)
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# Copy application code
COPY . /app

# Create a non-root user (recommended for security) and own the workdir
RUN useradd -m appuser && chown -R appuser:appuser /app
USER appuser

# HF Spaces & common configs: expose port used in your script
EXPOSE 7860

# Start the app with uvicorn. Adjust module:app if your file/module name differs.
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "7860", "--proxy-headers", "--loop", "asyncio", "--timeout-keep-alive", "30"]
