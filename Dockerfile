FROM python:3.12-slim

# NIST CM-7: Least functionality — no shell tools, no package manager after build
WORKDIR /app

# System deps for psutil only — nothing else
RUN apt-get update && apt-get install -y --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first (layer cache optimisation)
COPY requirements-deploy.txt .

# Install lightweight deploy deps (no spaCy/Presidio — regex fallback active)
RUN pip install --no-cache-dir -r requirements-deploy.txt

# Copy application code
COPY config.py models.py policy_engine.py presidio_scanner.py \
     alert_output.py ingestion.py scanner_worker.py \
     telemetry_generator.py main.py ./

# Non-root user (NIST AC-6: Least Privilege)
RUN useradd -m -u 1001 appuser && chown -R appuser /app
USER appuser

# PORT is injected by Render/Railway at runtime
ENV HOST=0.0.0.0
EXPOSE 8000

# Uvicorn — single worker for free tier RAM constraints
CMD ["python", "-m", "uvicorn", "presidio_scanner:app", \
     "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
