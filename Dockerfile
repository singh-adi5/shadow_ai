FROM python:3.11-slim

WORKDIR /app

# ENABLE_PRESIDIO_MODEL=false (default): installs requirements-deploy.txt —
# fastapi/pydantic/etc only, no presidio-analyzer/spacy at all — fast build,
# no compiler needed, app runs fully functional on the regex fallback (see
# SECURITY.md "PII Detection Coverage"). Correct default for a free/starter
# deploy plan.
# ENABLE_PRESIDIO_MODEL=true: installs the full requirements.txt (adds
# presidio-analyzer/presidio-anonymizer/spacy) plus the ~600MB spaCy
# language model, for full NLP-grade detection on a plan with more build
# resources. build-essential is only pulled in for this path, since some
# of that stack's transitive deps compile from source.
ARG ENABLE_PRESIDIO_MODEL=false

RUN if [ "$ENABLE_PRESIDIO_MODEL" = "true" ]; then \
        apt-get update \
        && apt-get install -y --no-install-recommends build-essential \
        && rm -rf /var/lib/apt/lists/*; \
    fi

COPY requirements.txt requirements-deploy.txt ./
RUN if [ "$ENABLE_PRESIDIO_MODEL" = "true" ]; then \
        pip install --no-cache-dir -r requirements.txt \
        && python -m spacy download en_core_web_lg; \
    else \
        pip install --no-cache-dir -r requirements-deploy.txt; \
    fi

COPY . .

ENV API_HOST=0.0.0.0 \
    API_WORKERS=1 \
    PYTHONUNBUFFERED=1

EXPOSE 8000

# presidio_scanner.py reads PORT (Render/Heroku-style injected env var, via
# config.API_PORT) and binds config.API_HOST — both overridable, see config.py.
CMD ["python", "presidio_scanner.py"]
