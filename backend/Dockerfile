FROM python:3.12-slim

WORKDIR /app

# System deps for spaCy/presidio build steps
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Pull the spaCy model at build time so the image is ready to run offline.
RUN pip install --no-cache-dir \
    https://github.com/explosion/spacy-models/releases/download/en_core_web_sm-3.7.1/en_core_web_sm-3.7.1-py3-none-any.whl

COPY app ./app
COPY .env.example .env

RUN mkdir -p data models

EXPOSE 8000

# In production, put this behind TLS (e.g. a reverse proxy) --
# the extension will be sending prompt content to this endpoint.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
