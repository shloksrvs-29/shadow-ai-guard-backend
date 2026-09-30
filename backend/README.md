# Shadow AI Guard — Backend

FastAPI gateway that inspects text intercepted by the browser extension
before it reaches a public LLM, and decides allow/block using a hybrid
regex + NER detection pipeline. Implements objectives 2.2–2.4, 2.6, 2.7
from the project synopsis.

## Quick start

```bash
cd backend
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
pip install https://github.com/explosion/spacy-models/releases/download/en_core_web_sm-3.7.1/en_core_web_sm-3.7.1-py3-none-any.whl

cp .env.example .env   # edit secrets before deploying anywhere real

uvicorn app.main:app --reload
```

Visit `http://127.0.0.1:8000/docs` for interactive Swagger UI.

Run tests:
```bash
pytest -v
```

## Architecture

```
Extension  →  POST /api/v1/analyze  →  RegexEngine   ┐
                                     →  NerEngine     ┤→ DecisionEngine → allow/block
                                                       ┘        ↓
                                                            AuditLog (hash-chained SQLite)
```

- **`app/detectors/regex_engine.py`** — deterministic patterns for structured
  secrets (AWS/GCP/GitHub/Slack/Stripe keys, JWTs, PEM private keys, DB
  connection strings, generic password assignments). Sub-millisecond.
- **`app/detectors/ner_engine.py`** — semantic detection for unstructured
  PII/business data. Ships today on **Presidio + spaCy** (`en_core_web_sm`).
  The interface (`NerBackend`) is swappable — flip one config value to use
  a **fine-tuned transformer** instead (see "Training your own model" below).
- **`app/policy/decision_engine.py`** — merges findings, applies
  `SAG_BLOCK_ON_SEVERITY` threshold, produces the final verdict + human
  explanation.
- **`app/audit/audit_log.py`** — SQLite audit trail where each row's hash
  includes the previous row's hash (blockchain-style chaining). `GET
  /api/v1/audit/verify` recomputes the whole chain and reports the first
  tampered row, if any.
- **`app/auth.py`** — API keys for extension clients (`X-API-Key` header),
  JWT login for the admin/audit dashboard (`POST /api/v1/auth/token`).

## API

| Method | Path | Auth | Purpose |
|---|---|---|---|
| GET | `/health` | none | liveness probe |
| POST | `/api/v1/analyze` | API key | run detection on a submitted text, get allow/block |
| POST | `/api/v1/auth/token` | none (username/password) | get a JWT for dashboard access |
| GET | `/api/v1/audit` | JWT | query audit history (filter by org/user) |
| GET | `/api/v1/audit/verify` | JWT | verify audit log hasn't been tampered with |

Default dev login: `admin` / `changeme` (rotate before any real deployment —
see `app/auth.py`, `_FAKE_USER_DB`).

Example request:
```bash
curl -X POST http://127.0.0.1:8000/api/v1/analyze \
  -H "X-API-Key: dev-local-key-change-me" \
  -H "Content-Type: application/json" \
  -d '{"text": "my key is AKIAIOSFODNN7EXAMPLE", "platform": "chatgpt", "user_id": "u1", "org_id": "acme"}'
```

## Training your own NER model (do this outside the dev sandbox)

The pretrained Presidio/spaCy backend works today but will produce some
false positives/negatives typical of general-purpose small models (e.g.
misclassifying a function name as a person). For real accuracy gains,
fine-tune a transformer on a labelled PII dataset:

```bash
pip install transformers datasets seqeval torch accelerate evaluate
python scripts/train_ner.py \
    --dataset_name ai4privacy/pii-masking-200k \
    --base_model distilbert-base-uncased \
    --output_dir ./models/shadow-ner-finetuned \
    --epochs 3
```

Run this on your own machine or Google Colab (GPU strongly recommended —
CPU works but is slow for 200k examples). Then point the backend at it:

```
SAG_NER_BACKEND=transformer
SAG_TRANSFORMER_MODEL_PATH=./models/shadow-ner-finetuned
```

Restart the service — no code changes needed, `NerEngine` picks the backend
from config.

## Deployment

```bash
docker build -t shadow-ai-guard-backend .
docker run -p 8000:8000 --env-file .env shadow-ai-guard-backend
```

For a real enterprise rollout, still needed (not yet built — flagging for
the next stage):
- Swap SQLite → Postgres for the audit log (multi-instance write safety).
- Replace `_FAKE_USER_DB` with a real user store / SSO (SAML/OIDC) for the
  admin dashboard.
- Put this behind TLS + a reverse proxy; restrict `SAG_ALLOWED_ORIGINS` to
  your actual extension ID(s) instead of `"*"`.
- Rate limiting / per-org quotas on `/api/v1/analyze`.
- Rotate `SAG_JWT_SECRET` and `SAG_API_KEYS` out of `.env` into a secrets
  manager (AWS Secrets Manager / Vault / etc).

## Known limitations (v1)

- Presidio/spaCy backend can misclassify some code identifiers as PERSON
  entities (see `test_analyze_blocks_secret` findings in practice) — the
  fine-tuning step above is the intended fix.
- Source-code detection is currently heuristic (pattern-hint counting), not
  ML-based — a good candidate for the same fine-tuning pass with a
  labelled code-vs-prose dataset.
- Audit log preview text is truncated/redacted by design (privacy), so it
  can't be used to fully reconstruct what was blocked — only that
  something in a given category was.
