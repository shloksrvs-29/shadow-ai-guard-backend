# PromptShield ~ Shadow AI Guard

A browser extension and detection backend that stops sensitive data — API keys,
credentials, customer PII, source code, Aadhaar/PAN numbers — from being typed
or pasted into ChatGPT, Gemini, or Claude. Detection happens before the
request leaves the browser, not after the fact.

This exists because "just block AI tools" doesn't work. People use them
anyway, and a ban just pushes usage somewhere you can't see it. The only
approach that actually holds up is inspecting content at the point of
submission and making a real-time allow/block decision, without asking
anyone to change how they work.

## What's actually in here

Two independent pieces, talking to each other over HTTP:

- **`extension/`** — a Manifest V3 Chrome/Edge extension. Content script
  intercepts paste events, Enter-to-submit, and send-button clicks on
  ChatGPT, Gemini, and Claude's web UIs, in the capture phase, before the
  site's own handlers run.
- **`backend/`** — a FastAPI service that receives intercepted text, runs it
  through two detectors in parallel, and returns an allow/block verdict. Also
  owns a hash-chained audit log.

There's no shared hosted backend. Every deployment runs its own instance.
That's a deliberate choice, not a missing feature — see
[Architecture decisions](#architecture-decisions) below.

## How detection works

```
extension (content script)
    │  intercepts paste / keydown-Enter / send-button click
    ▼
background service worker  ──POST /api/v1/analyze──▶  FastAPI backend
                                                            │
                                    ┌───────────────────────┼───────────────────────┐
                                    ▼                                               ▼
                            regex engine                                   NER engine
                    (structured secrets: AWS/GCP/GitHub/                (unstructured PII:
                     Slack/Stripe keys, JWTs, PEM keys,                  names, emails, phone
                     DB conn strings, Aadhaar w/ Verhoeff                numbers, addresses,
                     checksum, PAN, Indian mobile numbers)               DOB, credit cards —
                                    │                                    fine-tuned DistilBERT)
                                    └───────────────┬───────────────────────┘
                                                    ▼
                                            policy decision engine
                                        (merges findings → allow/block)
                                                    │
                                    ┌───────────────┴───────────────┐
                                    ▼                                ▼
                            ALLOW → forwarded                BLOCK → nothing sent,
                            to the AI platform                inline banner shown,
                                                                written to audit log
```

The regex engine is deterministic and runs in under a millisecond. The NER
engine is the slower, probabilistic half — it's what catches PII that
doesn't have a fixed structure (a person's name, a home address, a date of
birth written out in prose).

## Results

The fine-tuned model is a `distilbert-base-uncased` checkpoint, fine-tuned on
68,275 English-language examples (filtered from
[`ai4privacy/pii-masking-400k`](https://huggingface.co/datasets/ai4privacy/pii-masking-400k),
~406k rows across 6 languages) for 3 epochs on a single T4 GPU (~38 min).
Labels were built from the dataset's character-offset `privacy_mask` spans,
not its pre-tokenized columns, so the training pipeline isn't locked to one
specific base model — see `scripts/train_ner.py` if you want to swap in
something larger.

| Metric | Score |
|---|---|
| Precision | 0.877 |
| Recall | 0.891 |
| F1 | 0.884 |
| Accuracy | 0.985 |

Accuracy alone is a misleading number for token classification — most
tokens in any sentence aren't PII, so a model that predicted "nothing here"
every time would still score ~90%+ on accuracy while being useless. F1 is
the number that actually reflects performance here.

Regex-engine secrets (AWS keys, GitHub tokens, etc.) don't need this kind of
evaluation — they're pattern matches, either the format is right or it
isn't. Aadhaar detection additionally validates the Verhoeff check digit
before flagging a match, which rejects roughly 90% of random 12-digit
strings that would otherwise false-positive against the raw format alone.

## Repository layout

```
.
├── backend/
│   ├── app/
│   │   ├── detectors/       # regex_engine.py, ner_engine.py
│   │   ├── policy/          # decision_engine.py
│   │   ├── audit/           # hash-chained audit log
│   │   ├── models/          # pydantic schemas
│   │   ├── auth.py          # API key + JWT auth
│   │   ├── config.py
│   │   └── main.py          # FastAPI app / routes
│   ├── scripts/train_ner.py # fine-tuning script (run outside this repo — see below)
│   ├── tests/
│   ├── requirements.txt
│   └── Dockerfile
├── extension/
│   ├── manifest.json
│   └── src/                 # content.js, background.js, popup.*
└── website/                 # static landing/download page
```

## Running the backend

```bash
cd backend
python -m venv venv && source venv/bin/activate   # Windows: venv\Scripts\Activate.ps1
pip install -r requirements.txt
pip install https://github.com/explosion/spacy-models/releases/download/en_core_web_sm-3.7.1/en_core_web_sm-3.7.1-py3-none-any.whl

cp .env.example .env    # edit before deploying anywhere that isn't your own machine
uvicorn app.main:app --reload
```

`GET /health` should return `{"status": "ok", "ner_backend": "presidio"}`.
Swagger UI is at `/docs`.

By default this runs on the pretrained Presidio/spaCy NER backend. It works,
but it's a general-purpose small model, not something trained for this task
— expect some false positives/negatives. The fine-tuned DistilBERT model
above fixes most of that. To use it:

1. Run `scripts/train_ner.py` somewhere with a GPU and Hub access (Colab
   works — this repo is deliberately structured so training happens outside
   the deployed service, not inside it).
2. Drop the output directory into `backend/models/shadow-ner-finetuned/`.
3. Set `SAG_NER_BACKEND=transformer` in `.env`. Restart.

## Loading the extension

`chrome://extensions` → enable Developer Mode → Load unpacked → select
`extension/`. Open the popup, confirm the backend URL and API key match
what's in your `.env` (`SAG_API_KEYS`), save.

Interception targets a platform-specific CSS selector first, then falls
back to "last enabled button near the input box" if that selector doesn't
match — which is what keeps it working when ChatGPT/Gemini/Claude ship a
frontend redesign without you needing to update anything. If a submission
still isn't being caught, open the console (F12) before sending anything —
every intercepted attempt logs which method caught it.

## API

| Method | Path | Auth | Purpose |
|---|---|---|---|
| `GET` | `/health` | none | liveness check |
| `POST` | `/api/v1/analyze` | `X-API-Key` header | run detection, get allow/block |
| `POST` | `/api/v1/auth/token` | username/password | JWT for dashboard access |
| `GET` | `/api/v1/audit` | Bearer JWT | query audit history |
| `GET` | `/api/v1/audit/verify` | Bearer JWT | recompute the audit hash chain, confirm nothing's been altered |

## Architecture decisions

**No shared hosted backend.** Every deployment is self-hosted. This means
zero setup friction isn't possible — you have to run the backend yourself —
but it also means nobody's sensitive prompts ever transit infrastructure
that isn't theirs. For a DLP tool specifically, that trade-off isn't close.

**Fail-open, not fail-closed.** If the backend is unreachable, the extension
allows the submission rather than blocking everything (`background.js`,
`analyze()`). This favors not disrupting work over maximum strictness.
Flip it if your threat model wants the opposite.

**SQLite for the audit log.** Fine for one instance. Not safe for concurrent
writes across multiple backend instances — swap for Postgres before running
this at any real scale.

**Detection thresholds.** `SAG_BLOCK_ON_SEVERITY` (default: `medium`)
controls what actually triggers a block versus what just gets logged. Low-
severity findings (a bare first name, a generic code snippet) are recorded
but don't block by default — tune this per your actual risk tolerance.

## Known limitations

- Selector-based DOM interception is inherently fragile against frontend
  redesigns from platforms you don't control. The proximity fallback
  covers most drift; a genuinely new layout may still need a manual
  selector update in `content.js`.
- The NER model's accuracy is bounded by how close real-world prompts are
  to the synthetic dataset's phrasing. It generalizes well in testing, but
  it's not guaranteed on every possible sentence structure.
- The more robust long-term architecture for this category of tool is
  intercepting at the network layer (patching `fetch`/`XHR` in the page's
  main JS world) rather than watching DOM events — trades DOM-selector
  maintenance for having to reverse-engineer each platform's private
  request format, which isn't publicly documented and also changes over
  time. Worth it if selector maintenance becomes the actual bottleneck.
- Aadhaar/PAN detection is format-and-checksum based, not government
  verification — it confirms a string is *structurally* valid, not that
  it's an actually-issued number.

## Dataset note

The fine-tuned model was trained on `ai4privacy/pii-masking-400k`, which is
**not** under a permissive open-source license. Academic/research use with
citation is explicitly permitted; redistribution of the raw dataset or
derivative works requires written permission from AI4Privacy
(licensing@ai4privacy.com). Accordingly:

- The training script (`scripts/train_ner.py`) is included — it's ours.
- The raw dataset is **not** included or redistributed here.
- If you want the trained model weights specifically, retrain them
  yourself using the script above, or contact AI4Privacy about licensing
  terms for redistributing derivative models.

Citation, if you're referencing the dataset:

```
ai4privacy. (2023). PII Masking 400K. HuggingFace Hub. Custom Academic License.
https://huggingface.co/datasets/ai4privacy/pii-masking-400k
```
