"""
Shadow AI Guard -- backend gateway.

Endpoints:
  POST /api/v1/analyze          Extension calls this on every input/paste/submit.
  GET  /api/v1/audit            Admin dashboard queries flagged/blocked history.
  GET  /api/v1/audit/verify     Confirms the audit log hash chain is intact.
  POST /api/v1/auth/token       Username/password -> JWT (admin dashboard login).
  GET  /health                  Liveness/readiness probe.
"""
from __future__ import annotations

import time
import uuid

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm

from app.auth import authenticate_user, create_access_token, get_current_user, require_api_key
from app.config import get_settings
from app.detectors.ner_engine import NerEngine
from app.detectors.regex_engine import RegexEngine
from app.audit.audit_log import get_audit_log
from app.models.schemas import AnalyzeRequest, AnalyzeResponse, AuditEntry
from app.policy.decision_engine import decide

settings = get_settings()

app = FastAPI(
    title=settings.app_name,
    description="Real-time DLP gateway for public LLM usage (Shadow AI Guard).",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

_regex_engine = RegexEngine()


@app.get("/health", tags=["ops"])
async def health() -> dict:
    return {"status": "ok", "app": settings.app_name, "ner_backend": settings.ner_backend}


@app.post("/api/v1/analyze", response_model=AnalyzeResponse, tags=["detection"])
async def analyze(payload: AnalyzeRequest, _api_key: str = Depends(require_api_key)) -> AnalyzeResponse:
    start = time.perf_counter()
    request_id = str(uuid.uuid4())

    try:
        regex_findings = _regex_engine.scan(payload.text)
        ner_findings = NerEngine.get().scan(payload.text)
    except Exception as exc:  # pragma: no cover - defensive
        raise HTTPException(status_code=500, detail=f"Detection engine error: {exc}") from exc

    findings = regex_findings + ner_findings
    latency_ms = (time.perf_counter() - start) * 1000

    response = decide(findings, request_id=request_id, latency_ms=latency_ms)

    get_audit_log().record(
        org_id=payload.org_id,
        user_id=payload.user_id,
        platform=payload.platform,
        event_type=payload.event_type,
        decision=response.decision,
        categories=sorted({f.category.value for f in findings}),
        highest_severity=response.highest_severity.value if response.highest_severity else None,
        raw_text=payload.text,
    )

    return response


@app.get("/api/v1/audit", response_model=list[AuditEntry], tags=["audit"])
async def get_audit(
    org_id: str | None = None,
    user_id: str | None = None,
    limit: int = 100,
    offset: int = 0,
    _user=Depends(get_current_user),
) -> list[AuditEntry]:
    return get_audit_log().query(org_id=org_id, user_id=user_id, limit=limit, offset=offset)


@app.get("/api/v1/audit/verify", tags=["audit"])
async def verify_audit(_user=Depends(get_current_user)) -> dict:
    is_valid, bad_row = get_audit_log().verify_integrity()
    return {"valid": is_valid, "first_tampered_row_id": bad_row}


@app.post("/api/v1/auth/token", tags=["auth"])
async def login(form_data: OAuth2PasswordRequestForm = Depends()) -> dict:
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect username or password")
    token = create_access_token(user)
    return {"access_token": token, "token_type": "bearer"}
