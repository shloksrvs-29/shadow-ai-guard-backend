"""
Pydantic schemas shared across the API layer, detection engines, and audit log.
"""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Literal, Optional

from pydantic import BaseModel, Field


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class Category(str, Enum):
    # Structured secrets (regex engine)
    API_KEY = "api_key"
    ACCESS_TOKEN = "access_token"
    PRIVATE_KEY = "private_key"
    CREDENTIAL = "credential"
    JWT = "jwt"
    CLOUD_SECRET = "cloud_secret"
    DATABASE_CONN_STRING = "database_conn_string"
    # Unstructured / semantic (NER engine)
    PERSON_NAME = "person_name"
    EMAIL = "email"
    PHONE_NUMBER = "phone_number"
    SSN_OR_NATIONAL_ID = "ssn_or_national_id"
    CREDIT_CARD = "credit_card"
    FINANCIAL_INFO = "financial_info"
    LOCATION = "location"
    ORGANIZATION = "organization"
    IP_ADDRESS = "ip_address"
    SOURCE_CODE = "source_code"
    MEDICAL_INFO = "medical_info"
    # India-specific structured identifiers (regex engine)
    TAX_ID = "tax_id"  # e.g. Indian PAN, and similarly-shaped IDs elsewhere
    OTHER = "other"


class Finding(BaseModel):
    """A single detected sensitive-data span."""
    engine: Literal["regex", "ner"]
    category: Category
    severity: Severity
    matched_text: str = Field(..., description="Redacted/truncated preview, never full raw secret")
    start: int
    end: int
    confidence: float = Field(ge=0.0, le=1.0)
    explanation: str


class AnalyzeRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=50_000)
    platform: Optional[str] = Field(None, description="e.g. chatgpt, gemini, claude")
    user_id: Optional[str] = Field(None, description="Pseudonymous/employee identifier from the extension")
    org_id: Optional[str] = None
    event_type: Literal["input", "paste", "submit"] = "submit"
    url: Optional[str] = None


class Decision(str, Enum):
    ALLOW = "allow"
    BLOCK = "block"


class AnalyzeResponse(BaseModel):
    decision: Decision
    findings: list[Finding]
    highest_severity: Optional[Severity] = None
    message: str
    request_id: str
    latency_ms: float


class AuditEntry(BaseModel):
    id: int
    timestamp: datetime
    org_id: Optional[str]
    user_id: Optional[str]
    platform: Optional[str]
    event_type: str
    decision: Decision
    categories: list[str]
    highest_severity: Optional[str]
    text_preview: str
    entry_hash: str
    prev_hash: str


class AuditQuery(BaseModel):
    org_id: Optional[str] = None
    user_id: Optional[str] = None
    decision: Optional[Decision] = None
    limit: int = 100
    offset: int = 0