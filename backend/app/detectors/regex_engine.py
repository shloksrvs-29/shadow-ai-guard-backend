"""
Fast, deterministic pattern-matching engine for structured secrets:
API keys, cloud credentials, private keys, tokens, connection strings, etc.
Also covers India-specific structured identifiers (Aadhaar, PAN, Indian
mobile numbers) -- see the bottom of the pattern library.

This engine is intentionally dependency-free and sub-millisecond per call,
so it can run synchronously in the hot path before the (slower) NER engine.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, Optional

from app.models.schemas import Category, Finding, Severity


@dataclass(frozen=True)
class Pattern:
    name: str
    category: Category
    severity: Severity
    regex: re.Pattern
    explanation: str
    # Optional second-pass validator run on the raw matched text (e.g. a
    # checksum). Lets a pattern be broad enough to catch real formatting
    # variance while still rejecting most structurally-similar-but-invalid
    # matches -- see verhoeff_checksum_valid() below for why this matters
    # specifically for Aadhaar numbers.
    validator: Optional[Callable[[str], bool]] = None


# --------------------------------------------------------------------------
# Verhoeff checksum algorithm -- used to validate Aadhaar numbers.
#
# India's Aadhaar number is a 12-digit ID whose final digit is a Verhoeff
# check digit computed over the preceding 11 digits (this is also what
# UIDAI's own systems use for basic format validation). A naive "any
# 12-digit number" regex would false-positive constantly on invoice
# numbers, phone-number-adjacent digit strings, timestamps, etc. Checking
# the Verhoeff digit rejects the vast majority of those (roughly 9 out of
# 10 random 12-digit strings fail the checksum by chance), which is a much
# stronger signal than format alone -- the same reasoning that makes credit
# card Luhn-checking standard practice.
# --------------------------------------------------------------------------
_VERHOEFF_D_TABLE = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
    [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
    [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
]
_VERHOEFF_P_TABLE = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
    [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
    [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
]


def verhoeff_checksum_valid(digits: str) -> bool:
    """True if `digits` (a string of decimal digits, e.g. 12 for Aadhaar)
    passes the Verhoeff checksum -- i.e. is *structurally* a valid Aadhaar
    number. Does not confirm the number is actually issued/real, only that
    it's not a random/malformed digit string."""
    if not digits.isdigit():
        return False
    c = 0
    for i, digit_char in enumerate(reversed(digits)):
        c = _VERHOEFF_D_TABLE[c][_VERHOEFF_P_TABLE[i % 8][int(digit_char)]]
    return c == 0


def _aadhaar_validator(matched_text: str) -> bool:
    digits_only = re.sub(r"[\s-]", "", matched_text)
    return len(digits_only) == 12 and verhoeff_checksum_valid(digits_only)


# --------------------------------------------------------------------------
# Pattern library. Sources: vendor documentation for token formats (AWS,
# GitHub, Google, Slack, Stripe, OpenAI/Anthropic-style keys), common
# generic secret/credential shapes, and (for the India-specific block)
# UIDAI's published Aadhaar format spec + India's Income Tax Department's
# published PAN format spec. Extend this list as new platforms/locales are
# added -- it's the cheapest way to raise recall for obvious leaks.
# --------------------------------------------------------------------------
_PATTERNS: list[Pattern] = [
    Pattern(
        "aws_access_key_id", Category.CLOUD_SECRET, Severity.HIGH,
        re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
        "AWS Access Key ID pattern detected.",
    ),
    Pattern(
        "aws_secret_key", Category.CLOUD_SECRET, Severity.HIGH,
        re.compile(r"(?i)aws(.{0,20})?(secret|private)(.{0,20})?['\"]?\s*[:=]\s*['\"]?[A-Za-z0-9/+=]{40}['\"]?"),
        "AWS Secret Access Key pattern detected.",
    ),
    Pattern(
        "gcp_api_key", Category.API_KEY, Severity.HIGH,
        re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
        "Google Cloud API key pattern detected.",
    ),
    Pattern(
        "github_token", Category.ACCESS_TOKEN, Severity.HIGH,
        re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b"),
        "GitHub personal access / OAuth token detected.",
    ),
    Pattern(
        "slack_token", Category.ACCESS_TOKEN, Severity.HIGH,
        re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,72}\b"),
        "Slack API token detected.",
    ),
    Pattern(
        "stripe_key", Category.API_KEY, Severity.HIGH,
        re.compile(r"\b(sk|rk)_(live|test)_[0-9A-Za-z]{16,64}\b"),
        "Stripe secret/restricted API key detected.",
    ),
    Pattern(
        "generic_llm_or_service_key", Category.API_KEY, Severity.HIGH,
        re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"),
        "Generic vendor-style secret key (sk-...) detected -- commonly used by LLM/API providers.",
    ),
    Pattern(
        "jwt", Category.JWT, Severity.MEDIUM,
        re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"),
        "JSON Web Token (JWT) detected.",
    ),
    Pattern(
        "private_key_block", Category.PRIVATE_KEY, Severity.HIGH,
        re.compile(r"-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
        "PEM private key block detected.",
    ),
    Pattern(
        "db_connection_string", Category.DATABASE_CONN_STRING, Severity.HIGH,
        re.compile(r"(?i)\b(postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis):\/\/[^\s'\"]+:[^\s'\"@]+@[^\s'\"]+"),
        "Database connection string with embedded credentials detected.",
    ),
    Pattern(
        "generic_password_assignment", Category.CREDENTIAL, Severity.MEDIUM,
        re.compile(r"(?i)\b(password|passwd|pwd|secret)\s*[:=]\s*['\"]?[^\s'\"]{6,}['\"]?"),
        "Inline password/secret assignment detected.",
    ),
    Pattern(
        "bearer_token", Category.ACCESS_TOKEN, Severity.MEDIUM,
        re.compile(r"(?i)\bAuthorization:\s*Bearer\s+[A-Za-z0-9\-._~+/]{20,}=*"),
        "Bearer token in an Authorization header detected.",
    ),

    # --- India-specific structured identifiers ------------------------------
    Pattern(
        "india_aadhaar_number", Category.SSN_OR_NATIONAL_ID, Severity.HIGH,
        # 12 digits, first digit 2-9 (Aadhaar never starts with 0 or 1),
        # optionally grouped as 4-4-4 with spaces or hyphens.
        re.compile(r"\b[2-9]\d{3}[\s-]?\d{4}[\s-]?\d{4}\b"),
        "Indian Aadhaar number detected (12-digit national ID, passed Verhoeff checksum validation).",
        validator=_aadhaar_validator,
    ),
    Pattern(
        "india_pan_number", Category.TAX_ID, Severity.HIGH,
        # PAN format: 5 letters, 4 digits, 1 letter (e.g. ABCDE1234F).
        # 4th letter indicates holder type (P=individual, C=company, etc)
        # -- not validated here, format match alone is a strong signal
        # since this exact shape is very unlikely to occur by accident.
        re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b"),
        "Indian PAN (Permanent Account Number / tax ID) pattern detected.",
    ),
    Pattern(
        "india_phone_number", Category.PHONE_NUMBER, Severity.MEDIUM,
        # Indian mobile numbers: 10 digits starting 6-9, optionally
        # prefixed with +91 / 0. Negative lookaround prevents matching
        # inside a longer digit run (e.g. a 16-digit card number).
        re.compile(r"(?<!\d)(?:\+91[\s-]?|0)?[6-9]\d{9}(?!\d)"),
        "Indian mobile phone number pattern detected.",
    ),
]


class RegexEngine:
    """Stateless, thread-safe. Instantiate once and reuse."""

    def __init__(self, patterns: list[Pattern] | None = None) -> None:
        self._patterns = patterns or _PATTERNS

    def scan(self, text: str) -> list[Finding]:
        findings: list[Finding] = []
        for pattern in self._patterns:
            for match in pattern.regex.finditer(text):
                matched_text = match.group(0)
                if pattern.validator and not pattern.validator(matched_text):
                    continue
                findings.append(
                    Finding(
                        engine="regex",
                        category=pattern.category,
                        severity=pattern.severity,
                        matched_text=_redact(matched_text),
                        start=match.start(),
                        end=match.end(),
                        confidence=0.98,  # deterministic patterns get high fixed confidence
                        explanation=pattern.explanation,
                    )
                )
        return findings


def _redact(secret: str, keep: int = 4) -> str:
    """Never surface the raw secret in logs/UI -- show a masked preview only."""
    if len(secret) <= keep * 2:
        return "*" * len(secret)
    return f"{secret[:keep]}{'*' * (len(secret) - keep * 2)}{secret[-keep:]}"