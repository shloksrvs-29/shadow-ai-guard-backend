"""
Semantic / NER-based detection engine for unstructured sensitive content:
PII (names, emails, phone numbers, national IDs), financial data, locations,
organizations, and (heuristically, for now) proprietary source code.

Design: `NerEngine` is a thin façade over a `NerBackend`. Two backends are
provided:

  - PresidioBackend      -> works out of the box today (spaCy under the hood).
  - TransformerBackend   -> loads YOUR fine-tuned model (see
                             scripts/train_ner.py) once you've trained it on
                             a real-world PII dataset outside this sandbox.

Swap backends purely via config (app.config.Settings.ner_backend) -- no
calling code changes required. This satisfies objective 2.7 (vendor-neutral
extensibility) for the detection layer itself.
"""
from __future__ import annotations

import re
from abc import ABC, abstractmethod

from app.config import get_settings
from app.models.schemas import Category, Finding, Severity

# Map Presidio's built-in entity types -> our taxonomy + default severity.
_PRESIDIO_ENTITY_MAP: dict[str, tuple[Category, Severity]] = {
    "PERSON": (Category.PERSON_NAME, Severity.LOW),
    "EMAIL_ADDRESS": (Category.EMAIL, Severity.MEDIUM),
    "PHONE_NUMBER": (Category.PHONE_NUMBER, Severity.MEDIUM),
    "US_SSN": (Category.SSN_OR_NATIONAL_ID, Severity.HIGH),
    "UK_NHS": (Category.MEDICAL_INFO, Severity.HIGH),
    "CREDIT_CARD": (Category.CREDIT_CARD, Severity.HIGH),
    "IBAN_CODE": (Category.FINANCIAL_INFO, Severity.HIGH),
    "US_BANK_NUMBER": (Category.FINANCIAL_INFO, Severity.HIGH),
    "LOCATION": (Category.LOCATION, Severity.LOW),
    "ORGANIZATION": (Category.ORGANIZATION, Severity.LOW),
    "IP_ADDRESS": (Category.IP_ADDRESS, Severity.MEDIUM),
    "NRP": (Category.OTHER, Severity.LOW),
    "MEDICAL_LICENSE": (Category.MEDICAL_INFO, Severity.HIGH),
}

# Map ai4privacy's label taxonomy (used by scripts/train_ner.py) -> our
# taxonomy + default severity. The fine-tuned model's predicted entity_group
# labels come from this dataset's schema, which differs from Presidio's --
# both maps are consulted so TransformerBackend works regardless of which
# labelled dataset you trained against. Extend this if you fine-tune on a
# dataset with a different label set.
_AI4PRIVACY_ENTITY_MAP: dict[str, tuple[Category, Severity]] = {
    "USERNAME": (Category.OTHER, Severity.LOW),
    "EMAIL": (Category.EMAIL, Severity.MEDIUM),
    "TELEPHONENUM": (Category.PHONE_NUMBER, Severity.MEDIUM),
    "DATEOFBIRTH": (Category.OTHER, Severity.MEDIUM),
    "STREET": (Category.LOCATION, Severity.LOW),
    "CITY": (Category.LOCATION, Severity.LOW),
    "ZIPCODE": (Category.LOCATION, Severity.LOW),
    "CREDITCARDNUMBER": (Category.CREDIT_CARD, Severity.HIGH),
    "CREDITCARDCVV": (Category.CREDIT_CARD, Severity.HIGH),
    "CREDITCARDISSUER": (Category.FINANCIAL_INFO, Severity.LOW),
    "ACCOUNTNUMBER": (Category.FINANCIAL_INFO, Severity.HIGH),
    "ACCOUNTNAME": (Category.FINANCIAL_INFO, Severity.LOW),
    "IBAN": (Category.FINANCIAL_INFO, Severity.HIGH),
    "BIC": (Category.FINANCIAL_INFO, Severity.MEDIUM),
    "SSN": (Category.SSN_OR_NATIONAL_ID, Severity.HIGH),
    "PASSWORD": (Category.CREDENTIAL, Severity.HIGH),
    "IP": (Category.IP_ADDRESS, Severity.MEDIUM),
    "IPV4": (Category.IP_ADDRESS, Severity.MEDIUM),
    "IPV6": (Category.IP_ADDRESS, Severity.MEDIUM),
    "MAC": (Category.OTHER, Severity.LOW),
    "GIVENNAME": (Category.PERSON_NAME, Severity.LOW),
    "SURNAME": (Category.PERSON_NAME, Severity.LOW),
    "FULLNAME": (Category.PERSON_NAME, Severity.LOW),
    "JOBTITLE": (Category.OTHER, Severity.LOW),
    "COMPANYNAME": (Category.ORGANIZATION, Severity.LOW),
    "HEALTHINSURANCE": (Category.MEDICAL_INFO, Severity.HIGH),
    "MEDICALLICENSE": (Category.MEDICAL_INFO, Severity.HIGH),
}

# Merged lookup used by TransformerBackend so it works whichever taxonomy
# the fine-tuned model was trained on.
_ENTITY_LABEL_MAP: dict[str, tuple[Category, Severity]] = {
    **_PRESIDIO_ENTITY_MAP,
    **_AI4PRIVACY_ENTITY_MAP,
}

# Heuristic source-code detector: used until the fine-tuned transformer
# (trained on labelled proprietary-code-vs-prose data) is deployed. Looks
# for common code shapes across popular languages rather than one syntax.
_CODE_HINT_PATTERNS = [
    re.compile(r"\bdef\s+\w+\s*\("),
    re.compile(r"\bfunction\s+\w+\s*\("),
    re.compile(r"\bclass\s+\w+[\s\{\(:]"),
    re.compile(r"[;{}]\s*$", re.MULTILINE),
    re.compile(r"\bimport\s+[\w.]+"),
    re.compile(r"\b(SELECT|INSERT INTO|UPDATE)\b.*\bFROM\b", re.IGNORECASE),
    re.compile(r"=>|::|->"),
]


class NerBackend(ABC):
    @abstractmethod
    def detect(self, text: str) -> list[Finding]:
        ...


class PresidioBackend(NerBackend):
    """Wraps Microsoft Presidio's AnalyzerEngine (spaCy-backed)."""

    def __init__(self, spacy_model: str, score_threshold: float) -> None:
        # Imported lazily so the module can be imported without the heavy
        # spaCy/Presidio dependency chain loaded until actually needed.
        from presidio_analyzer import AnalyzerEngine
        from presidio_analyzer.nlp_engine import NlpEngineProvider

        provider = NlpEngineProvider(
            nlp_configuration={
                "nlp_engine_name": "spacy",
                "models": [{"lang_code": "en", "model_name": spacy_model}],
            }
        )
        self._analyzer = AnalyzerEngine(nlp_engine=provider.create_engine())
        self._threshold = score_threshold

    def detect(self, text: str) -> list[Finding]:
        results = self._analyzer.analyze(text=text, language="en")
        findings: list[Finding] = []
        for r in results:
            if r.score < self._threshold:
                continue
            category, severity = _PRESIDIO_ENTITY_MAP.get(r.entity_type, (Category.OTHER, Severity.LOW))
            findings.append(
                Finding(
                    engine="ner",
                    category=category,
                    severity=severity,
                    matched_text=_redact(text[r.start:r.end]),
                    start=r.start,
                    end=r.end,
                    confidence=round(float(r.score), 3),
                    explanation=f"Presidio/spaCy recognizer flagged entity type '{r.entity_type}'.",
                )
            )
        findings.extend(_detect_source_code(text))
        return findings


class TransformerBackend(NerBackend):
    """
    Loads a fine-tuned token-classification model produced by
    scripts/train_ner.py. Point app.config.Settings.transformer_model_path
    at the saved model directory and set ner_backend="transformer".

    Not active by default in this sandbox (no internet access to a base
    checkpoint here) -- but the interface is ready to drop in the moment
    you've trained and copied the model directory into the deployment.
    """

    def __init__(self, model_path: str, score_threshold: float) -> None:
        from transformers import AutoModelForTokenClassification, AutoTokenizer, pipeline

        tokenizer = AutoTokenizer.from_pretrained(model_path)
        model = AutoModelForTokenClassification.from_pretrained(model_path)
        self._pipe = pipeline(
            "token-classification",
            model=model,
            tokenizer=tokenizer,
            aggregation_strategy="simple",
        )
        self._threshold = score_threshold

    def detect(self, text: str) -> list[Finding]:
        results = self._pipe(text)
        findings: list[Finding] = []
        for r in results:
            if r["score"] < self._threshold:
                continue
            label = r["entity_group"].upper()
            category, severity = _ENTITY_LABEL_MAP.get(label, (Category.OTHER, Severity.LOW))
            findings.append(
                Finding(
                    engine="ner",
                    category=category,
                    severity=severity,
                    matched_text=_redact(r["word"]),
                    start=int(r["start"]),
                    end=int(r["end"]),
                    confidence=round(float(r["score"]), 3),
                    explanation=f"Fine-tuned transformer flagged entity type '{label}'.",
                )
            )
        findings.extend(_detect_source_code(text))
        return findings


def _detect_source_code(text: str) -> list[Finding]:
    hits = sum(1 for p in _CODE_HINT_PATTERNS if p.search(text))
    if hits >= 2:
        return [
            Finding(
                engine="ner",
                category=Category.SOURCE_CODE,
                severity=Severity.MEDIUM,
                matched_text=_redact(text[:60]),
                start=0,
                end=min(len(text), 60),
                confidence=min(0.5 + 0.1 * hits, 0.9),
                explanation="Heuristic source-code shape detected (multiple code-like tokens/structures).",
            )
        ]
    return []


def _redact(value: str, keep: int = 2) -> str:
    value = value.strip()
    if len(value) <= keep * 2:
        return "*" * len(value)
    return f"{value[:keep]}{'*' * (len(value) - keep * 2)}{value[-keep:]}"


class NerEngine:
    """Public façade used by the rest of the app. Picks the configured backend."""

    _instance: "NerEngine | None" = None

    def __init__(self) -> None:
        settings = get_settings()
        if settings.ner_backend == "transformer":
            self._backend: NerBackend = TransformerBackend(
                settings.transformer_model_path, settings.ner_score_threshold
            )
        else:
            self._backend = PresidioBackend(settings.ner_model_path, settings.ner_score_threshold)

    @classmethod
    def get(cls) -> "NerEngine":
        """Lazy singleton -- loading spaCy/transformer models is expensive,
        so we only pay that cost once per process."""
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def scan(self, text: str) -> list[Finding]:
        return self._backend.detect(text)