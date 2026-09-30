"""
Central configuration for Shadow AI Guard backend.
All values can be overridden via environment variables (see .env.example).
"""
from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_prefix="SAG_", extra="ignore")

    # --- General ---
    app_name: str = "Shadow AI Guard"
    environment: str = "development"  # development | staging | production

    # --- Auth ---
    # Simple shared-secret API keys for browser extensions / service clients.
    # In production, replace with a proper key-management/DB-backed store.
    api_keys: list[str] = ["dev-local-key-change-me"]
    jwt_secret: str = "CHANGE_ME_super_secret_key_for_jwt_signing"
    jwt_algorithm: str = "HS256"
    jwt_expiry_minutes: int = 60

    # --- Detection engine ---
    # NER backend: "presidio" (spaCy-based, works today) or "transformer"
    # (your fine-tuned model, see scripts/train_ner.py). The interface is
    # identical so you can flip this without touching calling code.
    ner_backend: str = "presidio"
    ner_model_path: str = "en_core_web_sm"          # spaCy model name
    transformer_model_path: str = "./models/shadow-ner-finetuned"  # local dir after fine-tuning
    ner_score_threshold: float = 0.5

    # Policy thresholds
    block_on_severity: str = "medium"  # low | medium | high  -> minimum severity that triggers a block

    # --- Audit log ---
    audit_db_path: str = "./data/audit_log.db"

    # --- CORS: browser extensions call this from extension origins ---
    allowed_origins: list[str] = ["*"]  # tighten in production to chrome-extension://<id>


@lru_cache
def get_settings() -> Settings:
    return Settings()
