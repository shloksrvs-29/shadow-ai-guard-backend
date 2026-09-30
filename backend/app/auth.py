"""
Authentication for two client types:

1. Browser extension  -> lightweight API key in the `X-API-Key` header.
   Simple to provision per-org/per-device; fine for a mini-project and a
   reasonable v1 for enterprise pilots (rotate keys via config/DB).

2. Admin dashboard     -> JWT bearer tokens (username/password -> token),
   scaffolded here so the audit dashboard can have real login rather than
   a shared secret. Swap `_FAKE_USER_DB` for a real user store later.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import Depends, Header, HTTPException, status
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel

from app.config import get_settings

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


# --- API key auth (extension clients) ---------------------------------

async def require_api_key(x_api_key: str = Header(..., alias="X-API-Key")) -> str:
    settings = get_settings()
    if x_api_key not in settings.api_keys:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API key")
    return x_api_key


# --- JWT auth (admin dashboard) ----------------------------------------

class TokenData(BaseModel):
    username: str
    org_id: Optional[str] = None
    role: str = "viewer"  # viewer | admin


# Placeholder user store -- replace with a real DB-backed user table.
# Password below is the bcrypt hash of "changeme" -- rotate immediately.
_FAKE_USER_DB = {
    "admin": {
        "username": "admin",
        "org_id": "default-org",
        "role": "admin",
        "hashed_password": pwd_context.hash("changeme"),
    }
}


def authenticate_user(username: str, password: str) -> Optional[TokenData]:
    user = _FAKE_USER_DB.get(username)
    if not user or not pwd_context.verify(password, user["hashed_password"]):
        return None
    return TokenData(username=user["username"], org_id=user["org_id"], role=user["role"])


def create_access_token(data: TokenData) -> str:
    settings = get_settings()
    expire = datetime.now(timezone.utc) + timedelta(minutes=settings.jwt_expiry_minutes)
    payload = data.model_dump()
    payload["exp"] = expire
    return jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)


async def get_current_user(authorization: str = Header(...)) -> TokenData:
    settings = get_settings()
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing bearer token")
    token = authorization.removeprefix("Bearer ")
    try:
        payload = jwt.decode(token, settings.jwt_secret, algorithms=[settings.jwt_algorithm])
        return TokenData(username=payload["username"], org_id=payload.get("org_id"), role=payload.get("role", "viewer"))
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")


async def require_admin(user: TokenData = Depends(get_current_user)) -> TokenData:
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin role required")
    return user
