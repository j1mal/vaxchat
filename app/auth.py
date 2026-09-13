from datetime import datetime, timedelta, timezone
from typing import Annotated
from uuid import uuid4

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlmodel import Session, select

from app.config import get_settings
from app.db import get_session
from app.models import RevokedToken, User

_hasher = PasswordHasher()
_bearer = HTTPBearer(auto_error=False)


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    try:
        return _hasher.verify(password_hash, password)
    except VerifyMismatchError:
        return False


def create_access_token(user_id: int, username: str) -> str:
    settings = get_settings()
    expire = datetime.now(timezone.utc) + timedelta(minutes=settings.jwt_expire_minutes)
    payload = {
        "sub": username,
        "uid": user_id,
        "jti": uuid4().hex,
        "exp": expire,
    }
    return jwt.encode(payload, settings.secret_key, algorithm=settings.jwt_algorithm)


def decode_token(token: str) -> dict:
    settings = get_settings()
    try:
        return jwt.decode(token, settings.secret_key, algorithms=[settings.jwt_algorithm])
    except jwt.PyJWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
        ) from exc


def is_token_revoked(session: Session, jti: str | None) -> bool:
    if not jti:
        return True
    row = session.get(RevokedToken, jti)
    return row is not None


def revoke_token(session: Session, token: str, user_id: int) -> None:
    payload = decode_token(token)
    jti = payload.get("jti")
    if not jti:
        return
    exp = payload.get("exp")
    if isinstance(exp, (int, float)):
        expires_at = datetime.fromtimestamp(exp, tz=timezone.utc)
    else:
        settings = get_settings()
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=settings.jwt_expire_minutes)
    existing = session.get(RevokedToken, jti)
    if existing:
        return
    session.add(RevokedToken(jti=jti, user_id=user_id, expires_at=expires_at))
    session.commit()


def purge_expired_revocations(session: Session) -> None:
    now = datetime.now(timezone.utc)
    rows = session.exec(select(RevokedToken).where(RevokedToken.expires_at < now)).all()
    for row in rows:
        session.delete(row)
    if rows:
        session.commit()


def get_current_user(
    creds: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
    session: Annotated[Session, Depends(get_session)],
) -> User:
    if creds is None or creds.scheme.lower() != "bearer":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    payload = decode_token(creds.credentials)
    if is_token_revoked(session, payload.get("jti")):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token revoked")
    user_id = payload.get("uid")
    user = session.get(User, user_id) if user_id is not None else None
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    return user


def get_bearer_token(
    creds: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
) -> str:
    if creds is None or creds.scheme.lower() != "bearer":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    return creds.credentials
