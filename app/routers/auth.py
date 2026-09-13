from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlmodel import Session, select

from app.auth import (
    create_access_token,
    get_bearer_token,
    get_current_user,
    hash_password,
    purge_expired_revocations,
    revoke_token,
    verify_password,
)
from app.config import get_settings
from app.db import get_session
from app.models import User
from app.pgp_util import is_pgp_public_key
from app.rate_limit import limiter
from app.schemas import LoginIn, MeOut, MeUpdate, RegisterIn, TokenOut
import re

USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,32}$")

router = APIRouter(prefix="/auth", tags=["auth"])
me_router = APIRouter(tags=["me"])


def normalize_username(raw: str) -> str:
    name = raw.strip()
    if not USERNAME_RE.fullmatch(name):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username must be 3-32 characters: letters, numbers, underscore",
        )
    return name.lower()


@router.post("/register", response_model=TokenOut)
@limiter.limit("5/minute")
def register(request: Request, body: RegisterIn, session: Annotated[Session, Depends(get_session)]):
    username = normalize_username(body.username)
    existing = session.exec(select(User).where(User.username == username)).first()
    if existing:
        # Soften username enumeration: generic conflict text (status still 409).
        detail = "Username taken" if get_settings().allow_username_taken_detail else "Could not create account"
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=detail)
    user = User(username=username, password_hash=hash_password(body.password))
    session.add(user)
    session.commit()
    session.refresh(user)
    return TokenOut(access_token=create_access_token(user.id, user.username), username=user.username)


@router.post("/login", response_model=TokenOut)
@limiter.limit("10/minute")
def login(request: Request, body: LoginIn, session: Annotated[Session, Depends(get_session)]):
    username = body.username.strip().lower()
    user = session.exec(select(User).where(User.username == username)).first()
    if user is None or not verify_password(user.password_hash, body.password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid username or password")
    return TokenOut(access_token=create_access_token(user.id, user.username), username=user.username)


@router.post("/logout")
def logout(
    user: Annotated[User, Depends(get_current_user)],
    token: Annotated[str, Depends(get_bearer_token)],
    session: Annotated[Session, Depends(get_session)],
):
    purge_expired_revocations(session)
    revoke_token(session, token, user.id)
    return {"ok": True}


@me_router.get("/me", response_model=MeOut)
def read_me(user: Annotated[User, Depends(get_current_user)]):
    return MeOut(username=user.username, public_key_armor=user.public_key_armor)


@me_router.put("/me", response_model=MeOut)
def update_me(
    body: MeUpdate,
    user: Annotated[User, Depends(get_current_user)],
    session: Annotated[Session, Depends(get_session)],
):
    settings = get_settings()
    if len(body.public_key_armor) > settings.max_public_key_chars:
        raise HTTPException(status_code=status.HTTP_413_CONTENT_TOO_LARGE, detail="public_key_armor too large")
    if not is_pgp_public_key(body.public_key_armor):
        raise HTTPException(status_code=400, detail="Expected an ASCII-armored PGP public key")
    user.public_key_armor = body.public_key_armor.strip()
    session.add(user)
    session.commit()
    session.refresh(user)
    return MeOut(username=user.username, public_key_armor=user.public_key_armor)
