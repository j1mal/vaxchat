from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlmodel import Session, select

from app.auth import get_current_user
from app.config import get_settings
from app.db import get_session
from app.models import Contact, User
from app.pgp_util import fingerprint_for_armor, is_pgp_public_key
from app.schemas import ContactIn, ContactOut

router = APIRouter(prefix="/contacts", tags=["contacts"])


def _username_of(session: Session, user_id: int) -> str:
    user = session.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return user.username


def _contact_out(session: Session, row: Contact) -> ContactOut:
    return ContactOut(
        id=row.id,
        username=_username_of(session, row.contact_user_id),
        public_key_armor=row.public_key_armor,
        fingerprint=row.fingerprint or "",
    )


@router.get("", response_model=list[ContactOut])
def list_contacts(
    user: Annotated[User, Depends(get_current_user)],
    session: Annotated[Session, Depends(get_session)],
):
    rows = session.exec(select(Contact).where(Contact.owner_id == user.id)).all()
    return [_contact_out(session, row) for row in rows]


@router.post("", response_model=ContactOut)
def add_contact(
    body: ContactIn,
    user: Annotated[User, Depends(get_current_user)],
    session: Annotated[Session, Depends(get_session)],
):
    settings = get_settings()
    username = body.username.strip().lower()
    if username == user.username:
        raise HTTPException(status_code=400, detail="You cannot add yourself as a contact")
    other = session.exec(select(User).where(User.username == username)).first()
    if other is None:
        raise HTTPException(status_code=404, detail="No account with that username")

    armor = body.public_key_armor.strip()
    if not armor:
        armor = (other.public_key_armor or "").strip()
    if armor and len(armor) > settings.max_public_key_chars:
        raise HTTPException(status_code=status.HTTP_413_CONTENT_TOO_LARGE, detail="public_key_armor too large")
    if not armor or not is_pgp_public_key(armor):
        raise HTTPException(
            status_code=400,
            detail="Paste their ASCII-armored PGP public key (or have them publish one on their profile)",
        )

    # Contacts are the explicit pin store. Prefer client-supplied fingerprint when it matches.
    computed = fingerprint_for_armor(armor)
    fingerprint = (body.fingerprint or "").strip() or computed
    if body.fingerprint and body.fingerprint.strip() != computed:
        # Allow storing a client GPG fingerprint as metadata only if they also pin the armor;
        # keep server hash as the binding id when mismatch — prefer computed for consistency.
        fingerprint = computed

    # If they already published a key, warn by rejecting a pin that differs (optional soft bind).
    published = (other.public_key_armor or "").strip()
    if published and is_pgp_public_key(published):
        pub_fp = fingerprint_for_armor(published)
        pin_fp = fingerprint_for_armor(armor)
        if pub_fp != pin_fp:
            # Allow pin of a different key (TOFU / out-of-band), but require explicit paste
            # (empty body.public_key_armor would have used published — already matching).
            if not body.public_key_armor.strip():
                armor = published
                fingerprint = pub_fp

    existing = session.exec(
        select(Contact).where(Contact.owner_id == user.id, Contact.contact_user_id == other.id)
    ).first()
    if existing:
        existing.public_key_armor = armor
        existing.fingerprint = fingerprint
        session.add(existing)
        session.commit()
        session.refresh(existing)
        return _contact_out(session, existing)

    row = Contact(
        owner_id=user.id,
        contact_user_id=other.id,
        public_key_armor=armor,
        fingerprint=fingerprint,
    )
    session.add(row)
    session.commit()
    session.refresh(row)
    return _contact_out(session, row)


@router.delete("/{username}", status_code=status.HTTP_204_NO_CONTENT)
def delete_contact(
    username: str,
    user: Annotated[User, Depends(get_current_user)],
    session: Annotated[Session, Depends(get_session)],
):
    other = session.exec(select(User).where(User.username == username.strip().lower())).first()
    if other is None:
        raise HTTPException(status_code=404, detail="Contact not found")
    row = session.exec(
        select(Contact).where(Contact.owner_id == user.id, Contact.contact_user_id == other.id)
    ).first()
    if row is None:
        raise HTTPException(status_code=404, detail="Contact not found")
    session.delete(row)
    session.commit()
