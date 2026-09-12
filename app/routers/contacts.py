from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlmodel import Session, select

from app.auth import get_current_user
from app.db import get_session
from app.models import Contact, User
from app.pgp_util import is_pgp_public_key
from app.schemas import ContactIn, ContactOut

router = APIRouter(prefix="/contacts", tags=["contacts"])


def _username_of(session: Session, user_id: int) -> str:
    user = session.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return user.username


@router.get("", response_model=list[ContactOut])
def list_contacts(
    user: Annotated[User, Depends(get_current_user)],
    session: Annotated[Session, Depends(get_session)],
):
    rows = session.exec(select(Contact).where(Contact.owner_id == user.id)).all()
    return [
        ContactOut(id=row.id, username=_username_of(session, row.contact_user_id), public_key_armor=row.public_key_armor)
        for row in rows
    ]


@router.post("", response_model=ContactOut)
def add_contact(
    body: ContactIn,
    user: Annotated[User, Depends(get_current_user)],
    session: Annotated[Session, Depends(get_session)],
):
    username = body.username.strip().lower()
    if username == user.username:
        raise HTTPException(status_code=400, detail="You cannot add yourself as a contact")
    other = session.exec(select(User).where(User.username == username)).first()
    if other is None:
        raise HTTPException(status_code=404, detail="No account with that username")

    armor = body.public_key_armor.strip()
    if not armor:
        armor = (other.public_key_armor or "").strip()
    if not armor or not is_pgp_public_key(armor):
        raise HTTPException(
            status_code=400,
            detail="Paste their ASCII-armored PGP public key (or have them publish one on their profile)",
        )

    existing = session.exec(
        select(Contact).where(Contact.owner_id == user.id, Contact.contact_user_id == other.id)
    ).first()
    if existing:
        existing.public_key_armor = armor
        session.add(existing)
        session.commit()
        session.refresh(existing)
        return ContactOut(id=existing.id, username=other.username, public_key_armor=existing.public_key_armor)

    row = Contact(owner_id=user.id, contact_user_id=other.id, public_key_armor=armor)
    session.add(row)
    session.commit()
    session.refresh(row)
    return ContactOut(id=row.id, username=other.username, public_key_armor=row.public_key_armor)


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
