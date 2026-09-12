from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlmodel import Session, select

from app.auth import get_current_user
from app.db import get_session
from app.models import Message, User
from app.pgp_util import is_pgp_message
from app.rate_limit import limiter
from app.schemas import MessageIn, MessageOut

router = APIRouter(prefix="/messages", tags=["messages"])


def _username(session: Session, user_id: int) -> str:
    user = session.get(User, user_id)
    if user is None:
        return "?"
    return user.username


@router.post("", response_model=list[MessageOut])
@limiter.limit("30/minute")
def send_message(
    request: Request,
    body: MessageIn,
    user: Annotated[User, Depends(get_current_user)],
    session: Annotated[Session, Depends(get_session)],
):
    if not is_pgp_message(body.ciphertext) or not is_pgp_message(body.self_ciphertext):
        raise HTTPException(status_code=400, detail="Messages must be ASCII-armored PGP MESSAGE blocks")

    recipient_name = body.recipient.strip().lower()
    other = session.exec(select(User).where(User.username == recipient_name)).first()
    if other is None:
        raise HTTPException(status_code=404, detail="Recipient not found")
    if other.id == user.id:
        raise HTTPException(status_code=400, detail="Cannot message yourself")

    outbound = Message(
        sender_id=user.id,
        recipient_id=other.id,
        # Conversation partner from the recipient's point of view is the sender.
        other_user_id=user.id,
        ciphertext=body.ciphertext.strip(),
    )
    self_copy = Message(
        sender_id=user.id,
        recipient_id=user.id,
        other_user_id=other.id,
        ciphertext=body.self_ciphertext.strip(),
    )
    session.add(outbound)
    session.add(self_copy)
    session.commit()
    session.refresh(self_copy)
    # Only the copy encrypted to the sender is returned; they cannot decrypt the recipient copy.
    return [_to_out(session, self_copy, user.id)]


@router.get("", response_model=list[MessageOut])
def list_messages(
    user: Annotated[User, Depends(get_current_user)],
    session: Annotated[Session, Depends(get_session)],
    after_id: Annotated[int, Query()] = 0,
    other: Annotated[str | None, Query()] = None,
):
    stmt = select(Message).where(Message.recipient_id == user.id, Message.id > after_id)
    if other:
        other_user = session.exec(select(User).where(User.username == other.strip().lower())).first()
        if other_user is None:
            return []
        stmt = stmt.where(Message.other_user_id == other_user.id)
    stmt = stmt.order_by(Message.id.asc())
    rows = session.exec(stmt).all()
    return [_to_out(session, row, user.id) for row in rows]


def _to_out(session: Session, row: Message, me_id: int) -> MessageOut:
    return MessageOut(
        id=row.id,
        sender_username=_username(session, row.sender_id),
        other_username=_username(session, row.other_user_id),
        ciphertext=row.ciphertext,
        created_at=row.created_at,
        is_outgoing=row.sender_id == me_id,
    )
