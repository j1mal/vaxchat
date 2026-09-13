from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlmodel import Session, select

from app.auth import get_current_user
from app.config import get_settings
from app.db import get_session
from app.models import Message, Room, RoomInvite, RoomMember, User
from app.pgp_util import is_pgp_message
from app.rate_limit import limiter
from app.schemas import (
    RoomCreate,
    RoomInviteCreate,
    RoomInviteOut,
    RoomMemberOut,
    RoomMessageIn,
    RoomMessageOut,
    RoomOut,
)

router = APIRouter(prefix="/rooms", tags=["rooms"])


def _username(session: Session, user_id: int) -> str:
    user = session.get(User, user_id)
    if user is None:
        return "?"
    return user.username


def _require_membership(session: Session, room_id: int, user_id: int) -> Room:
    room = session.get(Room, room_id)
    if room is None:
        raise HTTPException(status_code=404, detail="Room not found")
    membership = session.exec(
        select(RoomMember).where(RoomMember.room_id == room_id, RoomMember.user_id == user_id)
    ).first()
    if membership is None:
        raise HTTPException(status_code=403, detail="Not a member of this room")
    return room


def _member_rows(session: Session, room_id: int) -> list[RoomMemberOut]:
    members = session.exec(select(RoomMember).where(RoomMember.room_id == room_id)).all()
    out: list[RoomMemberOut] = []
    for member in members:
        user = session.get(User, member.user_id)
        if user is None:
            continue
        out.append(RoomMemberOut(username=user.username, public_key_armor=user.public_key_armor))
    return out


def _room_out(session: Session, room: Room) -> RoomOut:
    return RoomOut(
        id=room.id,
        name=room.name,
        is_direct=room.is_direct,
        members=_member_rows(session, room.id),
    )


def _find_direct_room(session: Session, user_a: int, user_b: int) -> Room | None:
    a_rooms = {
        m.room_id
        for m in session.exec(select(RoomMember).where(RoomMember.user_id == user_a)).all()
    }
    for room_id in a_rooms:
        room = session.get(Room, room_id)
        if room is None or not room.is_direct:
            continue
        members = session.exec(select(RoomMember).where(RoomMember.room_id == room_id)).all()
        ids = {m.user_id for m in members}
        if ids == {user_a, user_b}:
            return room
    return None


def _invite_out(session: Session, invite: RoomInvite) -> RoomInviteOut:
    room = session.get(Room, invite.room_id)
    return RoomInviteOut(
        id=invite.id,
        room_id=invite.room_id,
        room_name=room.name if room else "?",
        inviter_username=_username(session, invite.inviter_id),
        invitee_username=_username(session, invite.invitee_id),
        created_at=invite.created_at,
    )


def _create_invite(session: Session, room: Room, inviter: User, invitee: User) -> RoomInvite | None:
    if room.is_direct:
        raise HTTPException(status_code=400, detail="Cannot invite to a direct message room")
    if invitee.id == inviter.id:
        raise HTTPException(status_code=400, detail="Cannot invite yourself")
    already = session.exec(
        select(RoomMember).where(RoomMember.room_id == room.id, RoomMember.user_id == invitee.id)
    ).first()
    if already:
        return None
    existing = session.exec(
        select(RoomInvite).where(RoomInvite.room_id == room.id, RoomInvite.invitee_id == invitee.id)
    ).first()
    if existing:
        return existing
    invite = RoomInvite(room_id=room.id, inviter_id=inviter.id, invitee_id=invitee.id)
    session.add(invite)
    session.commit()
    session.refresh(invite)
    return invite


@router.get("", response_model=list[RoomOut])
def list_rooms(
    user: Annotated[User, Depends(get_current_user)],
    session: Annotated[Session, Depends(get_session)],
):
    memberships = session.exec(select(RoomMember).where(RoomMember.user_id == user.id)).all()
    rooms: list[RoomOut] = []
    for membership in memberships:
        room = session.get(Room, membership.room_id)
        if room is not None:
            rooms.append(_room_out(session, room))
    rooms.sort(key=lambda r: r.id)
    return rooms


@router.post("", response_model=RoomOut)
def create_room(
    body: RoomCreate,
    user: Annotated[User, Depends(get_current_user)],
    session: Annotated[Session, Depends(get_session)],
):
    settings = get_settings()
    if len(body.member_usernames) > settings.max_room_members:
        raise HTTPException(status_code=status.HTTP_413_CONTENT_TOO_LARGE, detail="too many member_usernames")

    if body.peer_username:
        peer_name = body.peer_username.strip().lower()
        if peer_name == user.username:
            raise HTTPException(status_code=400, detail="Cannot create a DM with yourself")
        peer = session.exec(select(User).where(User.username == peer_name)).first()
        if peer is None:
            raise HTTPException(status_code=404, detail="Peer user not found")
        existing = _find_direct_room(session, user.id, peer.id)
        if existing:
            return _room_out(session, existing)
        room = Room(name=body.name.strip() or peer.username, is_direct=True)
        session.add(room)
        session.commit()
        session.refresh(room)
        session.add(RoomMember(room_id=room.id, user_id=user.id))
        session.add(RoomMember(room_id=room.id, user_id=peer.id))
        session.commit()
        return _room_out(session, room)

    # Groups: creator is the only member. Listed usernames receive invites (consent required).
    invite_names = sorted(
        {
            n.strip().lower()
            for n in body.member_usernames
            if n.strip() and n.strip().lower() != user.username
        }
    )
    invitees: list[User] = []
    for name in invite_names:
        found = session.exec(select(User).where(User.username == name)).first()
        if found is None:
            raise HTTPException(status_code=404, detail=f"User not found: {name}")
        invitees.append(found)

    room_name = body.name.strip() or (
        ", ".join(invite_names) if invite_names else f"{user.username}'s group"
    )
    room = Room(name=room_name[:64], is_direct=False)
    session.add(room)
    session.commit()
    session.refresh(room)
    session.add(RoomMember(room_id=room.id, user_id=user.id))
    session.commit()

    for found in invitees:
        _create_invite(session, room, user, found)

    return _room_out(session, room)


@router.get("/invites", response_model=list[RoomInviteOut])
def list_my_invites(
    user: Annotated[User, Depends(get_current_user)],
    session: Annotated[Session, Depends(get_session)],
):
    rows = session.exec(select(RoomInvite).where(RoomInvite.invitee_id == user.id)).all()
    return [_invite_out(session, row) for row in rows]


@router.post("/{room_id}/invites", response_model=RoomInviteOut)
def invite_member(
    room_id: int,
    body: RoomInviteCreate,
    user: Annotated[User, Depends(get_current_user)],
    session: Annotated[Session, Depends(get_session)],
):
    room = _require_membership(session, room_id, user.id)
    invitee = session.exec(select(User).where(User.username == body.username.strip().lower())).first()
    if invitee is None:
        raise HTTPException(status_code=404, detail="User not found")
    invite = _create_invite(session, room, user, invitee)
    if invite is None:
        raise HTTPException(status_code=400, detail="User is already a member")
    return _invite_out(session, invite)


@router.post("/invites/{invite_id}/accept", response_model=RoomOut)
def accept_invite(
    invite_id: int,
    user: Annotated[User, Depends(get_current_user)],
    session: Annotated[Session, Depends(get_session)],
):
    invite = session.get(RoomInvite, invite_id)
    if invite is None or invite.invitee_id != user.id:
        raise HTTPException(status_code=404, detail="Invite not found")
    room = session.get(Room, invite.room_id)
    if room is None:
        session.delete(invite)
        session.commit()
        raise HTTPException(status_code=404, detail="Room not found")
    existing = session.exec(
        select(RoomMember).where(RoomMember.room_id == room.id, RoomMember.user_id == user.id)
    ).first()
    if not existing:
        session.add(RoomMember(room_id=room.id, user_id=user.id))
    session.delete(invite)
    session.commit()
    return _room_out(session, room)


@router.post("/invites/{invite_id}/decline", status_code=status.HTTP_204_NO_CONTENT)
def decline_invite(
    invite_id: int,
    user: Annotated[User, Depends(get_current_user)],
    session: Annotated[Session, Depends(get_session)],
):
    invite = session.get(RoomInvite, invite_id)
    if invite is None or invite.invitee_id != user.id:
        raise HTTPException(status_code=404, detail="Invite not found")
    session.delete(invite)
    session.commit()


@router.get("/{room_id}", response_model=RoomOut)
def get_room(
    room_id: int,
    user: Annotated[User, Depends(get_current_user)],
    session: Annotated[Session, Depends(get_session)],
):
    room = _require_membership(session, room_id, user.id)
    return _room_out(session, room)


@router.get("/{room_id}/members", response_model=list[RoomMemberOut])
def list_members(
    room_id: int,
    user: Annotated[User, Depends(get_current_user)],
    session: Annotated[Session, Depends(get_session)],
):
    _require_membership(session, room_id, user.id)
    return _member_rows(session, room_id)


@router.post("/{room_id}/messages", response_model=RoomMessageOut)
@limiter.limit("30/minute")
async def send_room_message(
    request: Request,
    room_id: int,
    body: RoomMessageIn,
    user: Annotated[User, Depends(get_current_user)],
    session: Annotated[Session, Depends(get_session)],
):
    _require_membership(session, room_id, user.id)
    settings = get_settings()
    if len(body.ciphertext) > settings.max_ciphertext_chars:
        raise HTTPException(status_code=status.HTTP_413_CONTENT_TOO_LARGE, detail="ciphertext too large")
    if not is_pgp_message(body.ciphertext):
        raise HTTPException(status_code=400, detail="Messages must be ASCII-armored PGP MESSAGE blocks")
    row = Message(
        room_id=room_id,
        sender_id=user.id,
        ciphertext=body.ciphertext.strip(),
    )
    session.add(row)
    session.commit()
    session.refresh(row)
    out = RoomMessageOut(
        id=row.id,
        room_id=row.room_id,
        sender_username=user.username,
        ciphertext=row.ciphertext,
        created_at=row.created_at,
        is_outgoing=True,
    )
    from app.ws import manager

    await manager.broadcast(
        room_id,
        {
            "id": out.id,
            "room_id": out.room_id,
            "sender_username": out.sender_username,
            "ciphertext": out.ciphertext,
            "created_at": out.created_at.isoformat(),
            "is_outgoing": False,
        },
    )
    return out


@router.get("/{room_id}/messages", response_model=list[RoomMessageOut])
def list_room_messages(
    room_id: int,
    user: Annotated[User, Depends(get_current_user)],
    session: Annotated[Session, Depends(get_session)],
    after_id: Annotated[int, Query()] = 0,
):
    _require_membership(session, room_id, user.id)
    rows = session.exec(
        select(Message)
        .where(Message.room_id == room_id, Message.id > after_id)
        .order_by(Message.id.asc())
    ).all()
    return [
        RoomMessageOut(
            id=row.id,
            room_id=row.room_id,
            sender_username=_username(session, row.sender_id),
            ciphertext=row.ciphertext,
            created_at=row.created_at,
            is_outgoing=row.sender_id == user.id,
        )
        for row in rows
    ]
