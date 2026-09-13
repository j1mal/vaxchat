from datetime import datetime, timezone
from typing import Optional

from sqlmodel import Field, SQLModel, UniqueConstraint


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class User(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    username: str = Field(index=True, unique=True, max_length=32)
    password_hash: str
    public_key_armor: Optional[str] = Field(default=None)
    created_at: datetime = Field(default_factory=utcnow)


class Contact(SQLModel, table=True):
    __table_args__ = (UniqueConstraint("owner_id", "contact_user_id"),)

    id: Optional[int] = Field(default=None, primary_key=True)
    owner_id: int = Field(foreign_key="user.id", index=True)
    contact_user_id: int = Field(foreign_key="user.id", index=True)
    public_key_armor: str
    fingerprint: str = Field(default="", index=True, max_length=128)
    created_at: datetime = Field(default_factory=utcnow)


class Room(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str = Field(max_length=64)
    is_direct: bool = Field(default=False, index=True)
    created_at: datetime = Field(default_factory=utcnow)


class RoomMember(SQLModel, table=True):
    __table_args__ = (UniqueConstraint("room_id", "user_id"),)

    id: Optional[int] = Field(default=None, primary_key=True)
    room_id: int = Field(foreign_key="room.id", index=True)
    user_id: int = Field(foreign_key="user.id", index=True)
    joined_at: datetime = Field(default_factory=utcnow)


class RoomInvite(SQLModel, table=True):
    __table_args__ = (UniqueConstraint("room_id", "invitee_id"),)

    id: Optional[int] = Field(default=None, primary_key=True)
    room_id: int = Field(foreign_key="room.id", index=True)
    inviter_id: int = Field(foreign_key="user.id", index=True)
    invitee_id: int = Field(foreign_key="user.id", index=True)
    created_at: datetime = Field(default_factory=utcnow)


class Message(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    room_id: int = Field(foreign_key="room.id", index=True)
    sender_id: int = Field(foreign_key="user.id", index=True)
    ciphertext: str
    created_at: datetime = Field(default_factory=utcnow)


class RevokedToken(SQLModel, table=True):
    """JWT denylist keyed by jti until the token's natural expiry."""

    jti: str = Field(primary_key=True, max_length=64)
    user_id: int = Field(index=True)
    expires_at: datetime = Field(index=True)
    revoked_at: datetime = Field(default_factory=utcnow)
