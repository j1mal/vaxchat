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
    created_at: datetime = Field(default_factory=utcnow)


class Message(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    sender_id: int = Field(foreign_key="user.id", index=True)
    recipient_id: int = Field(foreign_key="user.id", index=True)
    other_user_id: int = Field(foreign_key="user.id", index=True)
    ciphertext: str
    created_at: datetime = Field(default_factory=utcnow)
