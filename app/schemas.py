from datetime import datetime

from pydantic import BaseModel, Field, field_validator

from app.config import get_settings


def _max_pubkey() -> int:
    return get_settings().max_public_key_chars


def _max_members() -> int:
    return get_settings().max_room_members


class RegisterIn(BaseModel):
    username: str = Field(min_length=3, max_length=32)
    password: str = Field(min_length=8, max_length=256)


class LoginIn(BaseModel):
    username: str = Field(max_length=32)
    password: str = Field(max_length=256)


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"
    username: str


class MeOut(BaseModel):
    username: str
    public_key_armor: str | None = None


class MeUpdate(BaseModel):
    public_key_armor: str = Field(max_length=65_536)

    @field_validator("public_key_armor")
    @classmethod
    def _len_pubkey(cls, value: str) -> str:
        if len(value) > _max_pubkey():
            raise ValueError("public_key_armor too large")
        return value


class ContactIn(BaseModel):
    username: str = Field(max_length=32)
    public_key_armor: str = Field(default="", max_length=65_536)
    fingerprint: str = Field(default="", max_length=128)

    @field_validator("public_key_armor")
    @classmethod
    def _len_contact_pubkey(cls, value: str) -> str:
        if value and len(value) > _max_pubkey():
            raise ValueError("public_key_armor too large")
        return value


class ContactOut(BaseModel):
    id: int
    username: str
    public_key_armor: str
    fingerprint: str = ""


class RoomCreate(BaseModel):
    name: str = Field(default="", max_length=64)
    # Groups: creator-only at create time. Use invites to add others.
    # Kept for API compatibility but ignored for unilateral enrollment.
    member_usernames: list[str] = Field(default_factory=list, max_length=64)
    peer_username: str | None = Field(default=None, max_length=32)

    @field_validator("member_usernames")
    @classmethod
    def _cap_members(cls, value: list[str]) -> list[str]:
        if len(value) > _max_members():
            raise ValueError("too many member_usernames")
        return value


class RoomInviteCreate(BaseModel):
    username: str = Field(max_length=32)


class RoomInviteOut(BaseModel):
    id: int
    room_id: int
    room_name: str
    inviter_username: str
    invitee_username: str
    created_at: datetime


class RoomMemberOut(BaseModel):
    username: str
    public_key_armor: str | None = None


class RoomOut(BaseModel):
    id: int
    name: str
    is_direct: bool
    members: list[RoomMemberOut]


class RoomMessageIn(BaseModel):
    ciphertext: str = Field(max_length=512_000)


class RoomMessageOut(BaseModel):
    id: int
    room_id: int
    sender_username: str
    ciphertext: str
    created_at: datetime
    is_outgoing: bool
