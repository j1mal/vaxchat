from datetime import datetime

from pydantic import BaseModel, Field


class RegisterIn(BaseModel):
    username: str = Field(min_length=3, max_length=32)
    password: str = Field(min_length=8, max_length=256)


class LoginIn(BaseModel):
    username: str
    password: str


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"
    username: str


class MeOut(BaseModel):
    username: str
    public_key_armor: str | None = None


class MeUpdate(BaseModel):
    public_key_armor: str


class ContactIn(BaseModel):
    username: str
    public_key_armor: str = ""


class ContactOut(BaseModel):
    id: int
    username: str
    public_key_armor: str


class RoomCreate(BaseModel):
    name: str = Field(default="", max_length=64)
    member_usernames: list[str] = Field(default_factory=list)
    peer_username: str | None = None


class RoomMemberOut(BaseModel):
    username: str
    public_key_armor: str | None = None


class RoomOut(BaseModel):
    id: int
    name: str
    is_direct: bool
    members: list[RoomMemberOut]


class RoomMessageIn(BaseModel):
    ciphertext: str


class RoomMessageOut(BaseModel):
    id: int
    room_id: int
    sender_username: str
    ciphertext: str
    created_at: datetime
    is_outgoing: bool
