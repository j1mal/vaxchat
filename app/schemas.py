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


class MessageIn(BaseModel):
    recipient: str
    ciphertext: str
    self_ciphertext: str


class MessageOut(BaseModel):
    id: int
    sender_username: str
    other_username: str
    ciphertext: str
    created_at: datetime
    is_outgoing: bool
