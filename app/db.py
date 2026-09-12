from collections.abc import Generator

from sqlalchemy import inspect
from sqlmodel import Session, SQLModel, create_engine

from app.config import get_settings

_engine = None


def get_engine():
    global _engine
    if _engine is None:
        settings = get_settings()
        connect_args = {}
        if settings.database_url.startswith("sqlite"):
            connect_args = {"check_same_thread": False}
        _engine = create_engine(settings.database_url, connect_args=connect_args)
    return _engine


def reset_engine() -> None:
    global _engine
    if _engine is not None:
        _engine.dispose()
    _engine = None


def _message_columns(engine) -> set[str]:
    insp = inspect(engine)
    if not insp.has_table("message"):
        return set()
    return {col["name"] for col in insp.get_columns("message")}


def init_db() -> None:
    from app import models  # noqa: F401

    engine = get_engine()
    cols = _message_columns(engine)
    # create_all does not alter existing tables; wipe outdated message schema.
    if cols and "room_id" not in cols:
        SQLModel.metadata.drop_all(engine)
    SQLModel.metadata.create_all(engine)


def get_session() -> Generator[Session, None, None]:
    with Session(get_engine()) as session:
        yield session
