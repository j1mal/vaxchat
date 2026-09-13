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


def _table_columns(engine, table: str) -> set[str]:
    insp = inspect(engine)
    if not insp.has_table(table):
        return set()
    return {col["name"] for col in insp.get_columns(table)}


def _schema_outdated(engine) -> bool:
    msg_cols = _table_columns(engine, "message")
    if msg_cols and "room_id" not in msg_cols:
        return True
    contact_cols = _table_columns(engine, "contact")
    if contact_cols and "fingerprint" not in contact_cols:
        return True
    insp = inspect(engine)
    if insp.has_table("message") and not insp.has_table("revokedtoken"):
        # New table is fine via create_all; no wipe needed.
        pass
    if insp.has_table("message") and not insp.has_table("roominvite"):
        pass
    return False


def init_db() -> None:
    from app import models  # noqa: F401

    engine = get_engine()
    if _schema_outdated(engine):
        SQLModel.metadata.drop_all(engine)
    SQLModel.metadata.create_all(engine)


def get_session() -> Generator[Session, None, None]:
    with Session(get_engine()) as session:
        yield session
