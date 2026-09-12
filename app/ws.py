from __future__ import annotations

import asyncio
from collections import defaultdict

from fastapi import APIRouter, Depends, Query, WebSocket, WebSocketDisconnect
from sqlmodel import Session, select

from app.auth import decode_token
from app.db import get_engine
from app.models import RoomMember, User

router = APIRouter(tags=["websocket"])


class ConnectionManager:
    def __init__(self) -> None:
        self._rooms: dict[int, set[WebSocket]] = defaultdict(set)
        self._lock = asyncio.Lock()

    async def connect(self, room_id: int, websocket: WebSocket) -> None:
        await websocket.accept()
        async with self._lock:
            self._rooms[room_id].add(websocket)

    async def disconnect(self, room_id: int, websocket: WebSocket) -> None:
        async with self._lock:
            sockets = self._rooms.get(room_id)
            if not sockets:
                return
            sockets.discard(websocket)
            if not sockets:
                self._rooms.pop(room_id, None)

    async def broadcast(self, room_id: int, payload: dict) -> None:
        async with self._lock:
            sockets = list(self._rooms.get(room_id, set()))
        stale: list[WebSocket] = []
        for socket in sockets:
            try:
                await socket.send_json(payload)
            except Exception:
                stale.append(socket)
        for socket in stale:
            await self.disconnect(room_id, socket)


manager = ConnectionManager()


def user_from_token(token: str) -> User | None:
    try:
        payload = decode_token(token)
    except Exception:
        return None
    user_id = payload.get("uid")
    if user_id is None:
        return None
    with Session(get_engine()) as session:
        return session.get(User, user_id)


def is_room_member(room_id: int, user_id: int) -> bool:
    with Session(get_engine()) as session:
        row = session.exec(
            select(RoomMember).where(RoomMember.room_id == room_id, RoomMember.user_id == user_id)
        ).first()
        return row is not None


@router.websocket("/ws/{room_id}")
async def room_websocket(
    websocket: WebSocket,
    room_id: int,
    token: str = Query(...),
):
    user = user_from_token(token)
    if user is None or not is_room_member(room_id, user.id):
        await websocket.close(code=4403)
        return
    await manager.connect(room_id, websocket)
    try:
        while True:
            # Clients send via HTTP POST; keep the socket open for server pushes.
            await websocket.receive_text()
    except WebSocketDisconnect:
        await manager.disconnect(room_id, websocket)
    except Exception:
        await manager.disconnect(room_id, websocket)
