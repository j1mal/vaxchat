from __future__ import annotations

import json
import queue
import threading
import time
from dataclasses import dataclass, field
from typing import Any
from websockets.sync.client import connect as ws_connect

from client.api import ChatApi
from client.crypto import CryptoError, CryptoSession


@dataclass
class DisplayMessage:
    id: int
    room_id: int
    who: str
    text: str
    mark: str = ""
    is_outgoing: bool = False


@dataclass
class WorkerState:
    rooms: list[dict] = field(default_factory=list)
    contacts: list[dict] = field(default_factory=list)
    messages_by_room: dict[int, list[DisplayMessage]] = field(default_factory=dict)
    seen_ids: set[int] = field(default_factory=set)
    after_id_by_room: dict[int, int] = field(default_factory=dict)
    username: str | None = None
    key_fingerprint: str | None = None
    public_key_armor: str | None = None
    unlocked: bool = False


class BackgroundWorker:
    """Owns network + GPG. Talks to the UI only via queues."""

    def __init__(self, out_queue: queue.Queue) -> None:
        self._out = out_queue
        self._cmds: queue.Queue = queue.Queue()
        self._api = ChatApi()
        self._crypto = CryptoSession()
        self._state = WorkerState()
        self._raw_cache: dict[int, dict] = {}
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._ws_stop: dict[int, threading.Event] = {}
        self._ws_threads: dict[int, threading.Thread] = {}
        self._thread = threading.Thread(target=self._run, name="vaxchat-worker", daemon=True)
        self._thread.start()

    def submit(self, kind: str, **payload: Any) -> None:
        self._cmds.put((kind, payload))

    def shutdown(self) -> None:
        self._stop.set()
        self._stop_all_ws()
        self.submit("shutdown")
        self._thread.join(timeout=3.0)
        try:
            self._api.close()
        except Exception:
            pass
        self._crypto.clear()

    def _emit(self, kind: str, **payload: Any) -> None:
        self._out.put((kind, payload))

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                kind, payload = self._cmds.get(timeout=0.25)
            except queue.Empty:
                continue
            if kind == "shutdown":
                break
            try:
                self._handle(kind, payload)
            except Exception as exc:
                self._emit("error", message=str(exc))

    def _handle(self, kind: str, payload: dict[str, Any]) -> None:
        if kind == "set_server":
            self._api.base_url = str(payload["url"]).rstrip("/")
        elif kind == "login":
            self._api.base_url = str(payload.get("server") or self._api.base_url).rstrip("/")
            self._api.login(payload["username"], payload["password"])
            self._state.username = self._api.username
            self._emit("auth_ok", username=self._api.username)
            self._refresh_contacts()
            self._refresh_rooms()
            self._refresh_invites()
        elif kind == "register":
            self._api.base_url = str(payload.get("server") or self._api.base_url).rstrip("/")
            self._api.register(payload["username"], payload["password"])
            self._state.username = self._api.username
            self._emit("auth_ok", username=self._api.username)
            self._refresh_contacts()
            self._refresh_rooms()
            self._refresh_invites()
        elif kind == "logout":
            self._stop_all_ws()
            self._api.logout()
            self._crypto.clear()
            self._state = WorkerState()
            self._raw_cache = {}
            self._emit("logged_out")
        elif kind == "refresh_rooms":
            self._refresh_rooms()
        elif kind == "create_dm":
            peer = payload["peer_username"]
            armor = payload.get("public_key_armor") or ""
            room = self._api.create_dm(peer)
            if armor.strip():
                self._api.add_contact(peer, armor)
            elif not any(
                (m.get("username") == peer and m.get("public_key_armor"))
                for m in (room.get("members") or [])
            ):
                # Still create a contact row if they published a key on the room.
                pub = next(
                    (m.get("public_key_armor") for m in (room.get("members") or []) if m.get("username") == peer),
                    "",
                )
                if pub:
                    self._api.add_contact(peer, pub)
            self._refresh_contacts()
            self._refresh_rooms()
            self._emit("room_opened", room_id=room["id"])
        elif kind == "create_group":
            room = self._api.create_group(payload.get("name") or "", payload.get("member_usernames") or [])
            self._refresh_rooms()
            self._refresh_invites()
            self._emit("room_opened", room_id=room["id"])
            self._emit(
                "status",
                text="Group created. Listed users were invited (they must accept before joining).",
            )
        elif kind == "refresh_contacts":
            self._refresh_contacts()
        elif kind == "refresh_invites":
            self._refresh_invites()
        elif kind == "accept_invite":
            room = self._api.accept_invite(int(payload["invite_id"]))
            self._refresh_invites()
            self._refresh_rooms()
            self._emit("room_opened", room_id=room["id"])
        elif kind == "decline_invite":
            self._api.decline_invite(int(payload["invite_id"]))
            self._refresh_invites()
        elif kind == "add_contact":
            self._api.add_contact(payload["username"], payload.get("public_key_armor") or "")
            self._refresh_contacts()
            self._emit("contact_added")
        elif kind == "load_key":
            with self._lock:
                self._crypto.load_private(payload["armor"], payload.get("passphrase") or "")
                self._state.unlocked = True
                self._state.key_fingerprint = self._crypto.fingerprint
                self._state.public_key_armor = self._crypto.public_key_armor
            if self._crypto.public_key_armor:
                try:
                    self._api.publish_public_key(self._crypto.public_key_armor)
                    self._emit("status", text="Public key published.")
                except Exception as exc:
                    self._emit("status", text=f"Key loaded but publish failed: {exc}")
            with self._lock:
                self._redecrypt_all()
            self._emit(
                "key_loaded",
                fingerprint=self._crypto.fingerprint,
                public_key_armor=self._crypto.public_key_armor,
            )
            self._emit_messages()
        elif kind == "generate_key":
            with self._lock:
                armor = self._crypto.generate(payload.get("name") or "vaxchat", payload.get("passphrase") or "")
                self._state.unlocked = True
                self._state.key_fingerprint = self._crypto.fingerprint
                self._state.public_key_armor = self._crypto.public_key_armor
            if self._crypto.public_key_armor:
                try:
                    self._api.publish_public_key(self._crypto.public_key_armor)
                except Exception as exc:
                    self._emit("status", text=f"Key generated but publish failed: {exc}")
            self._emit(
                "key_generated",
                private_armor=armor,
                public_key_armor=self._crypto.public_key_armor,
                fingerprint=self._crypto.fingerprint,
            )
            with self._lock:
                self._redecrypt_all()
            self._emit_messages()
        elif kind == "send":
            self._do_send(int(payload["room_id"]), payload["text"])
        elif kind == "select_room":
            room_id = int(payload["room_id"])
            self._ensure_ws(room_id)
            self._catch_up(room_id)
        else:
            self._emit("error", message=f"Unknown command: {kind}")

    def _refresh_rooms(self) -> None:
        rooms = self._api.list_rooms()
        self._state.rooms = rooms
        self._emit("rooms", rooms=rooms)
        wanted = {int(r["id"]) for r in rooms}
        for room_id in list(self._ws_threads):
            if room_id not in wanted:
                self._stop_ws(room_id)
        for room_id in wanted:
            self._ensure_ws(room_id)
            self._catch_up(room_id)

    def _refresh_contacts(self) -> None:
        try:
            rows = self._api.list_contacts()
        except Exception as exc:
            self._emit("status", text=f"Contacts refresh failed: {exc}")
            return
        self._state.contacts = rows
        self._emit("contacts", contacts=rows)

    def _refresh_invites(self) -> None:
        try:
            rows = self._api.list_invites()
        except Exception as exc:
            self._emit("status", text=f"Invites refresh failed: {exc}")
            return
        self._emit("invites", invites=rows)

    def _contact_pubkey(self, username: str) -> str | None:
        for contact in self._state.contacts:
            if contact.get("username") == username:
                armor = (contact.get("public_key_armor") or "").strip()
                return armor or None
        return None

    def _stop_all_ws(self) -> None:
        for room_id in list(self._ws_threads):
            self._stop_ws(room_id)

    def _stop_ws(self, room_id: int) -> None:
        stop = self._ws_stop.get(room_id)
        if stop:
            stop.set()
        thread = self._ws_threads.pop(room_id, None)
        self._ws_stop.pop(room_id, None)
        if thread and thread.is_alive():
            thread.join(timeout=1.5)

    def _ensure_ws(self, room_id: int) -> None:
        existing = self._ws_threads.get(room_id)
        if existing and existing.is_alive():
            return
        stop = threading.Event()
        self._ws_stop[room_id] = stop
        thread = threading.Thread(
            target=self._ws_loop,
            args=(room_id, stop),
            name=f"vaxchat-ws-{room_id}",
            daemon=True,
        )
        self._ws_threads[room_id] = thread
        thread.start()

    def _ws_loop(self, room_id: int, stop: threading.Event) -> None:
        delay = 1.0
        while not self._stop.is_set() and not stop.is_set():
            token = self._api.token
            if not token:
                time.sleep(0.5)
                continue
            url = f"{self._api.ws_base()}/ws/{room_id}"
            try:
                with ws_connect(url, open_timeout=10, close_timeout=2) as socket:
                    socket.send(json.dumps({"type": "auth", "token": token}))
                    delay = 1.0
                    self._emit("status", text=f"WS connected · room {room_id}")
                    self._catch_up(room_id)
                    while not self._stop.is_set() and not stop.is_set():
                        try:
                            raw = socket.recv(timeout=1.0)
                        except TimeoutError:
                            continue
                        except Exception:
                            break
                        try:
                            payload = json.loads(raw)
                        except Exception:
                            continue
                        self._handle_incoming(room_id, payload)
            except Exception as exc:
                if self._stop.is_set() or stop.is_set():
                    break
                self._emit("status", text=f"WS reconnecting room {room_id} in {delay:.0f}s ({exc})")
                # Catch-up after drop / before retry so offline gap is filled.
                try:
                    self._catch_up(room_id)
                except Exception:
                    pass
                stop.wait(delay)
                delay = min(delay * 2, 30.0)

    def _catch_up(self, room_id: int) -> None:
        if not self._api.token:
            return
        after_id = self._state.after_id_by_room.get(room_id, 0)
        try:
            rows = self._api.list_room_messages(room_id, after_id=after_id)
        except Exception as exc:
            self._emit("status", text=f"Catch-up failed room {room_id}: {exc}")
            return
        with self._lock:
            added = self._ingest_raw(rows, room_id)
        if added:
            self._emit_messages()

    def _handle_incoming(self, room_id: int, payload: dict) -> None:
        row = {
            "id": payload.get("id"),
            "room_id": room_id,
            "sender_username": payload.get("sender_username"),
            "ciphertext": payload.get("ciphertext"),
            "is_outgoing": payload.get("sender_username") == self._state.username,
        }
        with self._lock:
            added = self._ingest_raw([row], room_id)
        if added:
            self._emit_messages()

    def _member_pubkeys(self, room_id: int) -> list[str]:
        """Contact-pinned keys win. Server member pubs are not used without a pin."""
        members = self._api.room_members(room_id)
        pubs: list[str] = []
        seen: set[str] = set()
        missing: list[str] = []
        for member in members:
            username = member.get("username") or ""
            if username == self._state.username:
                armor = (self._crypto.public_key_armor or "").strip()
            else:
                armor = (self._contact_pubkey(username) or "").strip()
                if not armor:
                    missing.append(username)
                    continue
            if armor and armor not in seen:
                seen.add(armor)
                pubs.append(armor)
        if missing:
            raise CryptoError(
                "Pin a contact public key for: " + ", ".join(missing) + " (server keys are not trusted until pinned)."
            )
        return pubs

    def _sender_pubkey_for_verify(self, room_id: int, sender_username: str | None) -> str | None:
        if not sender_username:
            return None
        pinned = self._contact_pubkey(sender_username)
        if pinned:
            return pinned
        for room in self._state.rooms:
            if int(room["id"]) != room_id:
                continue
            for member in room.get("members") or []:
                if member.get("username") == sender_username:
                    return member.get("public_key_armor")
        return None

    def _display_from_row(self, row: dict, room_id: int) -> DisplayMessage:
        who = "you" if row.get("is_outgoing") else row.get("sender_username") or "?"
        if not self._crypto.unlocked:
            return DisplayMessage(
                id=row["id"],
                room_id=room_id,
                who=who,
                text="[locked — load your private key]",
                is_outgoing=bool(row.get("is_outgoing")),
            )
        sender_pub = None
        if not row.get("is_outgoing"):
            sender_pub = self._sender_pubkey_for_verify(room_id, row.get("sender_username"))
        try:
            with self._lock:
                text, verified = self._crypto.decrypt(row["ciphertext"], sender_pub)
            mark = ""
            if verified is True:
                mark = " ✓"
            elif verified is False:
                mark = " (signature not verified)"
            return DisplayMessage(
                id=row["id"],
                room_id=room_id,
                who=who,
                text=text,
                mark=mark,
                is_outgoing=bool(row.get("is_outgoing")),
            )
        except CryptoError:
            return DisplayMessage(
                id=row["id"],
                room_id=room_id,
                who=who,
                text="[could not decrypt]",
                is_outgoing=bool(row.get("is_outgoing")),
            )

    def _ingest_raw(self, rows: list[dict], room_id: int) -> list[DisplayMessage]:
        added: list[DisplayMessage] = []
        for row in rows:
            msg_id = row.get("id")
            if msg_id is None or msg_id in self._state.seen_ids:
                continue
            self._state.seen_ids.add(msg_id)
            display = self._display_from_row(row, room_id)
            self._raw_cache[msg_id] = {**row, "room_id": room_id}
            self._state.messages_by_room.setdefault(room_id, []).append(display)
            self._state.after_id_by_room[room_id] = max(self._state.after_id_by_room.get(room_id, 0), int(msg_id))
            added.append(display)
        return added

    def _redecrypt_all(self) -> None:
        rebuilt: dict[int, list[DisplayMessage]] = {}
        for msg_id in sorted(self._raw_cache):
            row = self._raw_cache[msg_id]
            room_id = int(row["room_id"])
            display = self._display_from_row(row, room_id)
            rebuilt.setdefault(room_id, []).append(display)
        self._state.messages_by_room = rebuilt

    def _emit_messages(self) -> None:
        payload = {
            str(room_id): [
                {
                    "id": m.id,
                    "who": m.who,
                    "text": m.text,
                    "mark": m.mark,
                    "is_outgoing": m.is_outgoing,
                }
                for m in msgs
            ]
            for room_id, msgs in self._state.messages_by_room.items()
        }
        self._emit(
            "messages",
            messages_by_room=payload,
            unlocked=self._state.unlocked,
        )

    def _do_send(self, room_id: int, text: str) -> None:
        if not self._crypto.unlocked:
            self._emit("send_done", ok=False, error="Load your private key before sending.")
            return
        try:
            pubs = self._member_pubkeys(room_id)
            if self._crypto.public_key_armor and self._crypto.public_key_armor not in pubs:
                pubs.append(self._crypto.public_key_armor)
            if not pubs:
                self._emit("send_done", ok=False, error="No member public keys available.")
                return
            with self._lock:
                ciphertext = self._crypto.encrypt_message(text, pubs)
            row = self._api.send_room_message(room_id, ciphertext)
            row["is_outgoing"] = True
            with self._lock:
                self._ingest_raw([row], room_id)
            self._emit_messages()
            self._emit("send_done", ok=True)
            self._emit("status", text="Sent.")
        except Exception as exc:
            self._emit("send_done", ok=False, error=str(exc))
