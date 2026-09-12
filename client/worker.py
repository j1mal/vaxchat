from __future__ import annotations

import queue
import threading
import time
from dataclasses import dataclass, field
from typing import Any

from client.api import ChatApi
from client.crypto import CryptoError, CryptoSession

POLL_SECONDS = 3.0


@dataclass
class DisplayMessage:
    id: int
    peer: str
    who: str
    text: str
    mark: str = ""
    is_outgoing: bool = False


@dataclass
class WorkerState:
    contacts: list[dict] = field(default_factory=list)
    messages_by_peer: dict[str, list[DisplayMessage]] = field(default_factory=dict)
    seen_ids: set[int] = field(default_factory=set)
    after_id: int = 0
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
        self._polling = False
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, name="vaxchat-worker", daemon=True)
        self._thread.start()

    def submit(self, kind: str, **payload: Any) -> None:
        self._cmds.put((kind, payload))

    def shutdown(self) -> None:
        self._stop.set()
        self.submit("shutdown")
        self._thread.join(timeout=2.0)
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
                kind, payload = self._cmds.get(timeout=POLL_SECONDS if self._polling else 0.25)
            except queue.Empty:
                if self._polling:
                    self._do_poll()
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
            self._polling = True
            self._emit("auth_ok", username=self._api.username)
            self._refresh_contacts()
            self._do_poll()
        elif kind == "register":
            self._api.base_url = str(payload.get("server") or self._api.base_url).rstrip("/")
            self._api.register(payload["username"], payload["password"])
            self._state.username = self._api.username
            self._polling = True
            self._emit("auth_ok", username=self._api.username)
            self._refresh_contacts()
            self._do_poll()
        elif kind == "logout":
            self._polling = False
            self._api.logout()
            self._crypto.clear()
            self._state = WorkerState()
            self._raw_cache = {}
            self._emit("logged_out")
        elif kind == "refresh_contacts":
            self._refresh_contacts()
        elif kind == "add_contact":
            self._api.add_contact(payload["username"], payload.get("public_key_armor") or "")
            self._refresh_contacts()
            self._emit("contact_added")
        elif kind == "delete_contact":
            self._api.delete_contact(payload["username"])
            self._refresh_contacts()
            self._emit("contact_removed", username=payload["username"])
        elif kind == "load_key":
            self._crypto.load_private(payload["armor"], payload.get("passphrase") or "")
            self._state.unlocked = True
            self._state.key_fingerprint = self._crypto.fingerprint
            self._state.public_key_armor = self._crypto.public_key_armor
            if self._crypto.public_key_armor:
                try:
                    self._api.publish_public_key(self._crypto.public_key_armor)
                    published = True
                except Exception as exc:
                    published = False
                    self._emit("status", text=f"Key loaded but publish failed: {exc}")
                else:
                    if published:
                        self._emit("status", text="Public key published.")
            self._redecrypt_all()
            self._emit(
                "key_loaded",
                fingerprint=self._crypto.fingerprint,
                public_key_armor=self._crypto.public_key_armor,
            )
            self._emit_messages()
        elif kind == "generate_key":
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
            self._redecrypt_all()
            self._emit_messages()
        elif kind == "send":
            self._do_send(payload["peer"], payload["text"])
        elif kind == "poll_now":
            self._do_poll()
        else:
            self._emit("error", message=f"Unknown command: {kind}")

    def _contact_pubkey(self, username: str) -> str | None:
        for contact in self._state.contacts:
            if contact["username"] == username:
                return contact.get("public_key_armor")
        return None

    def _refresh_contacts(self) -> None:
        rows = self._api.list_contacts()
        self._state.contacts = rows
        self._emit("contacts", contacts=rows)

    def _peer_for(self, row: dict) -> str:
        if row.get("is_outgoing"):
            return row["other_username"]
        return row["sender_username"]

    def _display_from_row(self, row: dict) -> DisplayMessage:
        peer = self._peer_for(row)
        who = "you" if row.get("is_outgoing") else row["sender_username"]
        if not self._crypto.unlocked:
            return DisplayMessage(
                id=row["id"],
                peer=peer,
                who=who,
                text="[locked — load your private key]",
                is_outgoing=bool(row.get("is_outgoing")),
            )
        sender_pub = None if row.get("is_outgoing") else self._contact_pubkey(row["sender_username"])
        try:
            text, verified = self._crypto.decrypt(row["ciphertext"], sender_pub)
            mark = ""
            if verified is True:
                mark = " ✓"
            elif verified is False:
                mark = " (signature not verified)"
            return DisplayMessage(
                id=row["id"],
                peer=peer,
                who=who,
                text=text,
                mark=mark,
                is_outgoing=bool(row.get("is_outgoing")),
            )
        except CryptoError:
            return DisplayMessage(
                id=row["id"],
                peer=peer,
                who=who,
                text="[could not decrypt]",
                is_outgoing=bool(row.get("is_outgoing")),
            )

    def _ingest_raw(self, rows: list[dict]) -> list[DisplayMessage]:
        added: list[DisplayMessage] = []
        for row in rows:
            msg_id = row["id"]
            if msg_id in self._state.seen_ids:
                continue
            self._state.seen_ids.add(msg_id)
            display = self._display_from_row(row)
            self._raw_cache[msg_id] = row
            self._state.messages_by_peer.setdefault(display.peer, []).append(display)
            self._state.after_id = max(self._state.after_id, msg_id)
            added.append(display)
        return added

    def _redecrypt_all(self) -> None:
        rebuilt: dict[str, list[DisplayMessage]] = {}
        for msg_id in sorted(self._raw_cache):
            row = self._raw_cache[msg_id]
            display = self._display_from_row(row)
            rebuilt.setdefault(display.peer, []).append(display)
        self._state.messages_by_peer = rebuilt

    def _emit_messages(self) -> None:
        payload = {
            peer: [
                {
                    "id": m.id,
                    "who": m.who,
                    "text": m.text,
                    "mark": m.mark,
                    "is_outgoing": m.is_outgoing,
                }
                for m in msgs
            ]
            for peer, msgs in self._state.messages_by_peer.items()
        }
        self._emit(
            "messages",
            messages_by_peer=payload,
            after_id=self._state.after_id,
            unlocked=self._state.unlocked,
        )

    def _do_poll(self) -> None:
        if not self._api.token:
            return
        try:
            rows = self._api.list_messages(after_id=self._state.after_id)
        except Exception as exc:
            self._emit("status", text=f"Poll failed: {exc}")
            return
        added = self._ingest_raw(rows)
        if added:
            self._emit_messages()
        self._emit(
            "status",
            text=f"Polling {self._api.base_url} · last id {self._state.after_id}",
        )

    def _do_send(self, peer: str, text: str) -> None:
        if not self._crypto.unlocked:
            self._emit("send_done", ok=False, error="Load your private key before sending.")
            return
        their_pub = self._contact_pubkey(peer)
        my_pub = self._crypto.public_key_armor
        if not their_pub or not my_pub:
            self._emit("send_done", ok=False, error="Missing a public key for this conversation.")
            return
        try:
            to_them = self._crypto.encrypt_for(text, their_pub)
            to_me = self._crypto.encrypt_for(text, my_pub)
            rows = self._api.send_message(peer, to_them, to_me)
            self._ingest_raw(rows)
            self._emit_messages()
            self._emit("send_done", ok=True)
            self._emit("status", text="Sent.")
        except Exception as exc:
            self._emit("send_done", ok=False, error=str(exc))
