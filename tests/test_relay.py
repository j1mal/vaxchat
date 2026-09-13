from pathlib import Path
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

from app.config import get_settings
from app.db import init_db, reset_engine
from app.pgp_util import is_pgp_message
from client.crypto import CryptoError, CryptoSession
from client.worker import BackgroundWorker

TESTKEYS = Path(__file__).resolve().parents[1] / "testkeys"


@pytest.fixture
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    db_path = (tmp_path / "test.db").as_posix()
    monkeypatch.setenv("SECRET_KEY", "test-secret-key-for-jwt-please-ignore")
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_path}")
    monkeypatch.setenv("VAXCHAT_DOCS", "false")
    get_settings.cache_clear()
    reset_engine()
    from app.main import create_app

    init_db()
    with TestClient(create_app()) as test_client:
        yield test_client
    get_settings.cache_clear()
    reset_engine()


def _register(client: TestClient, username: str, password: str = "password123") -> str:
    response = client.post("/auth/register", json={"username": username, "password": password})
    assert response.status_code == 200, response.text
    return response.json()["access_token"]


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _keypair(name: str) -> CryptoSession:
    session = CryptoSession()
    session.generate(name, passphrase="test-passphrase")
    return session


def test_health(client: TestClient) -> None:
    assert client.get("/health").json() == {"ok": True}


def test_docs_disabled_by_default(client: TestClient) -> None:
    assert client.get("/docs").status_code == 404
    assert client.get("/openapi.json").status_code == 404


def test_register_login_and_me(client: TestClient) -> None:
    token = _register(client, "alice")
    me = client.get("/me", headers=_auth(token))
    assert me.status_code == 200
    assert me.json()["username"] == "alice"
    assert me.json()["public_key_armor"] is None

    login = client.post("/auth/login", json={"username": "alice", "password": "password123"})
    assert login.status_code == 200
    assert login.json()["username"] == "alice"


def test_duplicate_username_soft_detail(client: TestClient) -> None:
    _register(client, "alice")
    again = client.post("/auth/register", json={"username": "alice", "password": "password123"})
    assert again.status_code == 409
    assert again.json()["detail"] == "Could not create account"


def test_logout_revokes_token(client: TestClient) -> None:
    token = _register(client, "alice")
    assert client.get("/me", headers=_auth(token)).status_code == 200
    assert client.post("/auth/logout", headers=_auth(token)).status_code == 200
    assert client.get("/me", headers=_auth(token)).status_code == 401


def test_rejects_plaintext_message(client: TestClient) -> None:
    alice = _register(client, "alice")
    _register(client, "bob")
    dm = client.post("/rooms", headers=_auth(alice), json={"peer_username": "bob"})
    assert dm.status_code == 200
    room_id = dm.json()["id"]
    response = client.post(
        f"/rooms/{room_id}/messages",
        headers=_auth(alice),
        json={"ciphertext": "hello"},
    )
    assert response.status_code == 400


def test_rejects_fake_armored_junk(client: TestClient) -> None:
    alice = _register(client, "alice")
    _register(client, "bob")
    dm = client.post("/rooms", headers=_auth(alice), json={"peer_username": "bob"})
    room_id = dm.json()["id"]
    junk = "-----BEGIN PGP MESSAGE-----\n\njunk\n-----END PGP MESSAGE-----\n"
    assert is_pgp_message(junk) is False
    response = client.post(
        f"/rooms/{room_id}/messages",
        headers=_auth(alice),
        json={"ciphertext": junk},
    )
    assert response.status_code == 400


def test_oversized_ciphertext_rejected(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MAX_CIPHERTEXT_CHARS", "200")
    get_settings.cache_clear()
    alice = _register(client, "alice")
    _register(client, "bob")
    dm = client.post("/rooms", headers=_auth(alice), json={"peer_username": "bob"})
    room_id = dm.json()["id"]
    # Valid-looking multi-line base64 body, but over the capped size.
    body_lines = ["A" * 64 for _ in range(8)]
    huge = "-----BEGIN PGP MESSAGE-----\n\n" + "\n".join(body_lines) + "\n-----END PGP MESSAGE-----\n"
    assert len(huge) > 200
    response = client.post(
        f"/rooms/{room_id}/messages",
        headers=_auth(alice),
        json={"ciphertext": huge},
    )
    assert response.status_code in (400, 413)
    get_settings.cache_clear()


def test_dm_room_get_or_create(client: TestClient) -> None:
    alice = _register(client, "alice")
    _register(client, "bob")
    first = client.post("/rooms", headers=_auth(alice), json={"peer_username": "bob"})
    assert first.status_code == 200
    second = client.post("/rooms", headers=_auth(alice), json={"peer_username": "bob"})
    assert second.status_code == 200
    assert first.json()["id"] == second.json()["id"]
    assert first.json()["is_direct"] is True
    rooms = client.get("/rooms", headers=_auth(alice))
    assert rooms.status_code == 200
    assert len(rooms.json()) == 1


def test_group_invite_required_not_force_add(client: TestClient) -> None:
    alice = _register(client, "alice")
    bob = _register(client, "bob")
    created = client.post(
        "/rooms",
        headers=_auth(alice),
        json={"name": "crew", "member_usernames": ["bob"]},
    )
    assert created.status_code == 200
    room_id = created.json()["id"]
    members = {m["username"] for m in created.json()["members"]}
    assert members == {"alice"}

    bob_rooms = client.get("/rooms", headers=_auth(bob))
    assert all(r["id"] != room_id for r in bob_rooms.json())

    invites = client.get("/rooms/invites", headers=_auth(bob))
    assert invites.status_code == 200
    assert len(invites.json()) == 1
    invite_id = invites.json()[0]["id"]

    denied = client.get(f"/rooms/{room_id}/messages", headers=_auth(bob))
    assert denied.status_code == 403

    accepted = client.post(f"/rooms/invites/{invite_id}/accept", headers=_auth(bob))
    assert accepted.status_code == 200
    assert {m["username"] for m in accepted.json()["members"]} == {"alice", "bob"}


def test_encrypted_roundtrip(client: TestClient) -> None:
    alice_token = _register(client, "alice")
    bob_token = _register(client, "bob")
    alice = _keypair("alice")
    bob = _keypair("bob")

    assert client.put("/me", headers=_auth(alice_token), json={"public_key_armor": alice.public_key_armor}).status_code == 200
    assert client.put("/me", headers=_auth(bob_token), json={"public_key_armor": bob.public_key_armor}).status_code == 200

    dm = client.post("/rooms", headers=_auth(alice_token), json={"peer_username": "bob"})
    assert dm.status_code == 200
    room_id = dm.json()["id"]
    # Pin bob's published key as a contact (encrypt path must prefer pins).
    assert (
        client.post(
            "/contacts",
            headers=_auth(alice_token),
            json={"username": "bob", "public_key_armor": bob.public_key_armor},
        ).status_code
        == 200
    )
    pubs = [alice.public_key_armor, bob.public_key_armor]

    secret = "meet at dusk"
    ciphertext = alice.encrypt_message(secret, pubs)
    ciphertext2 = alice.encrypt_message(secret, pubs)
    assert "BEGIN PGP MESSAGE" in ciphertext2
    assert secret not in ciphertext

    sent = client.post(
        f"/rooms/{room_id}/messages",
        headers=_auth(alice_token),
        json={"ciphertext": ciphertext},
    )
    assert sent.status_code == 200
    assert "BEGIN PGP MESSAGE" in sent.json()["ciphertext"]

    inbox = client.get(f"/rooms/{room_id}/messages", headers=_auth(bob_token), params={"after_id": 0})
    assert inbox.status_code == 200
    rows = inbox.json()
    assert len(rows) == 1
    assert rows[0]["sender_username"] == "alice"
    plaintext, verified = bob.decrypt(rows[0]["ciphertext"], alice.public_key_armor)
    assert plaintext == secret
    assert verified is True

    alice_view = client.get(f"/rooms/{room_id}/messages", headers=_auth(alice_token), params={"after_id": 0})
    copies = alice_view.json()
    assert len(copies) == 1
    mine, _ = alice.decrypt(copies[0]["ciphertext"], alice.public_key_armor)
    assert mine == secret
    alice.clear()
    bob.clear()


def test_member_pubkeys_prefers_contact_pin() -> None:
    import queue

    out: queue.Queue = queue.Queue()
    worker = BackgroundWorker(out)
    try:
        bob_real = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n" + ("B" * 64 + "\n") * 2 + "-----END PGP PUBLIC KEY BLOCK-----\n"
        bob_evil = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n" + ("E" * 64 + "\n") * 2 + "-----END PGP PUBLIC KEY BLOCK-----\n"
        worker._state.username = "alice"
        worker._state.contacts = [{"username": "bob", "public_key_armor": bob_real}]
        worker._crypto.public_key_armor = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n" + ("A" * 64 + "\n") * 2 + "-----END PGP PUBLIC KEY BLOCK-----\n"

        worker._api = MagicMock()
        worker._api.room_members.return_value = [
            {"username": "alice", "public_key_armor": worker._crypto.public_key_armor},
            {"username": "bob", "public_key_armor": bob_evil},
        ]
        pubs = worker._member_pubkeys(1)
        assert bob_real.strip() in pubs
        assert bob_evil.strip() not in pubs

        worker._state.contacts = []
        with pytest.raises(CryptoError, match="Pin a contact"):
            worker._member_pubkeys(1)
    finally:
        worker.shutdown()


@pytest.mark.skipif(not (TESTKEYS / "jamalpriv.asc").exists(), reason="testkeys not present")
def test_real_testkeys_roundtrip(client: TestClient) -> None:
    jamal_token = _register(client, "jamal")
    jamal1_token = _register(client, "jamal1")

    jamal = CryptoSession()
    jamal1 = CryptoSession()
    jamal.load_private((TESTKEYS / "jamalpriv.asc").read_text(encoding="utf-8"), "12345")
    jamal1.load_private((TESTKEYS / "jamal1priv.asc").read_text(encoding="utf-8"), "12345")
    jamal_pub = (TESTKEYS / "jamalpub.asc").read_text(encoding="utf-8")
    jamal1_pub = (TESTKEYS / "jamal1pub.asc").read_text(encoding="utf-8")

    assert client.put("/me", headers=_auth(jamal_token), json={"public_key_armor": jamal_pub}).status_code == 200
    assert client.put("/me", headers=_auth(jamal1_token), json={"public_key_armor": jamal1_pub}).status_code == 200

    dm = client.post("/rooms", headers=_auth(jamal_token), json={"peer_username": "jamal1"})
    assert dm.status_code == 200
    room_id = dm.json()["id"]

    secret = "tea at dusk with real keys"
    ciphertext = jamal.encrypt_message(secret, [jamal_pub, jamal1_pub])
    jamal.encrypt_message(secret, [jamal_pub, jamal1_pub])

    sent = client.post(
        f"/rooms/{room_id}/messages",
        headers=_auth(jamal_token),
        json={"ciphertext": ciphertext},
    )
    assert sent.status_code == 200, sent.text

    inbox = client.get(f"/rooms/{room_id}/messages", headers=_auth(jamal1_token), params={"after_id": 0})
    assert inbox.status_code == 200
    rows = inbox.json()
    assert len(rows) == 1
    plaintext, verified = jamal1.decrypt(rows[0]["ciphertext"], jamal_pub)
    assert plaintext == secret
    assert verified is True
    jamal.clear()
    jamal1.clear()


def test_server_cannot_be_given_empty_pgp(client: TestClient) -> None:
    token = _register(client, "alice")
    _register(client, "bob")
    response = client.post(
        "/contacts",
        headers=_auth(token),
        json={"username": "bob", "public_key_armor": "not-a-key"},
    )
    assert response.status_code == 400


def test_non_member_cannot_read_room(client: TestClient) -> None:
    alice = _register(client, "alice")
    _register(client, "bob")
    charlie = _register(client, "charlie")
    dm = client.post("/rooms", headers=_auth(alice), json={"peer_username": "bob"})
    room_id = dm.json()["id"]
    denied = client.get(f"/rooms/{room_id}/messages", headers=_auth(charlie))
    assert denied.status_code == 403


def test_websocket_auth_first_message_no_query_token(client: TestClient) -> None:
    from starlette.websockets import WebSocketDisconnect

    alice = _register(client, "alice")
    _register(client, "bob")
    charlie = _register(client, "charlie")
    dm = client.post("/rooms", headers=_auth(alice), json={"peer_username": "bob"})
    room_id = dm.json()["id"]

    with client.websocket_connect(f"/ws/{room_id}") as ws:
        ws.send_json({"type": "auth", "token": charlie})
        with pytest.raises(WebSocketDisconnect):
            ws.receive_text()

    with client.websocket_connect(f"/ws/{room_id}") as ws:
        ws.send_json({"type": "auth", "token": alice})

    # Query string alone must not authenticate; bad first-message auth still fails.
    with client.websocket_connect(f"/ws/{room_id}?token={alice}") as ws:
        ws.send_json({"type": "auth", "token": "not-a-token"})
        with pytest.raises(WebSocketDisconnect):
            ws.receive_text()
