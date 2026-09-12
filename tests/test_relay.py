from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.config import get_settings
from app.db import init_db, reset_engine
from client.crypto import CryptoSession

TESTKEYS = Path(__file__).resolve().parents[1] / "testkeys"


@pytest.fixture
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    db_path = (tmp_path / "test.db").as_posix()
    monkeypatch.setenv("SECRET_KEY", "test-secret-key-for-jwt-please-ignore")
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_path}")
    get_settings.cache_clear()
    reset_engine()
    from app.main import app

    init_db()
    with TestClient(app) as test_client:
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


def test_register_login_and_me(client: TestClient) -> None:
    token = _register(client, "alice")
    me = client.get("/me", headers=_auth(token))
    assert me.status_code == 200
    assert me.json()["username"] == "alice"
    assert me.json()["public_key_armor"] is None

    login = client.post("/auth/login", json={"username": "alice", "password": "password123"})
    assert login.status_code == 200
    assert login.json()["username"] == "alice"


def test_duplicate_username(client: TestClient) -> None:
    _register(client, "alice")
    again = client.post("/auth/register", json={"username": "alice", "password": "password123"})
    assert again.status_code == 409


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
    members = client.get(f"/rooms/{room_id}/members", headers=_auth(alice_token))
    assert members.status_code == 200
    pubs = [m["public_key_armor"] for m in members.json() if m.get("public_key_armor")]
    assert len(pubs) == 2

    secret = "meet at dusk"
    ciphertext = alice.encrypt_message(secret, pubs)
    # Re-encrypt to same members must not fail on keyring conflicts.
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
    # Second encrypt to same peers — must not raise on duplicate import.
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


def test_websocket_rejects_non_member(client: TestClient) -> None:
    from starlette.websockets import WebSocketDisconnect

    alice = _register(client, "alice")
    _register(client, "bob")
    charlie = _register(client, "charlie")
    dm = client.post("/rooms", headers=_auth(alice), json={"peer_username": "bob"})
    room_id = dm.json()["id"]
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect(f"/ws/{room_id}?token={charlie}"):
            pass
