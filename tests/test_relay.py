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
    session.generate(name)
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
    response = client.post(
        "/messages",
        headers=_auth(alice),
        json={"recipient": "bob", "ciphertext": "hello", "self_ciphertext": "hello"},
    )
    assert response.status_code == 400


def test_encrypted_roundtrip(client: TestClient) -> None:
    alice_token = _register(client, "alice")
    bob_token = _register(client, "bob")
    alice = _keypair("alice")
    bob = _keypair("bob")

    pub_a = client.put("/me", headers=_auth(alice_token), json={"public_key_armor": alice.public_key_armor})
    pub_b = client.put("/me", headers=_auth(bob_token), json={"public_key_armor": bob.public_key_armor})
    assert pub_a.status_code == 200
    assert pub_b.status_code == 200

    add = client.post(
        "/contacts",
        headers=_auth(alice_token),
        json={"username": "bob", "public_key_armor": bob.public_key_armor},
    )
    assert add.status_code == 200
    client.post(
        "/contacts",
        headers=_auth(bob_token),
        json={"username": "alice", "public_key_armor": alice.public_key_armor},
    )

    secret = "meet at dusk"
    to_bob = alice.encrypt_for(secret, bob.public_key_armor or "")
    to_self = alice.encrypt_for(secret, alice.public_key_armor or "")
    assert "BEGIN PGP MESSAGE" in to_bob
    assert secret not in to_bob

    sent = client.post(
        "/messages",
        headers=_auth(alice_token),
        json={"recipient": "bob", "ciphertext": to_bob, "self_ciphertext": to_self},
    )
    assert sent.status_code == 200
    bodies = sent.json()
    assert all("BEGIN PGP MESSAGE" in row["ciphertext"] for row in bodies)

    inbox = client.get("/messages", headers=_auth(bob_token), params={"after_id": 0})
    assert inbox.status_code == 200
    rows = inbox.json()
    assert len(rows) == 1
    assert rows[0]["sender_username"] == "alice"
    plaintext, verified = bob.decrypt(rows[0]["ciphertext"], alice.public_key_armor)
    assert plaintext == secret
    assert verified is True

    alice_copy = client.get("/messages", headers=_auth(alice_token), params={"after_id": 0})
    copies = alice_copy.json()
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
    assert (
        client.post(
            "/contacts",
            headers=_auth(jamal_token),
            json={"username": "jamal1", "public_key_armor": jamal1_pub},
        ).status_code
        == 200
    )
    assert (
        client.post(
            "/contacts",
            headers=_auth(jamal1_token),
            json={"username": "jamal", "public_key_armor": jamal_pub},
        ).status_code
        == 200
    )

    secret = "tea at dusk with real keys"
    to_them = jamal.encrypt_for(secret, jamal1_pub)
    to_self = jamal.encrypt_for(secret, jamal_pub)
    sent = client.post(
        "/messages",
        headers=_auth(jamal_token),
        json={"recipient": "jamal1", "ciphertext": to_them, "self_ciphertext": to_self},
    )
    assert sent.status_code == 200, sent.text

    inbox = client.get("/messages", headers=_auth(jamal1_token), params={"after_id": 0})
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
