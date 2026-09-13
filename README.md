# vaxchat

Privacy-focused chat: **FastAPI** is a ciphertext relay (HTTP + WebSockets). A **CustomTkinter** client encrypts with **GnuPG** locally (multi-recipient OpenPGP for rooms).

## Threat model

| Hidden from the server | Visible to the server |
| --- | --- |
| Message text | Usernames, room membership |
| Private keys / passphrases | Who is in which room, timestamps |
| | Ciphertext size / invite graph |

Not Signal: no forward secrecy. Wipe/recreate `vaxchat.db` after schema upgrades (SQLite `create_all` only).

**Trust:** Contact-pinned public keys are what the client encrypts to. Server-published member keys are directory hints only until you pin them (New DM paste / Contacts). Groups use invites — listing someone at create time does not enroll them until they accept.

**Auth:** JWTs include a `jti`; `/auth/logout` denylists that id in SQLite until expiry. WebSockets authenticate with a first-message `{"type":"auth","token":"..."}` (no `?token=` query string).

**Docs:** `/docs` and `/openapi.json` are off unless `VAXCHAT_DOCS=true`.

**Username enumeration:** Register returns a generic 409 body (`Could not create account`) by default. Timing/status codes can still leak existence; rate limits reduce probing. Set `ALLOW_USERNAME_TAKEN_DETAIL=true` only for local debugging.

## Requirements

- Python 3.12
- GnuPG on PATH (`gpg --version`)

## Setup

```text
py -3.12 -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
copy .env.example .env
.venv\Scripts\python.exe renew_secret.py
```

`renew_secret.py` writes a long random `SECRET_KEY` into `.env`. Restart uvicorn after renewing (existing JWTs become invalid).

## Run

Delete an old `vaxchat.db` if you upgraded schemas (rooms / invites / token denylist / contact fingerprints).

Terminal 1:

```text
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Terminal 2 / 3 (one window per user):

```text
python -m client.app
```

1. Register / log in.
2. Load or generate a PGP key; publish happens automatically.
3. **New DM** (paste peer pubkey to pin) or **New group** (invitees must accept), then send.
4. Live delivery uses `ws://host/ws/{room_id}` with first-message JWT auth and HTTP catch-up on reconnect.

## Tests

```text
pytest -q
```
