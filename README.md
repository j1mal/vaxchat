# vaxchat

Privacy-focused chat: **FastAPI** is a ciphertext relay (HTTP + WebSockets). A **CustomTkinter** client encrypts with **GnuPG** locally (multi-recipient OpenPGP for rooms).

## Threat model

| Hidden from the server | Visible to the server |
| --- | --- |
| Message text | Usernames, room membership |
| Private keys / passphrases | Who is in which room, timestamps |
| | Ciphertext size |

Not Signal: no forward secrecy. Wipe/recreate `vaxchat.db` after schema upgrades (SQLite `create_all` only).

## Requirements

- Python 3.12
- GnuPG on PATH (`gpg --version`)

## Setup

```text
py -3.12 -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
copy .env.example .env
```

Set a long random `SECRET_KEY` in `.env`.

## Run

Delete an old `vaxchat.db` if you upgraded from the pre-rooms schema.

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
3. **New DM** or **New group**, then send. Ciphertext is multi-recipient; live delivery uses `ws://host/ws/{room_id}?token=...` with HTTP catch-up on reconnect.

## Tests

```text
pytest -q
```
