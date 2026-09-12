# vaxchat

A privacy-focused chat app: **FastAPI stores ciphertext only**, and a **CustomTkinter desktop client** encrypts and decrypts with **GnuPG** on your machine.

The server never sees plaintext or private keys. It *does* see usernames, who talks to whom, and timestamps.

## Requirements

- Python 3.12
- [GnuPG](https://gnupg.org/) on your PATH (`gpg --version`). Needed for modern Ed25519 keys (PGPy cannot load them).

## Threat model

| Hidden from the server | Visible to the server |
| --- | --- |
| Message text | Usernames |
| Private keys and passphrases | Who messaged whom |
| Key material in an isolated local GnuPG home | Ciphertext size and time |

This is not Signal. OpenPGP has no forward secrecy: if a private key leaks later, old ciphertext in the database can be read.

Private keys are imported into a temporary GnuPG home for the client session. They are never sent in HTTP bodies.

## Setup

Use Python 3.12 (the Windows `py` launcher default may be newer).

```text
py -3.12 -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
copy .env.example .env
```

Edit `.env` and set a long random `SECRET_KEY`.

## Run

Terminal 1 — relay:

```text
uvicorn app.main:app --reload --port 8000
```

If Windows blocks port 8000 (`WinError 10013`), pick another:

```text
uvicorn app.main:app --reload --port 8765
```

Terminal 2 — desktop client (open twice for two users):

```text
python -m client.app
```

1. Register two usernames.
2. In each window: **Load private key** (e.g. from `testkeys/`) with passphrase, or **Generate keys**.
3. Add the other user as a contact (paste their public key, or skip the paste if they already published one).
4. Send a message. It is encrypted locally; the server only stores `-----BEGIN PGP MESSAGE-----` blocks.

Default server URL in the client is `http://127.0.0.1:8000`. Change it in the login screen if you used another port. Use HTTPS if the relay is not on localhost.

### Sample keys

`testkeys/` (gitignored) can hold local test keypairs. Example pair names: `jamal` / `jamal1`.

## Tests

```text
pytest -q
```
