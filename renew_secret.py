#!/usr/bin/env python3
"""Generate a strong SECRET_KEY and write it into .env (creating from .env.example if needed).

Usage:
  .venv\\Scripts\\python.exe renew_secret.py
  .venv\\Scripts\\python.exe renew_secret.py --bytes 64
  .venv\\Scripts\\python.exe renew_secret.py --print-only

Restart the server after renewing. Existing JWTs become invalid (expected).
"""

from __future__ import annotations

import argparse
import re
import secrets
from pathlib import Path

ROOT = Path(__file__).resolve().parent
ENV_PATH = ROOT / ".env"
EXAMPLE_PATH = ROOT / ".env.example"


def generate_secret(nbytes: int = 64) -> str:
    # urlsafe gives a long, high-entropy string suitable for JWT HMAC keys
    return secrets.token_urlsafe(nbytes)


def upsert_env_secret(path: Path, secret: str) -> None:
    if not path.exists():
        if EXAMPLE_PATH.exists():
            text = EXAMPLE_PATH.read_text(encoding="utf-8")
        else:
            text = "DATABASE_URL=sqlite:///./vaxchat.db\nJWT_EXPIRE_MINUTES=10080\nRATE_LIMIT_ENABLED=true\n"
        path.write_text(text, encoding="utf-8")

    lines = path.read_text(encoding="utf-8").splitlines()
    key_re = re.compile(r"^SECRET_KEY\s*=")
    replaced = False
    out: list[str] = []
    for line in lines:
        if key_re.match(line):
            out.append(f"SECRET_KEY={secret}")
            replaced = True
        else:
            out.append(line)
    if not replaced:
        out.insert(0, f"SECRET_KEY={secret}")
    path.write_text("\n".join(out) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="Renew vaxchat SECRET_KEY")
    parser.add_argument("--bytes", type=int, default=64, help="Random bytes before urlsafe encoding (default 64)")
    parser.add_argument("--print-only", action="store_true", help="Print the key; do not write .env")
    args = parser.parse_args()
    if args.bytes < 32:
        raise SystemExit("--bytes must be at least 32")
    secret = generate_secret(args.bytes)
    if args.print_only:
        print(secret)
        return
    upsert_env_secret(ENV_PATH, secret)
    print(f"Wrote new SECRET_KEY to {ENV_PATH}")
    print("Restart uvicorn so the new key is loaded. Existing sessions are invalidated.")


if __name__ == "__main__":
    main()
