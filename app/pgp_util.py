from __future__ import annotations

import base64
import hashlib
import re

from app.config import get_settings

_ARMOR_BODY_RE = re.compile(
    r"^-----BEGIN (?P<header>PGP (?:MESSAGE|PUBLIC KEY BLOCK))-----\r?\n"
    r"(?:.*?\r?\n)*?"
    r"\r?\n"
    r"(?P<body>[A-Za-z0-9+/=\r\n]+)"
    r"-----END (?P=header)-----\s*$",
    re.DOTALL,
)


def fingerprint_for_armor(armor: str) -> str:
    """Stable pin id derived from armored key material (server has no GPG)."""
    normalized = "\n".join(line.strip() for line in armor.strip().splitlines() if line.strip())
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def _validate_armor(blob: str, *, header: str, max_chars: int) -> bool:
    text = blob.strip().replace("\r\n", "\n").replace("\r", "\n")
    if not text or len(text) > max_chars:
        return False
    begin = f"-----BEGIN {header}-----"
    end = f"-----END {header}-----"
    if not text.startswith(begin) or end not in text:
        return False
    # Require a blank line separating headers from base64 body (OpenPGP armor).
    parts = text.split("\n\n", 1)
    if len(parts) != 2:
        return False
    body_and_end = parts[1]
    if end not in body_and_end:
        return False
    body = body_and_end.split(end, 1)[0]
    # Drop optional checksum line (=XXXX)
    lines = [ln.strip() for ln in body.splitlines() if ln.strip()]
    if lines and lines[-1].startswith("=") and len(lines[-1]) >= 5:
        lines = lines[:-1]
    if len(lines) < 2:
        return False
    raw = "".join(lines)
    if len(raw) < 64:
        return False
    try:
        # Armor uses base64; validate alphabet + padding.
        base64.b64decode(raw, validate=True)
    except Exception:
        return False
    return True


def is_pgp_message(blob: str) -> bool:
    settings = get_settings()
    return _validate_armor(blob, header="PGP MESSAGE", max_chars=settings.max_ciphertext_chars)


def is_pgp_public_key(blob: str) -> bool:
    settings = get_settings()
    return _validate_armor(blob, header="PGP PUBLIC KEY BLOCK", max_chars=settings.max_public_key_chars)
