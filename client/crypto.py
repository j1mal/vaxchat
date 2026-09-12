from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

import gnupg


class CryptoError(Exception):
    pass


class CryptoSession:
    """Holds crypto state via an isolated GnuPG home. Private keys never leave this machine."""

    def __init__(self) -> None:
        self._home: Path | None = None
        self._gpg: gnupg.GPG | None = None
        self._passphrase: str = ""
        self.fingerprint: str | None = None
        self.public_key_armor: str | None = None

    @property
    def unlocked(self) -> bool:
        return self._gpg is not None and self.fingerprint is not None

    def clear(self) -> None:
        self._gpg = None
        self._passphrase = ""
        self.fingerprint = None
        self.public_key_armor = None
        if self._home is not None and self._home.exists():
            shutil.rmtree(self._home, ignore_errors=True)
        self._home = None

    def _ensure_gpg(self) -> gnupg.GPG:
        if self._gpg is not None:
            return self._gpg
        self._home = Path(tempfile.mkdtemp(prefix="vaxchat-gpg-"))
        self._gpg = gnupg.GPG(gnupghome=str(self._home))
        return self._gpg

    def load_private(self, armor: str, passphrase: str = "") -> None:
        self.clear()
        gpg = self._ensure_gpg()
        imported = gpg.import_keys(armor.strip())
        if not imported.fingerprints:
            raise CryptoError("Could not import private key (unsupported or corrupt).")
        # Prefer a secret key fingerprint.
        secrets = gpg.list_keys(True)
        if not secrets:
            raise CryptoError("That file is a public key. Load a private key to decrypt.")
        fp = secrets[0]["fingerprint"]
        # Validate passphrase by attempting a sign of a tiny message.
        if passphrase:
            signed = gpg.sign("vaxchat-unlock-check", keyid=fp, passphrase=passphrase, clearsign=True)
            if not signed.data:
                self.clear()
                raise CryptoError("Wrong passphrase or key cannot sign.")
        else:
            # Unprotected keys: try without passphrase.
            signed = gpg.sign("vaxchat-unlock-check", keyid=fp, clearsign=True)
            if not signed.data:
                self.clear()
                raise CryptoError("This private key needs a passphrase.")
        exported = gpg.export_keys(fp)
        if not exported:
            self.clear()
            raise CryptoError("Could not export public key from private key.")
        self.fingerprint = fp
        self._passphrase = passphrase
        self.public_key_armor = str(exported)

    def generate(self, name: str, passphrase: str = "") -> str:
        """Create a modern OpenPGP key with GnuPG. Returns private key armor."""
        self.clear()
        gpg = self._ensure_gpg()
        email = f"{name}@vaxchat.local"
        if passphrase:
            result = gpg.gen_key(
                gpg.gen_key_input(
                    name_real=name,
                    name_email=email,
                    key_type="EDDSA",
                    key_curve="ed25519",
                    subkey_type="ECDH",
                    subkey_curve="cv25519",
                    passphrase=passphrase,
                    expire_date=0,
                )
            )
            if not result.fingerprint:
                result = gpg.gen_key(
                    gpg.gen_key_input(
                        name_real=name,
                        name_email=email,
                        key_type="RSA",
                        key_length=2048,
                        passphrase=passphrase,
                        expire_date=0,
                    )
                )
            if not result.fingerprint:
                raise CryptoError(f"Key generation failed: {result.stderr or result.status}")
            private = gpg.export_keys(result.fingerprint, secret=True, passphrase=passphrase)
        else:
            # GnuPG 2.1+ needs %no-protection for unprotected secret keys.
            batch = "\n".join(
                [
                    "Key-Type: EDDSA",
                    "Key-Curve: ed25519",
                    "Key-Usage: sign",
                    "Subkey-Type: ECDH",
                    "Subkey-Curve: cv25519",
                    "Subkey-Usage: encrypt",
                    f"Name-Real: {name}",
                    f"Name-Email: {email}",
                    "Expire-Date: 0",
                    "%no-protection",
                    "%commit",
                ]
            )
            result = gpg.gen_key(batch)
            if not result.fingerprint:
                batch_rsa = "\n".join(
                    [
                        "Key-Type: RSA",
                        "Key-Length: 2048",
                        f"Name-Real: {name}",
                        f"Name-Email: {email}",
                        "Expire-Date: 0",
                        "%no-protection",
                        "%commit",
                    ]
                )
                result = gpg.gen_key(batch_rsa)
            if not result.fingerprint:
                raise CryptoError(f"Key generation failed: {result.stderr or result.status}")
            private = gpg.export_keys(result.fingerprint, secret=True, expect_passphrase=False)
        if not private:
            raise CryptoError("Could not export generated private key.")
        self.load_private(str(private), passphrase)
        return str(private)

    def encrypt_for(self, plaintext: str, recipient_public_armor: str) -> str:
        return self.encrypt_message(plaintext, [recipient_public_armor])

    def _import_public(self, armor: str) -> str:
        """Import a public key into the session keyring; tolerate re-import of the same key."""
        if self._gpg is None:
            raise CryptoError("Load your private key first.")
        imported = self._gpg.import_keys(armor.strip())
        # GnuPG returns fingerprints even when the key "already exists" in the keyring.
        if imported.fingerprints:
            return imported.fingerprints[0]
        # Fallback: scan keyring for a key matching this armor's identity packet.
        # Some gpg builds report count=0 on duplicate import; try listing after import.
        try:
            probe = self._gpg.list_keys(False)
        except Exception as exc:
            raise CryptoError(f"Could not import recipient public key: {exc}") from exc
        if not probe:
            raise CryptoError("Could not import recipient public key.")
        # Last resort: re-export/import via temporary parse — still may fail.
        raise CryptoError("Could not import recipient public key.")

    def encrypt_message(self, plaintext: str, recipient_public_armors: list[str]) -> str:
        """Encrypt once to every recipient pubkey (multi-recipient OpenPGP). Safe to re-call."""
        if not self.unlocked or self._gpg is None or not self.fingerprint:
            raise CryptoError("Load your private key first.")
        if not recipient_public_armors:
            raise CryptoError("At least one recipient public key is required.")
        fingerprints: list[str] = []
        seen: set[str] = set()
        for armor in recipient_public_armors:
            if not armor or not armor.strip():
                continue
            fp = self._import_public(armor)
            if fp not in seen:
                seen.add(fp)
                fingerprints.append(fp)
        if not fingerprints:
            raise CryptoError("Could not import any recipient public keys.")
        encrypted = self._gpg.encrypt(
            plaintext,
            fingerprints,
            sign=self.fingerprint,
            passphrase=self._passphrase or None,
            always_trust=True,
            armor=True,
        )
        if not encrypted.ok:
            raise CryptoError(f"Encrypt failed: {encrypted.status} {encrypted.stderr}")
        return str(encrypted)

    def decrypt(self, ciphertext: str, sender_public_armor: str | None = None) -> tuple[str, bool | None]:
        if not self.unlocked or self._gpg is None:
            raise CryptoError("Load your private key first.")
        gpg = self._gpg
        if sender_public_armor:
            try:
                self._import_public(sender_public_armor)
            except CryptoError:
                gpg.import_keys(sender_public_armor.strip())
        decrypted = gpg.decrypt(ciphertext.strip(), passphrase=self._passphrase or None)
        if not decrypted.ok:
            raise CryptoError(f"Decrypt failed: {decrypted.status} {decrypted.stderr}")
        plaintext = decrypted.data
        if isinstance(plaintext, bytes):
            plaintext = plaintext.decode("utf-8", errors="replace")
        verified: bool | None = None
        if sender_public_armor:
            if decrypted.valid is True:
                verified = True
            elif decrypted.signature_id or decrypted.username:
                verified = bool(decrypted.valid)
            else:
                verified = False
        return str(plaintext), verified
