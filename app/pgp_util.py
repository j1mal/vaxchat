def is_pgp_message(blob: str) -> bool:
    text = blob.strip()
    return text.startswith("-----BEGIN PGP MESSAGE-----") and "-----END PGP MESSAGE-----" in text


def is_pgp_public_key(blob: str) -> bool:
    text = blob.strip()
    return (
        text.startswith("-----BEGIN PGP PUBLIC KEY BLOCK-----")
        and "-----END PGP PUBLIC KEY BLOCK-----" in text
    )
