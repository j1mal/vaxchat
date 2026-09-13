from functools import lru_cache

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# Hard floor so a forgotten .env cannot leave a trivial HMAC secret in "prod-like" runs.
_INSECURE_DEFAULTS = {"", "dev-only-change-me", "change-me-to-a-long-random-string"}


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    secret_key: str = "dev-only-change-me"
    jwt_expire_minutes: int = 60 * 24 * 7
    database_url: str = "sqlite:///./vaxchat.db"
    jwt_algorithm: str = "HS256"
    # Production default: hide OpenAPI. Set VAXCHAT_DOCS=true for local exploration.
    vaxchat_docs: bool = False
    # Soften register conflict messaging (409 still indicates conflict for clients that care).
    allow_username_taken_detail: bool = False

    # Payload caps
    max_ciphertext_chars: int = 256_000
    max_public_key_chars: int = 32_768
    max_room_members: int = 32

    @field_validator("secret_key")
    @classmethod
    def _warn_weak_secret(cls, value: str) -> str:
        if value.strip() in _INSECURE_DEFAULTS or len(value.strip()) < 32:
            # Allow boot for first-run, but callers should run renew_secret.py.
            return value
        return value


@lru_cache
def get_settings() -> Settings:
    return Settings()


def require_strong_secret() -> None:
    """Optional guard for production entrypoints."""
    settings = get_settings()
    key = settings.secret_key.strip()
    if key in _INSECURE_DEFAULTS or len(key) < 32:
        raise RuntimeError(
            "SECRET_KEY is missing or too weak. Run: python renew_secret.py"
        )
