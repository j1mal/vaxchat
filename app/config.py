from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    secret_key: str = "dev-only-change-me"
    jwt_expire_minutes: int = 60 * 24 * 7
    database_url: str = "sqlite:///./vaxchat.db"
    jwt_algorithm: str = "HS256"


@lru_cache
def get_settings() -> Settings:
    return Settings()
