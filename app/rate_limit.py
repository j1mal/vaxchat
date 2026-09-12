import os

from dotenv import load_dotenv
from slowapi import Limiter
from slowapi.util import get_remote_address

load_dotenv()


def _enabled() -> bool:
    return os.environ.get("RATE_LIMIT_ENABLED", "true").lower() not in {"0", "false", "no"}


limiter = Limiter(key_func=get_remote_address, enabled=_enabled())

