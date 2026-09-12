import os

os.environ["RATE_LIMIT_ENABLED"] = "false"
os.environ.setdefault("SECRET_KEY", "test-secret-key-for-jwt-please-ignore")
