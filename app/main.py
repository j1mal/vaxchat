from contextlib import asynccontextmanager

from fastapi import FastAPI
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from app.config import get_settings
from app.db import init_db
from app.rate_limit import limiter
from app.routers import auth as auth_router
from app.routers import contacts as contacts_router
from app.routers import rooms as rooms_router
from app import ws as ws_router


@asynccontextmanager
async def lifespan(_app: FastAPI):
    init_db()
    yield


def create_app() -> FastAPI:
    settings = get_settings()
    docs = settings.vaxchat_docs
    application = FastAPI(
        title="vaxchat",
        description="Ciphertext relay. The server cannot read message bodies.",
        lifespan=lifespan,
        docs_url="/docs" if docs else None,
        redoc_url="/redoc" if docs else None,
        openapi_url="/openapi.json" if docs else None,
    )
    application.state.limiter = limiter
    application.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

    application.include_router(auth_router.router)
    application.include_router(auth_router.me_router)
    application.include_router(contacts_router.router)
    application.include_router(rooms_router.router)
    application.include_router(ws_router.router)

    @application.get("/health")
    def health():
        return {"ok": True}

    return application


app = create_app()
