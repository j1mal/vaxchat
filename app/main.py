from contextlib import asynccontextmanager

from fastapi import FastAPI
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

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


app = FastAPI(
    title="vaxchat",
    description="Ciphertext relay. The server cannot read message bodies.",
    lifespan=lifespan,
)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.include_router(auth_router.router)
app.include_router(auth_router.me_router)
app.include_router(contacts_router.router)
app.include_router(rooms_router.router)
app.include_router(ws_router.router)


@app.get("/health")
def health():
    return {"ok": True}
