from __future__ import annotations

from fastapi import APIRouter, FastAPI

from .routers import accounts, auth, catalogue, flags, health, revocations, submissions

app = FastAPI(title="RELIC API", version="0.1.0")

app.include_router(health.router)

v1 = APIRouter(prefix="/v1")
for module in (auth, catalogue, submissions, flags, revocations, accounts):
    v1.include_router(module.router)

app.include_router(v1)
