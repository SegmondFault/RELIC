from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import AsyncIterator

from fastapi import APIRouter, Depends, FastAPI, Request
from fastapi.responses import JSONResponse
from psycopg import Error as DatabaseError
from psycopg_pool import PoolTimeout

from .config import Settings, get_settings
from .db import make_pool, map_db_error
from .deps import global_rate_limit
from .routers import (
    accounts,
    auth,
    catalogue,
    components,
    flags,
    health,
    registrations,
    revocations,
    submissions,
)
from .security import (
    BodySizeLimitMiddleware,
    ByteBudget,
    RateLimiter,
    SecurityHeadersMiddleware,
    UploadSlots,
)

log = logging.getLogger("relic.api")


def _configure_logging() -> None:
    # Uvicorn configures only its own loggers; make audit events visible.
    relic = logging.getLogger("relic")
    if not relic.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s"))
        relic.addHandler(handler)
        relic.setLevel(logging.INFO)


def create_app(settings: Settings | None = None) -> FastAPI:
    """Application factory (uvicorn --factory api.main:create_app)."""
    settings = settings or get_settings()
    _configure_logging()

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        pool = make_pool(settings)
        # Do not block start-up on the database; requests fail with 503
        # until it is reachable, and /healthz stays a pure liveness probe.
        await pool.open(wait=False)
        app.state.pool = pool
        try:
            yield
        finally:
            await pool.close()

    docs = settings.insecure_dev_mode
    app = FastAPI(
        title="RELIC API",
        version="0.1.0",
        lifespan=lifespan,
        docs_url="/docs" if docs else None,
        redoc_url="/redoc" if docs else None,
        openapi_url="/openapi.json" if docs else None,
    )
    app.state.settings = settings
    app.state.rate_limiter = RateLimiter()
    app.state.upload_slots = UploadSlots()
    app.state.upload_budget = ByteBudget()

    # add_middleware prepends: SecurityHeaders (added last) is outermost and
    # also covers 413 responses produced by the body limit.
    app.add_middleware(
        BodySizeLimitMiddleware,
        max_bytes=settings.max_body_bytes,
        larger=[
            ("/v1/fidbf-objects", settings.max_object_bytes),
            ("/v1/fidbf", settings.max_submission_bytes),
            ("/v1/bsim", settings.max_submission_bytes),
            ("/v1/provenance", settings.max_submission_bytes),
        ],
    )
    app.add_middleware(SecurityHeadersMiddleware, allow_docs=docs)

    @app.exception_handler(PoolTimeout)
    async def _pool_unavailable(_: Request, __: PoolTimeout) -> JSONResponse:
        return JSONResponse(status_code=503, content={"detail": "Database unavailable"})

    @app.exception_handler(DatabaseError)
    async def _database_error(_: Request, exc: DatabaseError) -> JSONResponse:
        status, detail = map_db_error(exc)
        if status >= 500:
            log.error("database error sqlstate=%s", exc.sqlstate, exc_info=exc)
        return JSONResponse(status_code=status, content={"detail": detail})

    app.include_router(health.router)

    v1 = APIRouter(prefix="/v1", dependencies=[Depends(global_rate_limit)])
    for module in (
        auth, accounts, registrations, catalogue, submissions, components, flags, revocations
    ):
        v1.include_router(module.router)
    v1.include_router(submissions.upload_router)
    app.include_router(v1)

    return app
