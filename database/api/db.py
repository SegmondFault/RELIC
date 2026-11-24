"""Database pool and mapping of database errors to HTTP status codes."""

from __future__ import annotations

from psycopg import Error
from psycopg.rows import dict_row
from psycopg_pool import AsyncConnectionPool

from .config import Settings

__all__ = ["make_pool", "map_db_error"]


def make_pool(settings: Settings) -> AsyncConnectionPool:
    return AsyncConnectionPool(
        conninfo=settings.database_url.get_secret_value(),
        min_size=settings.pool_min_size,
        max_size=settings.pool_max_size,
        kwargs={
            "autocommit": True,
            "row_factory": dict_row,
            "application_name": "relic-api",
            # Bound every statement and abandoned transaction server-side.
            "options": (
                f"-c statement_timeout={settings.statement_timeout_ms}"
                f" -c idle_in_transaction_session_timeout={settings.statement_timeout_ms * 2}"
            ),
        },
        timeout=10,
        open=False,
    )


_EXACT = {
    "42501": 403,
    "23505": 409,
    "23503": 422,
    "23514": 422,
    "23502": 422,
    "40001": 503,
    "40P01": 503,
}


def map_db_error(exc: Error) -> tuple[int, str]:
    state = exc.sqlstate or ""
    status = _EXACT.get(state)
    if status is None:
        if state.startswith("23"):
            status = 409
        elif state.startswith("22"):
            status = 422
    if status is None:
        return 500, "Internal database error"
    if status == 503:
        return 503, "Transient database conflict; retry"
    return status, (exc.diag.message_primary or "Request rejected by database")
