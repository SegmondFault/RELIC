from __future__ import annotations

import base64
from contextlib import asynccontextmanager
from decimal import Decimal
from typing import Any, AsyncIterator, Mapping, Sequence

from psycopg import AsyncConnection, Error, sql
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb
from psycopg_pool import AsyncConnectionPool

from .config import Settings

__all__ = [
    "Jsonb", 
    "make_pool", 
    "read_tx", 
    "write_tx", 
    "fetch_one", 
    "fetch_all",
    "insert_row", 
    "clean_row", 
    "map_db_error"
]

def make_pool(settings: Settings) -> AsyncConnectionPool:
    return AsyncConnectionPool(
        conninfo=settings.database_url,
        min_size=settings.pool_min_size,
        max_size=settings.pool_max_size,
        kwargs={"autocommit": True, "row_factory": dict_row},
        open=False,
    )


@asynccontextmanager
async def read_tx(conn: AsyncConnection) -> AsyncIterator[None]:
    async with conn.transaction():
        await conn.execute("SET TRANSACTION READ ONLY")
        yield


@asynccontextmanager
async def write_tx(conn: AsyncConnection) -> AsyncIterator[None]:
    async with conn.transaction():
        yield


def _clean(v: Any) -> Any:
    if isinstance(v, (bytes, bytearray, memoryview)):
        return base64.b64encode(bytes(v)).decode("ascii")
    if isinstance(v, Decimal):  # numeric(20,0) addresses
        return int(v) if v == v.to_integral_value() else str(v)
    return v


def clean_row(row: Mapping[str, Any]) -> dict[str, Any]:
    return {k: _clean(v) for k, v in row.items()}


async def fetch_one(
    conn: AsyncConnection, 
    query: Any, 
    params: Sequence[Any] | None = None, 
    *, 
    raw: bool = False
) -> dict[str, Any] | None:
    cur = await conn.execute(query, params)
    row = await cur.fetchone()
    if row is None:
        return None
    return row if raw else clean_row(row)


async def fetch_all(
    conn: AsyncConnection, query: Any,
    params: Sequence[Any] | None = None
) -> list[dict[str, Any]]:
    cur = await conn.execute(query, params)
    return [clean_row(r) for r in await cur.fetchall()]


async def insert_row(
    conn: AsyncConnection, 
    table: str, 
    values: Mapping[str, Any], 
    returning: Sequence[str]
) -> dict[str, Any]:
    query = sql.SQL("INSERT INTO {t} ({cols}) VALUES ({ph}) RETURNING {ret}").format(
        t=sql.Identifier(table),
        cols=sql.SQL(", ").join(map(sql.Identifier, values)),
        ph=sql.SQL(", ").join(sql.Placeholder() for _ in values),
        ret=sql.SQL(", ").join(map(sql.Identifier, returning)),
    )
    row = await fetch_one(conn, query, list(values.values()))
    assert row is not None
    return row

_EXACT = {
    "42501": 403, 
    "23505": 409, 
    "23503": 422, 
    "23514": 422, 
    "23502": 422, 
    "40001": 503, 
    "40P01": 503
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
