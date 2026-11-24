"""Shared admission of Analyst-signed rows with client-chosen IDs.

The Analyst chooses the row's ID and signs it with the other fields; the API
verifies the signature with the Analyst's registered key and stores the row.
Rows are immutable, so an identical retry returns the stored row (``200``)
and the same ID with other content is ``409``.
"""

from __future__ import annotations

import logging
from typing import Any, Awaitable, Callable
from uuid import UUID

from fastapi import HTTPException, Response
from psycopg import AsyncConnection, errors

from ..crypto import verify
from ..deps import Identity, registered_key

audit = logging.getLogger("relic.audit")


async def verified_signature(
    conn: AsyncConnection,
    analyst: Identity,
    claimed: UUID,
    domain: bytes,
    record: bytes,
    signature: str,
    what: str,
) -> bytes:
    """The caller's signature over ``record``, checked with their registered key."""
    if claimed != analyst.user_id:
        raise HTTPException(status_code=403, detail="analyst_id must be the authenticated account")
    raw = bytes.fromhex(signature)
    if not verify(await registered_key(conn, analyst.user_id), domain, record, raw):
        audit.warning("%s signature rejected analyst=%s", what, analyst.user_id)
        raise HTTPException(status_code=403, detail=f"{what.capitalize()} signature rejected")
    return raw


async def admit(
    conn: AsyncConnection,
    response: Response,
    *,
    select: str,
    key: UUID,
    insert: Callable[[], Awaitable[dict]],
    same: Callable[[dict], bool],
    id_field: str,
    what: str,
) -> dict:
    """Insert the row, or return the stored one if it is identical.

    Call inside a transaction. ``select`` reads the row by ``key`` with the
    columns the route returns; ``insert`` writes it and returns that row;
    ``same`` compares a stored row with the request.
    """
    cur = await conn.execute(select, (key,))
    existing = await cur.fetchone()
    if existing is None:
        try:
            # A savepoint, so a concurrent identical insert that wins leaves
            # this transaction usable to read the winner.
            async with conn.transaction():
                return await insert()
        except errors.UniqueViolation as exc:
            if not (exc.diag.constraint_name or "").endswith("_pkey"):
                raise HTTPException(
                    status_code=409, detail=exc.diag.message_primary or "Conflict"
                ) from exc
        cur = await conn.execute(select, (key,))
        existing = await cur.fetchone()
    if existing is None or not same(existing):
        raise HTTPException(
            status_code=409, detail=f"{id_field} is already used for a different {what}"
        )
    response.status_code = 200
    return existing


def fields_match(row: dict[str, Any], expected: dict[str, Any]) -> bool:
    return all(row[column] == value for column, value in expected.items())
