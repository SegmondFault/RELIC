"""Two-Moderator approval for Moderator powers (shared by registrations and revocations).

Approving a Moderator registration, or the revocation of a Moderator account,
needs two different active Moderators. Each signs the ordinary decision
message. The first approval is stored in an approval table; the second
Moderator's decision is final. The database enforces the same rule.
"""

from __future__ import annotations

from typing import Literal
from uuid import UUID

from fastapi import HTTPException
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse
from psycopg import AsyncConnection

from ..schemas import AwaitingSecondApproval

_TABLES = {
    "registration": ("catalogue.registration_approval", "registration_request_id"),
    "revocation": ("catalogue.revocation_approval", "revocation_id"),
}


def approvals_sql(kind: Literal["registration", "revocation"], row_key: str) -> str:
    """Select-list expression: the stored first approvals of the row, as JSON."""
    table, key = _TABLES[kind]
    return f"""coalesce((
        SELECT json_agg(json_build_object(
                   'moderator_id', a.moderator_id,
                   'signature', encode(a.approval_signature, 'hex'),
                   'approved_at', a.approved_at) ORDER BY a.approved_at)
          FROM {table} AS a WHERE a.{key} = {row_key}), '[]'::json) AS approvals"""


async def lock(conn: AsyncConnection, kind: str, key: UUID) -> None:
    """Serialise decisions on one request, so two first approvals cannot race."""
    await conn.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))", (f"{kind}:{key}",))


async def first_approval(
    conn: AsyncConnection,
    kind: Literal["registration", "revocation"],
    key: UUID,
    moderator_id: UUID,
    signature: bytes,
    *,
    exclude: UUID | None = None,
) -> JSONResponse | None:
    """Store a first approval and return 202, or None if this approval can be final.

    It can be final when another active Moderator (not ``exclude``, the
    revocation target) has already approved.
    """
    table, column = _TABLES[kind]
    cur = await conn.execute(
        f"""SELECT moderator_id FROM {table}
             WHERE {column} = %s AND catalogue.is_active_moderator(moderator_id)""",
        (key,),
    )
    approvers = {row["moderator_id"] for row in await cur.fetchall()} - {exclude}
    if approvers - {moderator_id}:
        return None
    if moderator_id in approvers:
        raise HTTPException(
            status_code=409,
            detail="You have already approved; another Moderator must approve",
        )
    await conn.execute(
        f"INSERT INTO {table} ({column}, moderator_id, approval_signature) VALUES (%s, %s, %s)",
        (key, moderator_id, signature),
    )
    cur = await conn.execute(
        f"SELECT {approvals_sql(kind, '%s')}", (key,)
    )
    approvals = (await cur.fetchone())["approvals"]
    body = AwaitingSecondApproval(approvals=approvals)
    return JSONResponse(status_code=202, content=jsonable_encoder(body))
