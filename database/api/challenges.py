"""Issue and atomically consume single-use authentication challenges."""

from __future__ import annotations

import secrets
from typing import Literal
from uuid import UUID

from psycopg import AsyncConnection, IntegrityError

from .crypto import NONCE_BYTES, Challenge

Purpose = Literal["login", "registration"]

_ISSUE = """
    INSERT INTO catalogue.auth_challenge
        (purpose, nonce, claimed_user_id, audience, expires_at)
    VALUES (%s::catalogue.auth_challenge_purpose, %s, %s, %s,
            clock_timestamp() + make_interval(secs => %s))
    RETURNING challenge_id, purpose::text AS purpose, encode(nonce, 'hex') AS nonce,
              audience, expires_at,
              (extract(epoch FROM expires_at) * 1000000)::bigint AS expires_at_unix_micros
"""

_CONSUME = """
    UPDATE catalogue.auth_challenge
       SET consumed_at = clock_timestamp()
     WHERE challenge_id = %s
       AND purpose = %s::catalogue.auth_challenge_purpose
       AND claimed_user_id IS NOT DISTINCT FROM %s
       AND audience = %s
       AND consumed_at IS NULL
       AND expires_at > clock_timestamp()
    RETURNING nonce,
              (extract(epoch FROM expires_at) * 1000000)::bigint AS expires_at_unix_micros
"""


async def issue(
    conn: AsyncConnection,
    *,
    purpose: Purpose,
    audience: str,
    ttl_seconds: int,
    claimed_user_id: UUID | None,
) -> dict:
    cur = await conn.execute(
        _ISSUE,
        (purpose, secrets.token_bytes(NONCE_BYTES), claimed_user_id, audience, ttl_seconds),
    )
    row = await cur.fetchone()
    assert row is not None
    if secrets.randbelow(100) == 0:
        await conn.execute("SELECT catalogue.purge_expired_auth_challenges()")
    return row


async def consume(
    conn: AsyncConnection,
    *,
    challenge_id: UUID,
    purpose: Purpose,
    audience: str,
    claimed_user_id: UUID | None,
) -> Challenge | None:
    """Mark a challenge used. Returns None if it is unknown, expired or spent.

    The connection is in autocommit mode, so consumption is durable even if
    the signature that follows turns out to be invalid.
    """
    try:
        cur = await conn.execute(_CONSUME, (challenge_id, purpose, claimed_user_id, audience))
        row = await cur.fetchone()
    except IntegrityError:
        # Expired between the WHERE clause and the row trigger.
        return None
    if row is None:
        return None
    return Challenge(
        challenge_id=challenge_id,
        nonce=bytes(row["nonce"]),
        audience=audience,
        expires_at_unix_micros=row["expires_at_unix_micros"],
    )
