"""Request dependencies: settings, database connections and caller identity."""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Annotated, AsyncIterator, Callable, Awaitable
from uuid import UUID

import jwt
from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from psycopg import AsyncConnection

from .config import Settings
from .security import rate_limit

_MAX_TOKEN_LENGTH = 2048
_bearer = HTTPBearer(auto_error=False)


def get_settings(request: Request) -> Settings:
    return request.app.state.settings


async def get_conn(request: Request) -> AsyncIterator[AsyncConnection]:
    async with request.app.state.pool.connection() as conn:
        yield conn


SettingsDep = Annotated[Settings, Depends(get_settings)]
# Returned to the pool when the handler returns, not when the response has
# been sent: a streamed download must not hold a connection for its whole
# transfer (a few slow clients would otherwise exhaust the pool).
ConnDep = Annotated[AsyncConnection, Depends(get_conn, scope="function")]


def unauthorised(detail: str = "Authentication required") -> HTTPException:
    return HTTPException(status_code=401, detail=detail, headers={"WWW-Authenticate": "Bearer"})


# ---------------------------------------------------------------------------
# Session tokens
# ---------------------------------------------------------------------------


def issue_token(settings: Settings, user_id: UUID) -> str:
    now = int(time.time())
    claims = {
        "iss": settings.audience,
        "aud": settings.audience,
        "sub": str(user_id),
        "iat": now,
        "nbf": now,
        "exp": now + settings.jwt_ttl_seconds,
        "jti": uuid.uuid4().hex,
    }
    return jwt.encode(claims, settings.jwt_secret.get_secret_value(), algorithm="HS256")


def decode_token(settings: Settings, token: str) -> UUID:
    if len(token) > _MAX_TOKEN_LENGTH:
        raise unauthorised("Invalid token")
    try:
        claims = jwt.decode(
            token,
            settings.jwt_secret.get_secret_value(),
            algorithms=["HS256"],
            audience=settings.audience,
            issuer=settings.audience,
            options={"require": ["exp", "iat", "nbf", "iss", "aud", "sub", "jti"]},
        )
        return UUID(claims["sub"])
    except (jwt.PyJWTError, ValueError, TypeError) as exc:
        raise unauthorised("Invalid token") from exc


# ---------------------------------------------------------------------------
# Caller identity
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Identity:
    user_id: UUID
    role: str
    owner_type: str
    public_key: str
    created_at: datetime


_IDENTITY_COLUMNS = """
    SELECT user_id, role::text AS role, owner_type::text AS owner_type,
           encode(public_key, 'hex') AS public_key, created_at,
           catalogue.account_is_revoked(user_id) AS revoked
      FROM catalogue.user_public
"""
IDENTITY_QUERY = _IDENTITY_COLUMNS + " WHERE user_id = %s"
# Public keys are unique across all accounts (user_public_public_key_idx).
IDENTITY_BY_KEY_QUERY = _IDENTITY_COLUMNS + " WHERE public_key = %s"


async def token_subject(
    settings: SettingsDep,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
) -> UUID:
    """Validate the bearer token without touching the database."""
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise unauthorised()
    return decode_token(settings, credentials.credentials)


async def current_identity(
    request: Request,
    # Declared before ``conn`` so a missing or invalid token is rejected
    # before a pooled connection is checked out.
    user_id: Annotated[UUID, Depends(token_subject)],
    conn: ConnDep,
) -> Identity:
    """Resolve the bearer token to an active human account.

    The account is re-read on every request, so a revocation takes effect
    immediately rather than when the token expires.
    """
    return await _resolve_identity(request, conn, user_id)


async def _resolve_identity(request: Request, conn: AsyncConnection, user_id: UUID) -> Identity:
    cur = await conn.execute(IDENTITY_QUERY, (user_id,))
    row = await cur.fetchone()
    if row is None or row["revoked"] or row["owner_type"] != "human" or row["role"] is None:
        raise unauthorised("Invalid token")
    identity = Identity(
        user_id=row["user_id"],
        role=row["role"],
        owner_type=row["owner_type"],
        public_key=row["public_key"],
        created_at=row["created_at"],
    )
    request.state.identity = identity
    return identity


CurrentIdentity = Annotated[Identity, Depends(current_identity)]


async def identity_without_connection(
    request: Request,
    user_id: Annotated[UUID, Depends(token_subject)],
) -> Identity:
    """Like ``current_identity``, but borrows a connection only for the lookup.

    For handlers that spend long without the database (a streamed upload):
    they must not hold a pooled connection meanwhile.
    """
    async with request.app.state.pool.connection() as conn:
        return await _resolve_identity(request, conn, user_id)


def require_roles(
    *roles: str, hold_connection: bool = True
) -> Callable[[Identity], Awaitable[Identity]]:
    resolve = current_identity if hold_connection else identity_without_connection

    # A default, not an Annotated hint: with postponed annotations FastAPI
    # could not resolve the local ``resolve`` inside a string.
    async def dependency(identity: Identity = Depends(resolve)) -> Identity:
        if identity.role not in roles:
            raise HTTPException(status_code=403, detail="Role not permitted for this operation")
        return identity

    return dependency


async def registered_key(conn: AsyncConnection, user_id: UUID) -> bytes:
    """The Ed25519 key registered for ``user_id`` (an authenticated caller).

    Signed requests are always verified with this key, never one from the request.
    """
    cur = await conn.execute(
        "SELECT public_key FROM catalogue.user_public WHERE user_id = %s", (user_id,)
    )
    return (await cur.fetchone())["public_key"]


global_rate_limit = rate_limit(
    "global", lambda request: request.app.state.settings.global_rate_limit_per_minute, 60
)
auth_rate_limit = rate_limit(
    "auth", lambda request: request.app.state.settings.auth_rate_limit_per_minute, 60
)
registration_rate_limit = rate_limit(
    "registration",
    lambda request: request.app.state.settings.registration_rate_limit_per_hour,
    3600,
)
