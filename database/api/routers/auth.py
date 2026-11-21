from __future__ import annotations

import logging

from fastapi import APIRouter, Depends

from .. import challenges
from ..crypto import LOGIN_SIGNATURE_DOMAIN, login_record, verify
from ..deps import (
    IDENTITY_QUERY,
    ConnDep,
    CurrentIdentity,
    SettingsDep,
    auth_rate_limit,
    issue_token,
    unauthorised,
)
from ..schemas import ChallengeRequest, ChallengeResponse, LoginRequest, TokenResponse, UserPublic

router = APIRouter(tags=["auth"])
audit = logging.getLogger("relic.audit")


@router.post(
    "/auth/challenge",
    status_code=201,
    response_model=ChallengeResponse,
    dependencies=[Depends(auth_rate_limit)],
)
async def create_challenge(body: ChallengeRequest, settings: SettingsDep, conn: ConnDep):
    """Issue a single-use challenge for login or registration.

    A login challenge is issued for any well-formed User ID, so this endpoint
    does not reveal which accounts exist.
    """
    return await challenges.issue(
        conn,
        purpose=body.purpose,
        audience=settings.audience,
        ttl_seconds=settings.challenge_ttl_seconds,
        claimed_user_id=body.user_id,
    )


@router.post(
    "/auth/login",
    response_model=TokenResponse,
    dependencies=[Depends(auth_rate_limit)],
)
async def login(body: LoginRequest, settings: SettingsDep, conn: ConnDep):
    """Exchange a signed login challenge for a short-lived bearer token."""
    challenge = await challenges.consume(
        conn,
        challenge_id=body.challenge_id,
        purpose="login",
        audience=settings.audience,
        claimed_user_id=body.user_id,
    )
    cur = await conn.execute(IDENTITY_QUERY, (body.user_id,))
    account = await cur.fetchone()

    authenticated = (
        challenge is not None
        and account is not None
        and account["owner_type"] == "human"
        and account["role"] is not None
        and not account["revoked"]
        and verify(
            bytes.fromhex(account["public_key"]),
            LOGIN_SIGNATURE_DOMAIN,
            login_record(challenge, body.user_id),
            bytes.fromhex(body.signature),
        )
    )
    if not authenticated:
        audit.warning("login rejected user_id=%s", body.user_id)
        raise unauthorised("Authentication failed")

    audit.info("login user_id=%s role=%s", body.user_id, account["role"])
    return TokenResponse(
        access_token=issue_token(settings, body.user_id),
        expires_in=settings.jwt_ttl_seconds,
    )


@router.get("/me", response_model=UserPublic)
async def me(identity: CurrentIdentity):
    return UserPublic(
        user_id=identity.user_id,
        role=identity.role,
        owner_type=identity.owner_type,
        public_key=identity.public_key,
        created_at=identity.created_at,
        revoked=False,
    )
