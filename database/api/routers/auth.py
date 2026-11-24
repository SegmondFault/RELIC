from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException

from .. import challenges
from ..crypto import LOGIN_SIGNATURE_DOMAIN, login_record, verify
from ..deps import (
    IDENTITY_BY_KEY_QUERY,
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

    A challenge names no account, so issuing one reveals nothing about which
    keys or accounts exist.
    """
    return await challenges.issue(
        conn,
        purpose=body.purpose,
        audience=settings.audience,
        ttl_seconds=settings.challenge_ttl_seconds,
    )


_REGISTRATION_STATUS = """
    SELECT coalesce(decision::text, 'pending') AS status
      FROM catalogue.registration_request
     WHERE public_key = %s
     ORDER BY (decision IS NULL) DESC, requested_at DESC
     LIMIT 1
"""


@router.post(
    "/auth/login",
    response_model=TokenResponse,
    dependencies=[Depends(auth_rate_limit)],
)
async def login(body: LoginRequest, settings: SettingsDep, conn: ConnDep):
    """Exchange a signed login challenge for a short-lived bearer token.

    The caller names itself by public key. The signature is checked against
    that key before any account is looked up, so every failure without the
    private key (unknown key, wrong signature, spent or expired challenge)
    is identical and takes the same path.
    """
    public_key = bytes.fromhex(body.public_key)
    fingerprint = body.public_key[:16]
    challenge = await challenges.consume(
        conn,
        challenge_id=body.challenge_id,
        purpose="login",
        audience=settings.audience,
    )
    if challenge is None or not verify(
        public_key,
        LOGIN_SIGNATURE_DOMAIN,
        login_record(challenge, public_key),
        bytes.fromhex(body.signature),
    ):
        audit.warning("login rejected key=%s", fingerprint)
        raise unauthorised("Authentication failed")

    # From here on the caller has proven possession of the key, so telling
    # them the state of their own account or registration leaks nothing.
    cur = await conn.execute(IDENTITY_BY_KEY_QUERY, (public_key,))
    account = await cur.fetchone()
    if account is None:
        cur = await conn.execute(_REGISTRATION_STATUS, (public_key,))
        registration = await cur.fetchone()
        audit.info(
            "login without account key=%s registration=%s",
            fingerprint,
            registration["status"] if registration else None,
        )
        if registration is not None and registration["status"] == "pending":
            raise HTTPException(status_code=403, detail="Registration is pending approval")
        if registration is not None and registration["status"] == "rejected":
            raise HTTPException(status_code=403, detail="Registration was rejected")
        raise unauthorised("Authentication failed")

    if account["revoked"]:
        audit.warning("login rejected for revoked account user_id=%s", account["user_id"])
        raise HTTPException(status_code=403, detail="Account has been revoked")
    if account["owner_type"] != "human" or account["role"] is None:
        # System accounts sign chain entries only; they never get a session.
        audit.warning("login rejected for system account user_id=%s", account["user_id"])
        raise unauthorised("Authentication failed")

    audit.info("login user_id=%s role=%s", account["user_id"], account["role"])
    return TokenResponse(
        access_token=issue_token(settings, account["user_id"]),
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
