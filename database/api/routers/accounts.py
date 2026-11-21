from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException
from psycopg import errors

from .. import challenges
from ..crypto import REGISTRATION_SIGNATURE_DOMAIN, registration_record, verify
from ..deps import ConnDep, SettingsDep, registration_rate_limit
from ..schemas import RegistrationRequest, RegistrationResponse

router = APIRouter(tags=["accounts"])
audit = logging.getLogger("relic.audit")

_INSERT = """
    INSERT INTO catalogue.registration_request
        (challenge_id, public_key, requested_role, name, organisation, email, proof_signature)
    VALUES (%s, %s, %s::catalogue.account_role, %s, %s, %s, %s)
    RETURNING registration_request_id, requested_at
"""


@router.post(
    "/accounts",
    status_code=202,
    response_model=RegistrationResponse,
    dependencies=[Depends(registration_rate_limit)],
)
async def request_account(body: RegistrationRequest, settings: SettingsDep, conn: ConnDep):
    """Submit a BYO-key registration request.

    The signature proves possession of the private key matching
    ``public_key`` and binds every submitted detail to a fresh challenge.
    The request stays pending until a Moderator decides it; it is not an
    account and cannot sign anything.
    """
    challenge = await challenges.consume(
        conn,
        challenge_id=body.challenge_id,
        purpose="registration",
        audience=settings.audience,
        claimed_user_id=None,
    )
    public_key = bytes.fromhex(body.public_key)
    signature = bytes.fromhex(body.signature)
    if challenge is None or not verify(
        public_key,
        REGISTRATION_SIGNATURE_DOMAIN,
        registration_record(
            challenge,
            public_key=public_key,
            requested_role=body.requested_role,
            name=body.name,
            organisation=body.organisation,
            email=body.email,
        ),
        signature,
    ):
        audit.warning("registration proof rejected challenge_id=%s", body.challenge_id)
        raise HTTPException(status_code=401, detail="Registration proof rejected")

    try:
        cur = await conn.execute(
            _INSERT,
            (
                body.challenge_id,
                public_key,
                body.requested_role,
                body.name,
                body.organisation,
                body.email,
                signature,
            ),
        )
    except errors.UniqueViolation as exc:
        raise HTTPException(
            status_code=409, detail="This public key already has an account or a pending request"
        ) from exc
    row = await cur.fetchone()
    assert row is not None
    audit.info(
        "registration requested id=%s role=%s", row["registration_request_id"], body.requested_role
    )
    return RegistrationResponse(**row)
