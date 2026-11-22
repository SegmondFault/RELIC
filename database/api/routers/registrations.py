"""Moderator review of pending BYO-key registrations."""

from __future__ import annotations

import logging
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query

from ..crypto import REGISTRATION_DECISION_SIGNATURE_DOMAIN, registration_decision_record, verify
from ..deps import ConnDep, Identity, require_roles
from . import _approvals
from ..schemas import (
    AwaitingSecondApproval,
    RegistrationDecisionRequest,
    RegistrationDecisionResponse,
    RegistrationDetail,
    RegistrationStatus,
)

# One dependency object, so FastAPI resolves it once per request.
require_moderator = require_roles("moderator")
ModeratorDep = Annotated[Identity, Depends(require_moderator)]

router = APIRouter(tags=["registrations"], dependencies=[Depends(require_moderator)])
audit = logging.getLogger("relic.audit")

_COLUMNS = """
    registration_request_id,
    coalesce(decision::text, 'pending') AS status,
    encode(public_key, 'hex') AS public_key,
    requested_role::text AS requested_role,
    name, organisation, email, requested_at,
    moderator_id, decided_at,
    encode(decision_signature, 'hex') AS decision_signature,
    user_id,
    CASE WHEN requested_role = 'moderator' THEN 2 ELSE 1 END AS approvals_required,
""" + _approvals.approvals_sql(
    "registration", "catalogue.registration_request.registration_request_id"
)


@router.get("/registrations", response_model=list[RegistrationDetail])
async def list_registrations(
    conn: ConnDep,
    status: RegistrationStatus = "pending",
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0, le=1_000_000)] = 0,
):
    """Registration requests, oldest first. Pending by default."""
    cur = await conn.execute(
        f"""SELECT {_COLUMNS} FROM catalogue.registration_request
             WHERE coalesce(decision::text, 'pending') = %s
             ORDER BY requested_at, registration_request_id
             LIMIT %s OFFSET %s""",
        (status, limit, offset),
    )
    return await cur.fetchall()


@router.get("/registrations/{registration_request_id}", response_model=RegistrationDetail)
async def get_registration(registration_request_id: UUID, conn: ConnDep):
    """One request, in the exact shape `relic-sign-challenge decide-registration` signs."""
    cur = await conn.execute(
        f"SELECT {_COLUMNS} FROM catalogue.registration_request WHERE registration_request_id = %s",
        (registration_request_id,),
    )
    row = await cur.fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Registration request not found")
    return row


@router.post(
    "/registrations/{registration_request_id}/decision",
    response_model=RegistrationDecisionResponse,
    responses={202: {"model": AwaitingSecondApproval}},
)
async def decide_registration(
    registration_request_id: UUID,
    body: RegistrationDecisionRequest,
    moderator: ModeratorDep,
    conn: ConnDep,
):
    """Approve or reject a pending request with a signed, final decision.

    The signature is verified against the Moderator's registered key over the
    request row as stored, inside the same transaction that records the
    decision (and, on approval, creates the account). Approving a Moderator
    needs two different Moderators: the first approval is stored and answered
    with ``202``; the second creates the account. One rejection is final.
    """
    if body.moderator_id != moderator.user_id:
        raise HTTPException(
            status_code=403, detail="moderator_id must be the authenticated account"
        )

    async with conn.transaction():
        # relic_app has no UPDATE privilege here (so FOR UPDATE is refused);
        # an advisory lock serialises decisions on this request instead, and
        # decide_registration() locks the row and rejects a second decision.
        await _approvals.lock(conn, "registration", registration_request_id)
        cur = await conn.execute(
            """SELECT public_key, requested_role::text AS requested_role, name, organisation,
                      email, decision
                 FROM catalogue.registration_request
                WHERE registration_request_id = %s""",
            (registration_request_id,),
        )
        request = await cur.fetchone()
        if request is None:
            raise HTTPException(status_code=404, detail="Registration request not found")
        if request["decision"] is not None:
            raise HTTPException(status_code=409, detail="Registration request is already decided")

        cur = await conn.execute(
            "SELECT public_key FROM catalogue.user_public WHERE user_id = %s",
            (moderator.user_id,),
        )
        moderator_key = (await cur.fetchone())["public_key"]
        signature = bytes.fromhex(body.signature)
        record = registration_decision_record(
            registration_request_id,
            public_key=request["public_key"],
            requested_role=request["requested_role"],
            name=request["name"],
            organisation=request["organisation"],
            email=request["email"],
            moderator_id=moderator.user_id,
            decision=body.decision,
        )
        if not verify(moderator_key, REGISTRATION_DECISION_SIGNATURE_DOMAIN, record, signature):
            audit.warning(
                "registration decision signature rejected id=%s moderator=%s",
                registration_request_id,
                moderator.user_id,
            )
            raise HTTPException(status_code=403, detail="Decision signature rejected")

        if body.decision == "approved" and request["requested_role"] == "moderator":
            pending = await _approvals.first_approval(
                conn, "registration", registration_request_id, moderator.user_id, signature
            )
            if pending is not None:
                audit.info(
                    "registration first approval id=%s moderator=%s",
                    registration_request_id,
                    moderator.user_id,
                )
                return pending

        # The database re-checks that the decider is an active Moderator and
        # that the decision is final.
        cur = await conn.execute(
            """SELECT catalogue.decide_registration(
                          %s, %s, %s::catalogue.registration_decision, %s) AS user_id""",
            (registration_request_id, moderator.user_id, body.decision, signature),
        )
        user_id = (await cur.fetchone())["user_id"]
        cur = await conn.execute(
            "SELECT decided_at FROM catalogue.registration_request"
            " WHERE registration_request_id = %s",
            (registration_request_id,),
        )
        decided_at = (await cur.fetchone())["decided_at"]

    audit.info(
        "registration %s id=%s moderator=%s user_id=%s",
        body.decision,
        registration_request_id,
        moderator.user_id,
        user_id,
    )
    return RegistrationDecisionResponse(
        registration_request_id=registration_request_id,
        decision=body.decision,
        decided_at=decided_at,
        user_id=user_id,
    )
