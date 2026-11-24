"""Revocation requests and signed, final decisions (Moderators).

Analysts request revocation of catalogue entries; Moderators file revocations
of accounts (``target_type = user``) and decide every request, their own
included. Revoking a Moderator account needs two different Moderators.

Nothing is deleted: an approved revocation marks its target revoked. For an
account, access ends immediately, because every request re-reads the account.
"""

from __future__ import annotations

import logging
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from psycopg import errors

from ..crypto import (
    REVOCATION_DECISION_SIGNATURE_DOMAIN,
    REVOCATION_REQUEST_SIGNATURE_DOMAIN,
    RevocationRequest as SignedRevocation,
    revocation_decision_record,
    revocation_request_record,
    verify,
)
from ..deps import ConnDep, Identity, current_identity, registered_key, require_roles
from . import _approvals
from ..schemas import (
    AwaitingSecondApproval,
    RevocationDecisionRequest,
    RevocationDecisionResponse,
    RevocationDetail,
    RevocationRequest,
    RevocationStatus,
    TargetType,
)

RequesterDep = Annotated[Identity, Depends(require_roles("analyst", "moderator"))]
ModeratorDep = Annotated[Identity, Depends(require_roles("moderator"))]

# Reading revocations needs any active account; writing needs the route's role.
router = APIRouter(tags=["revocations"], dependencies=[Depends(current_identity)])
audit = logging.getLogger("relic.audit")

_COLUMNS = """
    revocation_id,
    coalesce(decision::text, 'pending') AS status,
    requester_id,
    target_type::text AS target_type,
    target_id, reason, requested_at,
    encode(request_signature, 'hex') AS request_signature,
    moderator_id, decided_at,
    encode(decision_signature, 'hex') AS decision_signature,
    CASE WHEN catalogue.target_is_moderator(target_type, target_id) THEN 2 ELSE 1 END
        AS approvals_required,
""" + _approvals.approvals_sql("revocation", "catalogue.revocation.revocation_id")

_INSERT = f"""
    INSERT INTO catalogue.revocation
        (revocation_id, requester_id, target_type, target_id, reason, request_signature)
    VALUES (%s, %s, %s::catalogue.corpus_target_type, %s, %s, %s)
    RETURNING {_COLUMNS}
"""


@router.get("/revocations", response_model=list[RevocationDetail])
async def list_revocations(
    conn: ConnDep,
    status: RevocationStatus | None = None,
    target_type: TargetType | None = None,
    target_id: UUID | None = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0, le=1_000_000)] = 0,
):
    """Revocation requests and decisions, oldest first, optionally filtered."""
    cur = await conn.execute(
        f"""SELECT {_COLUMNS} FROM catalogue.revocation
             WHERE (%(status)s::text IS NULL OR coalesce(decision::text, 'pending') = %(status)s)
               AND (%(target_type)s::text IS NULL OR target_type::text = %(target_type)s)
               AND (%(target_id)s::uuid IS NULL OR target_id = %(target_id)s)
             ORDER BY requested_at, revocation_id
             LIMIT %(limit)s OFFSET %(offset)s""",
        {
            "status": status,
            "target_type": target_type,
            "target_id": target_id,
            "limit": limit,
            "offset": offset,
        },
    )
    return await cur.fetchall()


@router.get("/revocations/{revocation_id}", response_model=RevocationDetail)
async def get_revocation(revocation_id: UUID, conn: ConnDep):
    """One request, in the exact shape `relic-sign-challenge decide-revocation` signs."""
    cur = await conn.execute(
        f"SELECT {_COLUMNS} FROM catalogue.revocation WHERE revocation_id = %s",
        (revocation_id,),
    )
    row = await cur.fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Revocation request not found")
    return row


@router.post("/revocations", status_code=201, response_model=RevocationDetail)
async def request_revocation(
    body: RevocationRequest,
    response: Response,
    requester: RequesterDep,
    conn: ConnDep,
):
    """Request revocation of a catalogue entry (Analysts) or an account (Moderators), signed.

    ``revocation_id`` is chosen by the requester and signed, so a request can
    be stored once. An identical retry returns the stored request with
    ``200``; the same ID with different content is ``409``. ``403`` for an
    Analyst targeting an account, a Moderator targeting an entry or their own
    account, or a bad signature.
    """
    if body.requester_id != requester.user_id:
        raise HTTPException(status_code=403, detail="requester_id must be the authenticated account")
    if (body.target_type == "user") != (requester.role == "moderator"):
        raise HTTPException(
            status_code=403,
            detail="Accounts are revoked by Moderators; Analysts request revocation of catalogue entries"
            if requester.role == "analyst"
            else "Moderators file revocations of accounts; Analysts request them for catalogue entries",
        )
    if body.target_type == "user" and body.target_id == requester.user_id:
        raise HTTPException(
            status_code=403, detail="A Moderator cannot request the revocation of their own account"
        )

    request = SignedRevocation(
        revocation_id=body.revocation_id,
        requester_id=body.requester_id,
        target_type=body.target_type,
        target_id=body.target_id,
        reason=body.reason,
    )
    signature = bytes.fromhex(body.signature)

    async with conn.transaction():
        # The key registered for the claimed User ID, never one from the request.
        key = await registered_key(conn, body.requester_id)
        if not verify(key, REVOCATION_REQUEST_SIGNATURE_DOMAIN, revocation_request_record(request), signature):
            audit.warning(
                "revocation request signature rejected id=%s requester=%s",
                body.revocation_id,
                body.requester_id,
            )
            raise HTTPException(status_code=403, detail="Request signature rejected")

        cur = await conn.execute(
            f"SELECT {_COLUMNS} FROM catalogue.revocation WHERE revocation_id = %s",
            (body.revocation_id,),
        )
        existing = await cur.fetchone()
        if existing is not None:
            if existing["request_signature"] == body.signature and (
                existing["requester_id"],
                existing["target_type"],
                existing["target_id"],
                existing["reason"],
            ) == (body.requester_id, body.target_type, body.target_id, body.reason):
                response.status_code = 200
                return existing
            raise HTTPException(
                status_code=409, detail="revocation_id is already used for a different request"
            )

        # The database re-checks the requester's role for the target type and
        # that the target exists (422 via the global handler otherwise).
        try:
            cur = await conn.execute(
                _INSERT,
                (
                    body.revocation_id,
                    body.requester_id,
                    body.target_type,
                    body.target_id,
                    body.reason,
                    signature,
                ),
            )
        except errors.UniqueViolation as exc:
            if exc.diag.constraint_name == "revocation_open_target_idx":
                detail = "This target already has an open revocation request"
            elif exc.diag.constraint_name == "revocation_pkey":
                detail = "revocation_id is already used"
            else:
                detail = exc.diag.message_primary or "Target is already revoked"
            raise HTTPException(status_code=409, detail=detail) from exc
        row = await cur.fetchone()

    audit.info(
        "revocation requested id=%s target=%s:%s requester=%s",
        body.revocation_id,
        body.target_type,
        body.target_id,
        body.requester_id,
    )
    return row


@router.post(
    "/revocations/{revocation_id}/decision",
    response_model=RevocationDecisionResponse,
    responses={202: {"model": AwaitingSecondApproval}},
)
async def decide_revocation(
    revocation_id: UUID,
    body: RevocationDecisionRequest,
    moderator: ModeratorDep,
    conn: ConnDep,
):
    """Approve or reject a pending request with a signed, final decision.

    The signature is verified against the Moderator's registered key over the
    request as stored, in the same transaction that records the decision.
    Approving the revocation of a Moderator account needs two different
    Moderators (neither the target): the first approval is stored and
    answered with ``202``; the second revokes. One rejection is final.
    """
    if body.moderator_id != moderator.user_id:
        raise HTTPException(
            status_code=403, detail="moderator_id must be the authenticated account"
        )

    async with conn.transaction():
        await _approvals.lock(conn, "revocation", revocation_id)
        cur = await conn.execute(
            """SELECT requester_id, target_type::text AS target_type, target_id, reason,
                      decision,
                      catalogue.target_is_moderator(target_type, target_id) AS target_is_moderator
                 FROM catalogue.revocation
                WHERE revocation_id = %s""",
            (revocation_id,),
        )
        stored = await cur.fetchone()
        if stored is None:
            raise HTTPException(status_code=404, detail="Revocation request not found")
        if stored["decision"] is not None:
            raise HTTPException(status_code=409, detail="Revocation request is already decided")
        if stored["target_type"] == "user" and stored["target_id"] == moderator.user_id:
            raise HTTPException(
                status_code=403,
                detail="A Moderator cannot decide the revocation of their own account",
            )

        request = SignedRevocation(
            revocation_id=revocation_id,
            requester_id=stored["requester_id"],
            target_type=stored["target_type"],
            target_id=stored["target_id"],
            reason=stored["reason"],
        )
        record = revocation_decision_record(
            request, moderator_id=moderator.user_id, decision=body.decision
        )
        signature = bytes.fromhex(body.signature)
        key = await registered_key(conn, moderator.user_id)
        if not verify(key, REVOCATION_DECISION_SIGNATURE_DOMAIN, record, signature):
            audit.warning(
                "revocation decision signature rejected id=%s moderator=%s",
                revocation_id,
                moderator.user_id,
            )
            raise HTTPException(status_code=403, detail="Decision signature rejected")

        if body.decision == "approved" and stored["target_is_moderator"]:
            pending = await _approvals.first_approval(
                conn,
                "revocation",
                revocation_id,
                moderator.user_id,
                signature,
                exclude=stored["target_id"],
            )
            if pending is not None:
                audit.info(
                    "revocation first approval id=%s moderator=%s", revocation_id, moderator.user_id
                )
                return pending

        # The row triggers re-check the Moderator and the requester, forbid
        # self-decision and set decided_at from the database clock. The WHERE
        # clause makes a concurrent second decision update nothing.
        cur = await conn.execute(
            """UPDATE catalogue.revocation
                  SET moderator_id = %s,
                      decision = %s::catalogue.revocation_decision,
                      decided_at = clock_timestamp(),
                      decision_signature = %s
                WHERE revocation_id = %s AND decision IS NULL
            RETURNING decided_at""",
            (moderator.user_id, body.decision, signature, revocation_id),
        )
        decided = await cur.fetchone()
        if decided is None:
            raise HTTPException(status_code=409, detail="Revocation request is already decided")

    audit.info(
        "revocation %s id=%s target=%s:%s moderator=%s",
        body.decision,
        revocation_id,
        stored["target_type"],
        stored["target_id"],
        moderator.user_id,
    )
    return RevocationDecisionResponse(
        revocation_id=revocation_id, decision=body.decision, decided_at=decided["decided_at"]
    )
