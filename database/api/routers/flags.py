"""Signed flags (Viewers) and signed responses to them (Analysts).

A flag points at one catalogue object, account, flag or flag response, with a
note. It has no status: Analysts answer it with responses, and act on it by
requesting a revocation of its target. Both are append-only. The client
chooses the ID and signs it, so a signed flag or response is stored at most
once; an identical retry returns the stored row with ``200``.

The database re-checks every rule: the author's role and that their account
is active, that the target exists, one flag per Viewer and target, and no new
flags on a revoked target or responses to a revoked flag.
"""

from __future__ import annotations

import logging
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Response
from psycopg import errors

from ..crypto import (
    FLAG_RESPONSE_SIGNATURE_DOMAIN,
    FLAG_SIGNATURE_DOMAIN,
    Flag as SignedFlag,
    flag_record,
    flag_response_record,
    verify,
)
from ..deps import ConnDep, Identity, current_identity, registered_key, require_roles
from ..schemas import Flag, FlagResponse, FlagResponseSubmission, FlagSubmission
from .catalogue import FLAG_RESPONSES, FLAGS

ViewerDep = Annotated[Identity, Depends(require_roles("viewer"))]
AnalystDep = Annotated[Identity, Depends(require_roles("analyst"))]

router = APIRouter(dependencies=[Depends(current_identity)], tags=["flags"])
audit = logging.getLogger("relic.audit")

_INSERT_FLAG = f"""
    INSERT INTO catalogue.flag AS t
        (flag_id, viewer_request_id, target_type, target_id, note, signature)
    VALUES (%s, %s, %s::catalogue.corpus_target_type, %s, %s, %s)
    RETURNING {FLAGS.columns}
"""

_INSERT_RESPONSE = f"""
    INSERT INTO catalogue.flag_response AS t
        (flag_response_id, flag_id, analyst_request_id, note, signature)
    VALUES (%s, %s, %s, %s, %s)
    RETURNING {FLAG_RESPONSES.columns}
"""


def _conflict(exc: errors.UniqueViolation, id_field: str) -> HTTPException:
    constraint = exc.diag.constraint_name or ""
    if constraint == "flag_one_per_viewer_target_idx":
        detail = "You have already flagged this target"
    elif constraint.endswith("_pkey"):
        detail = f"{id_field} is already used"
    else:
        detail = exc.diag.message_primary or "Conflict"
    return HTTPException(status_code=409, detail=detail)


@router.post("/flags", status_code=201, response_model=Flag)
async def submit_flag(body: FlagSubmission, response: Response, viewer: ViewerDep, conn: ConnDep):
    """Flag one catalogue object, account, flag or flag response (signed).

    ``201`` created; ``200`` identical retry; ``403`` bad signature or not the
    caller; ``409`` ID reused with other content, target already flagged by
    this Viewer, or target revoked; ``422`` unknown target.
    """
    if body.viewer_id != viewer.user_id:
        raise HTTPException(status_code=403, detail="viewer_id must be the authenticated account")

    flag = SignedFlag(
        flag_id=body.flag_id,
        viewer_id=body.viewer_id,
        target_type=body.target_type,
        target_id=body.target_id,
        note=body.note,
    )
    signature = bytes.fromhex(body.signature)

    async with conn.transaction():
        key = await registered_key(conn, body.viewer_id)
        if not verify(key, FLAG_SIGNATURE_DOMAIN, flag_record(flag), signature):
            audit.warning("flag signature rejected id=%s viewer=%s", body.flag_id, body.viewer_id)
            raise HTTPException(status_code=403, detail="Flag signature rejected")

        cur = await conn.execute(
            f"SELECT {FLAGS.columns} FROM catalogue.flag AS t WHERE t.flag_id = %s",
            (body.flag_id,),
        )
        existing = await cur.fetchone()
        if existing is not None:
            if existing["signature"] == body.signature and (
                existing["viewer_id"],
                existing["target_type"],
                existing["target_id"],
                existing["note"],
            ) == (body.viewer_id, body.target_type, body.target_id, body.note):
                response.status_code = 200
                return existing
            raise HTTPException(status_code=409, detail="flag_id is already used for a different flag")

        try:
            cur = await conn.execute(
                _INSERT_FLAG,
                (body.flag_id, body.viewer_id, body.target_type, body.target_id, body.note, signature),
            )
        except errors.UniqueViolation as exc:
            raise _conflict(exc, "flag_id") from exc
        row = await cur.fetchone()

    audit.info(
        "flag raised id=%s target=%s:%s viewer=%s",
        body.flag_id,
        body.target_type,
        body.target_id,
        body.viewer_id,
    )
    return row


@router.post("/flags/{flag_id}/responses", status_code=201, response_model=FlagResponse)
async def respond_to_flag(
    flag_id: UUID,
    body: FlagResponseSubmission,
    response: Response,
    analyst: AnalystDep,
    conn: ConnDep,
):
    """Respond to a flag (signed over the flag as stored and this response).

    A flag can have many responses. ``201`` created; ``200`` identical retry;
    ``403`` bad signature or not the caller; ``404`` unknown flag; ``409`` ID
    reused with other content, or the flag is revoked.
    """
    if body.analyst_id != analyst.user_id:
        raise HTTPException(status_code=403, detail="analyst_id must be the authenticated account")
    signature = bytes.fromhex(body.signature)

    async with conn.transaction():
        cur = await conn.execute(
            """SELECT viewer_request_id, target_type::text AS target_type, target_id, note
                 FROM catalogue.flag WHERE flag_id = %s""",
            (flag_id,),
        )
        stored = await cur.fetchone()
        if stored is None:
            raise HTTPException(status_code=404, detail="Flag not found")

        flag = SignedFlag(
            flag_id=flag_id,
            viewer_id=stored["viewer_request_id"],
            target_type=stored["target_type"],
            target_id=stored["target_id"],
            note=stored["note"],
        )
        record = flag_response_record(
            flag,
            flag_response_id=body.flag_response_id,
            analyst_id=body.analyst_id,
            note=body.note,
        )
        key = await registered_key(conn, body.analyst_id)
        if not verify(key, FLAG_RESPONSE_SIGNATURE_DOMAIN, record, signature):
            audit.warning(
                "flag response signature rejected id=%s flag=%s analyst=%s",
                body.flag_response_id,
                flag_id,
                body.analyst_id,
            )
            raise HTTPException(status_code=403, detail="Response signature rejected")

        cur = await conn.execute(
            f"""SELECT {FLAG_RESPONSES.columns} FROM catalogue.flag_response AS t
                 WHERE t.flag_response_id = %s""",
            (body.flag_response_id,),
        )
        existing = await cur.fetchone()
        if existing is not None:
            if existing["signature"] == body.signature and (
                existing["flag_id"],
                existing["analyst_id"],
                existing["note"],
            ) == (flag_id, body.analyst_id, body.note):
                response.status_code = 200
                return existing
            raise HTTPException(
                status_code=409, detail="flag_response_id is already used for a different response"
            )

        try:
            cur = await conn.execute(
                _INSERT_RESPONSE,
                (body.flag_response_id, flag_id, body.analyst_id, body.note, signature),
            )
        except errors.UniqueViolation as exc:
            raise _conflict(exc, "flag_response_id") from exc
        row = await cur.fetchone()

    audit.info(
        "flag response id=%s flag=%s analyst=%s", body.flag_response_id, flag_id, body.analyst_id
    )
    return row
