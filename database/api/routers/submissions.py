"""Signed corpus submissions by Analysts.

Licence assertions and classifications are independently signed claims: the
Analyst chooses the ID and signs the claim, the API verifies it with the
Analyst's registered key and stores it in one transaction. Neither takes an
integrity-chain entry. Both are immutable; a correction is a new claim plus a
revocation of the old one. An identical retry returns the stored row (200).

FIDBF objects, BSim objects and provenance seals each take an
integrity-chain entry, which the API cannot sign: they are staged here and
admitted by relic-admit (see the section below).
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import stat
import uuid
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from fastapi import Path as PathParam
from pydantic import ValidationError
from starlette.concurrency import run_in_threadpool

from ..crypto import (
    CLASSIFICATION_SIGNATURE_DOMAIN,
    LICENSE_ASSERTION_SIGNATURE_DOMAIN,
    Classification as SignedClassification,
    LicenseAssertion as SignedLicenseAssertion,
    classification_record,
    license_assertion_record,
)
from ..config import Settings
from ..deps import (
    ConnDep,
    CurrentIdentity,
    Identity,
    SettingsDep,
    current_identity,
    require_roles,
)
from ..schemas import (
    BsimSubmissionIn,
    ClassificationDetail,
    ClassificationSubmission,
    FidbfManifest,
    LicenseAssertion,
    LicenseAssertionSubmission,
    ProvenanceSubmissionIn,
    StagedObject,
    SubmissionState,
    SubmissionStatus,
)
from ._claims import admit, fields_match, verified_signature
from .catalogue import CLASSIFICATIONS, LICENSE_ASSERTIONS

AnalystDep = Annotated[Identity, Depends(require_roles("analyst"))]

router = APIRouter(dependencies=[Depends(current_identity)], tags=["submissions"])
# Uploads stream for minutes without the database, so this router holds no
# pooled connection: the caller is resolved with a briefly borrowed one.
upload_router = APIRouter(tags=["submissions"])
UploaderDep = Annotated[Identity, Depends(require_roles("analyst", hold_connection=False))]
audit = logging.getLogger("relic.audit")


# ---------------------------------------------------------------------------
# Licence assertions
# ---------------------------------------------------------------------------

_LICENSE_SELECT = (
    f"SELECT {LICENSE_ASSERTIONS.columns} FROM catalogue.license_assertion AS t"
    " WHERE t.license_assertion_id = %s"
)
_LICENSE_INSERT = f"""
    INSERT INTO catalogue.license_assertion AS t
        (license_assertion_id, source_id, binary_id, spdx_expression, basis, confidence,
         evidence_provenance_id, submitted_by_analyst_id, signature)
    VALUES (%s, %s, %s, %s, %s::catalogue.license_assertion_basis, %s::numeric, %s, %s, %s)
    RETURNING {LICENSE_ASSERTIONS.columns}
"""


@router.post("/license-assertions", status_code=201, response_model=LicenseAssertion)
async def submit_license_assertion(
    body: LicenseAssertionSubmission, response: Response, analyst: AnalystDep, conn: ConnDep
):
    """Claim an SPDX licence for one source or binary (signed).

    ``201`` created; ``200`` identical retry; ``403`` bad signature or not the
    caller; ``409`` ID reused with other content, or the target is revoked;
    ``422`` invalid expression, unknown target or unknown evidence.
    """
    claim = SignedLicenseAssertion(
        license_assertion_id=body.license_assertion_id,
        analyst_id=body.analyst_id,
        target_type=body.target_type,
        target_id=body.target_id,
        spdx_expression=body.spdx_expression,
        basis=body.basis,
        confidence=body.confidence,
        evidence_provenance_id=body.evidence_provenance_id,
    )

    async def insert() -> dict:
        cur = await conn.execute(
            _LICENSE_INSERT,
            (
                body.license_assertion_id,
                body.target_id if body.target_type == "source" else None,
                body.target_id if body.target_type == "binary" else None,
                body.spdx_expression, body.basis, body.confidence,
                body.evidence_provenance_id, body.analyst_id, signature,
            ),
        )
        return await cur.fetchone()

    async with conn.transaction():
        signature = await verified_signature(
            conn, analyst, body.analyst_id, LICENSE_ASSERTION_SIGNATURE_DOMAIN,
            license_assertion_record(claim), body.signature, "licence assertion",
        )
        row = await admit(
            conn, response, select=_LICENSE_SELECT, key=body.license_assertion_id,
            insert=insert, id_field="license_assertion_id", what="assertion",
            same=lambda row: fields_match(row, {
                "signature": body.signature,
                "submitted_by_analyst_id": body.analyst_id,
                "target_type": body.target_type,
                "target_id": body.target_id,
                "spdx_expression": body.spdx_expression,
                "basis": body.basis,
                "confidence": body.confidence,
                "evidence_provenance_id": body.evidence_provenance_id,
            }),
        )
    audit.info(
        "licence assertion id=%s target=%s:%s analyst=%s",
        body.license_assertion_id, body.target_type, body.target_id, body.analyst_id,
    )
    return row


# ---------------------------------------------------------------------------
# Classifications
# ---------------------------------------------------------------------------

_CLASSIFICATION_COLUMNS = f"{CLASSIFICATIONS.columns}, {CLASSIFICATIONS.detail}"
_CLASSIFICATION_SELECT = (
    f"SELECT {_CLASSIFICATION_COLUMNS} FROM catalogue.classification AS t"
    " WHERE t.classification_id = %s"
)
_CLASSIFICATION_INSERT = f"""
    INSERT INTO catalogue.classification AS t
        (classification_id, target_type, target_id, label, confidence, analyst_id,
         misp_universe, misp_uuid, evidence, evidence_json, signature)
    VALUES (%s, %s::catalogue.corpus_target_type, %s, %s, %s::numeric, %s, %s, %s,
            %s::jsonb, %s, %s)
    RETURNING {_CLASSIFICATION_COLUMNS}
"""


@router.post("/classifications", status_code=201, response_model=ClassificationDetail)
async def submit_classification(
    body: ClassificationSubmission, response: Response, analyst: AnalystDep, conn: ConnDep
):
    """Label one binary, function or behavioural composition (signed).

    ``evidence_json`` is signed and stored as the exact text sent. ``201``
    created; ``200`` identical retry; ``403`` bad signature or not the caller;
    ``409`` ID reused with other content, or the target is revoked; ``422``
    invalid fields or unknown target.
    """
    claim = SignedClassification(
        classification_id=body.classification_id,
        analyst_id=body.analyst_id,
        target_type=body.target_type,
        target_id=body.target_id,
        label=body.label,
        confidence=body.confidence,
        misp_universe=body.misp_universe,
        misp_uuid=body.misp_uuid,
        evidence_json=body.evidence_json,
    )

    async def insert() -> dict:
        cur = await conn.execute(
            _CLASSIFICATION_INSERT,
            (
                body.classification_id, body.target_type, body.target_id, body.label,
                body.confidence, body.analyst_id, body.misp_universe, body.misp_uuid,
                body.evidence_json, body.evidence_json, signature,
            ),
        )
        return await cur.fetchone()

    async with conn.transaction():
        signature = await verified_signature(
            conn, analyst, body.analyst_id, CLASSIFICATION_SIGNATURE_DOMAIN,
            classification_record(claim), body.signature, "classification",
        )
        row = await admit(
            conn, response, select=_CLASSIFICATION_SELECT, key=body.classification_id,
            insert=insert, id_field="classification_id", what="classification",
            same=lambda row: fields_match(row, {
                "signature": body.signature,
                "analyst_id": body.analyst_id,
                "target_type": body.target_type,
                "target_id": body.target_id,
                "label": body.label,
                "confidence": body.confidence,
                "misp_universe": body.misp_universe,
                "misp_uuid": body.misp_uuid,
                "evidence_json": body.evidence_json,
            }),
        )
    audit.info(
        "classification id=%s target=%s:%s analyst=%s",
        body.classification_id, body.target_type, body.target_id, body.analyst_id,
    )
    return row


# ---------------------------------------------------------------------------
# FIDBF, BSim and provenance: staged for relic-admit
# ---------------------------------------------------------------------------
#
# The API never holds the integrity key, so it cannot admit these (each takes
# an integrity-chain entry). It checks what it can, stores the signed
# submission as received, and answers 202; relic-admit, on the host as
# relic_worker, verifies the signatures and admits or rejects it. The
# submission ID is the ID of the object it creates.

_SUBMISSION_COLUMNS = """
    submission_id, kind::text AS kind, status::text AS status, received_at, decided_at,
    attempts, result, error"""


def canonical_storage_path(sha256: str) -> str:
    """Where relic-admit stores a FIDBF object, relative to the object root."""
    return f"{sha256[:2]}/{sha256}.fidbf"


def _status(row: dict) -> dict:
    row = {key: value for key, value in row.items() if key not in ("payload_json", "analyst_id")}
    return {**row, "status_url": f"/v1/submissions/{row['submission_id']}"}


def _duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    keys = [key for key, _ in pairs]
    if len(keys) != len(set(keys)):
        raise ValueError("duplicate keys")
    return dict(pairs)


def _invalid(error: ValidationError) -> HTTPException:
    return HTTPException(
        status_code=422,
        detail=error.errors(include_url=False, include_context=False, include_input=False),
    )


async def _json_body(request: Request) -> tuple[str, Any]:
    """The body as received (it is stored verbatim) and parsed."""
    raw = await request.body()
    try:
        text = raw.decode("utf-8")
        return text, json.loads(text, object_pairs_hook=_duplicate_keys)
    except (UnicodeDecodeError, ValueError) as error:
        raise HTTPException(status_code=422, detail=f"Body must be JSON: {error}") from error


async def _stage(
    conn: ConnDep,
    response: Response,
    *,
    kind: str,
    submission_id: UUID,
    analyst: Identity,
    claimed: UUID,
    payload: str,
    object_sha256: str | None = None,
) -> dict:
    if claimed != analyst.user_id:
        raise HTTPException(status_code=403, detail="The Analyst must be the authenticated account")
    columns = _SUBMISSION_COLUMNS + ", payload_json"
    select = f"SELECT {columns} FROM catalogue.submission WHERE submission_id = %s"

    async def insert() -> dict:
        cur = await conn.execute(
            f"""INSERT INTO catalogue.submission
                    (submission_id, kind, analyst_id, payload_json, object_sha256)
                VALUES (%s, %s::catalogue.submission_kind, %s, %s, %s)
                RETURNING {columns}""",
            (submission_id, kind, analyst.user_id, payload, object_sha256),
        )
        return await cur.fetchone()

    async with conn.transaction():
        row = await admit(
            conn, response, select=select, key=submission_id, insert=insert,
            id_field="ID", what="submission",
            same=lambda row: row["payload_json"] == payload,
        )
    if response.status_code != 200:
        response.status_code = 202
    audit.info("%s submission staged id=%s analyst=%s", kind, submission_id, analyst.user_id)
    return _status(row)


def _staged_object(settings: Settings, sha256: str) -> os.stat_result | None:
    try:
        info = os.lstat(settings.staging_dir / f"{sha256}.fidbf")
    except FileNotFoundError:
        return None
    return info if stat.S_ISREG(info.st_mode) else None


def _staging_bytes(settings: Settings) -> int:
    total = 0
    with os.scandir(settings.staging_dir) as entries:
        for entry in entries:
            if entry.is_file(follow_symlinks=False):
                total += entry.stat(follow_symlinks=False).st_size
    return total


_DAY = 24 * 3600.0


@upload_router.put(
    "/fidbf-objects/{sha256}", status_code=201, response_model=StagedObject,
    responses={200: {"description": "Already staged"}},
)
async def upload_fidbf_object(
    sha256: Annotated[str, PathParam(pattern=r"^[0-9a-f]{64}$")],
    request: Request,
    response: Response,
    analyst: UploaderDep,
    settings: SettingsDep,
):
    """Upload a FIDBF object (raw bytes, with ``Content-Length``) before its manifest.

    Named by its SHA-256, which the body must match. Streamed to the staging
    directory while hashing; at most ``max_object_bytes``. ``201`` staged;
    ``200`` already staged; ``411`` no ``Content-Length``; ``413`` too large;
    ``422`` digest mismatch or empty; ``429`` too many uploads in progress, or
    the Analyst's daily upload budget is used up; ``503`` too many uploads in
    progress overall; ``507`` the staging area is full.
    """
    try:
        declared = int(request.headers["content-length"])
    except (KeyError, ValueError) as error:
        raise HTTPException(status_code=411, detail="Content-Length is required") from error
    if declared == 0:
        raise HTTPException(status_code=422, detail="Empty object")
    if declared > settings.max_object_bytes:
        raise HTTPException(status_code=413, detail="Object too large")
    key = str(analyst.user_id)
    budget = request.app.state.upload_budget
    if budget.used(key, _DAY) + declared > settings.upload_bytes_per_analyst_per_day:
        raise HTTPException(
            status_code=429, detail="Daily upload budget used up", headers={"Retry-After": "3600"}
        )
    # The incoming object counts: the cap holds even with uploads in flight
    # (each slot can add at most max_object_bytes).
    if _staging_bytes(settings) + declared > settings.max_staging_bytes:
        raise HTTPException(status_code=507, detail="Staging area is full; try again later")
    slots = request.app.state.upload_slots
    if not slots.acquire(key, settings.max_uploads_per_analyst, settings.max_uploads_total):
        raise HTTPException(
            status_code=503 if slots.total >= settings.max_uploads_total else 429,
            detail="Too many uploads in progress; try again shortly",
            headers={"Retry-After": "30"},
        )
    try:
        size, md5 = await _receive_object(request, settings, sha256, response)
    finally:
        slots.release(key)
    budget.record(key, size, _DAY)
    audit.info("FIDBF object staged sha256=%s size=%d analyst=%s", sha256, size, analyst.user_id)
    return StagedObject(sha256=sha256, md5=md5, size_bytes=size)


async def _receive_object(
    request: Request, settings: Settings, sha256: str, response: Response
) -> tuple[int, str]:
    part = settings.staging_dir / f"{sha256}.{uuid.uuid4().hex}.part"
    final = settings.staging_dir / f"{sha256}.fidbf"
    digest, md5, size = hashlib.sha256(), hashlib.md5(usedforsecurity=False), 0
    descriptor = os.open(part, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o640)
    try:
        with os.fdopen(descriptor, "wb") as output:
            async for chunk in request.stream():
                size += len(chunk)
                if size > settings.max_object_bytes:
                    raise HTTPException(status_code=413, detail="Object too large")
                digest.update(chunk)
                md5.update(chunk)
                await run_in_threadpool(output.write, chunk)
            output.flush()
            await run_in_threadpool(os.fsync, output.fileno())
        if size == 0:
            raise HTTPException(status_code=422, detail="Empty object")
        if digest.hexdigest() != sha256:
            raise HTTPException(status_code=422, detail="Body does not match its SHA-256")
        if _staged_object(settings, sha256) is not None:
            response.status_code = 200
        else:
            os.replace(part, final)
    finally:
        part.unlink(missing_ok=True)
    return size, md5.hexdigest()


@router.post(
    "/fidbf", status_code=202, response_model=SubmissionStatus,
    responses={200: {"description": "Identical retry"}},
)
async def submit_fidbf(
    request: Request, response: Response, analyst: AnalystDep, conn: ConnDep,
    settings: SettingsDep,
):
    """Submit a signed FIDBF manifest (from ``relic-sign-fidbf``) for admission.

    Upload the object first (``PUT /v1/fidbf-objects/{sha256}``). The
    manifest's ``storage_path`` must be ``<first two hex digits>/<sha256>.fidbf``
    (``relic-sign-fidbf --canonical-storage-path``). relic-admit verifies the
    signatures and admits the source, batch, binary, FIDBF, functions and
    integrity entry together. ``202`` staged; ``200`` identical retry;
    ``403`` not the caller; ``409`` ID reused with another manifest; ``422``
    invalid, or the object is not uploaded.
    """
    payload, parsed = await _json_body(request)
    try:
        manifest = FidbfManifest.model_validate(parsed)
    except ValidationError as error:
        raise _invalid(error) from error
    fidbf = manifest.fidbf
    if manifest.source.source_type.upper() != "FIDBF":
        raise HTTPException(status_code=422, detail="source.source_type must be FIDBF")
    if fidbf.storage_path != canonical_storage_path(fidbf.sha256):
        raise HTTPException(
            status_code=422,
            detail=f"fidbf.storage_path must be {canonical_storage_path(fidbf.sha256)}",
        )
    if manifest.analyst_user_id == analyst.user_id and _staged_object(settings, fidbf.sha256) is None:
        cur = await conn.execute(
            "SELECT 1 FROM catalogue.fidbf WHERE sha256::text = %s", (fidbf.sha256,)
        )
        if await cur.fetchone() is None:
            raise HTTPException(
                status_code=422, detail="Upload the object first: PUT /v1/fidbf-objects/{sha256}"
            )
    return await _stage(
        conn, response, kind="fidbf", submission_id=fidbf.fidbf_id, analyst=analyst,
        claimed=manifest.analyst_user_id, payload=payload, object_sha256=fidbf.sha256,
    )


@router.post(
    "/bsim", status_code=202, response_model=SubmissionStatus,
    responses={200: {"description": "Identical retry"}},
)
async def submit_bsim(request: Request, response: Response, analyst: AnalystDep, conn: ConnDep):
    """Submit a signed BSim object and its function links (``relic-sign-challenge sign-bsim``).

    ``202`` staged; ``200`` identical retry; ``403`` not the caller; ``409``
    ID reused with another submission; ``422`` invalid.
    """
    payload, parsed = await _json_body(request)
    try:
        body = BsimSubmissionIn.model_validate(parsed)
    except ValidationError as error:
        raise _invalid(error) from error
    return await _stage(
        conn, response, kind="bsim", submission_id=body.bsim_id, analyst=analyst,
        claimed=body.analyst_id, payload=payload,
    )


@router.post(
    "/provenance", status_code=202, response_model=SubmissionStatus,
    responses={200: {"description": "Identical retry"}},
)
async def submit_provenance(
    request: Request, response: Response, analyst: AnalystDep, conn: ConnDep
):
    """Submit a signed provenance seal (``relic-sign-challenge sign-provenance``).

    ``202`` staged; ``200`` identical retry; ``403`` not the caller; ``409``
    ID reused with another submission; ``422`` invalid.
    """
    payload, parsed = await _json_body(request)
    try:
        body = ProvenanceSubmissionIn.model_validate(parsed)
    except ValidationError as error:
        raise _invalid(error) from error
    return await _stage(
        conn, response, kind="provenance", submission_id=body.provenance_id, analyst=analyst,
        claimed=body.analyst_id, payload=payload,
    )


@router.get("/submissions", response_model=list[SubmissionStatus])
async def list_submissions(
    identity: CurrentIdentity,
    conn: ConnDep,
    status: SubmissionState | None = None,
    after: UUID | None = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
):
    """The caller's own submissions, by ID; ``after`` pages."""
    cur = await conn.execute(
        f"""SELECT {_SUBMISSION_COLUMNS} FROM catalogue.submission
             WHERE analyst_id = %s
               AND (%s::catalogue.submission_status IS NULL
                    OR status = %s::catalogue.submission_status)
               AND (%s::uuid IS NULL OR submission_id > %s::uuid)
             ORDER BY submission_id LIMIT %s""",
        (identity.user_id, status, status, after, after, limit),
    )
    return [_status(row) for row in await cur.fetchall()]


@router.get("/submissions/{submission_id}", response_model=SubmissionStatus)
async def get_submission(submission_id: UUID, identity: CurrentIdentity, conn: ConnDep):
    """One submission's status: for its submitter, and for Moderators."""
    cur = await conn.execute(
        f"SELECT {_SUBMISSION_COLUMNS}, analyst_id FROM catalogue.submission"
        " WHERE submission_id = %s",
        (submission_id,),
    )
    row = await cur.fetchone()
    if row is None or (row["analyst_id"] != identity.user_id and identity.role != "moderator"):
        raise HTTPException(status_code=404, detail="Submission not found")
    return _status(row)
