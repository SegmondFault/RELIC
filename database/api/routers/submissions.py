"""Signed corpus submissions by Analysts.

Licence assertions and classifications are independently signed claims: the
Analyst chooses the ID and signs the claim, the API verifies it with the
Analyst's registered key and stores it in one transaction. Neither takes an
integrity-chain entry. Both are immutable; a correction is a new claim plus a
revocation of the old one. An identical retry returns the stored row (200).

The remaining routes wait for decisions on integrity-key custody and object
storage.
"""

from __future__ import annotations

import logging
from typing import Annotated

from fastapi import APIRouter, Depends, Response

from ..crypto import (
    CLASSIFICATION_SIGNATURE_DOMAIN,
    LICENSE_ASSERTION_SIGNATURE_DOMAIN,
    Classification as SignedClassification,
    LicenseAssertion as SignedLicenseAssertion,
    classification_record,
    license_assertion_record,
)
from ..deps import ConnDep, Identity, current_identity, require_roles
from ..schemas import (
    ClassificationDetail,
    ClassificationSubmission,
    LicenseAssertion,
    LicenseAssertionSubmission,
)
from ._claims import admit, fields_match, verified_signature
from ._stubs import todo
from .catalogue import CLASSIFICATIONS, LICENSE_ASSERTIONS

AnalystDep = Annotated[Identity, Depends(require_roles("analyst"))]

router = APIRouter(dependencies=[Depends(current_identity)], tags=["submissions"])
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
# Waiting for integrity-key custody and object storage
# ---------------------------------------------------------------------------


@router.post("/sources", status_code=201)
async def submit_source():
    todo()


@router.post("/batches", status_code=201)
async def submit_batch():
    todo()


@router.post("/fidbf", status_code=201)
async def submit_fidbf():
    todo()


@router.post("/bsim", status_code=201)
async def submit_bsim():
    todo()


@router.post("/provenance", status_code=201)
async def submit_provenance():
    todo()
