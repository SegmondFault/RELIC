"""Signed software components, releases, binary-component assertions and
behavioural compositions, written by Analysts.

Like licence assertions, each row is chosen, signed and owned by one Analyst:
the API verifies the signature with the Analyst's registered key and stores
the row; an identical retry returns it (``200``). Rows are immutable and take
no integrity-chain entry; a correction is a new row plus a revocation.

A behavioural composition is signed together with all its members and is
written with them in one transaction; the database refuses members added
later.
"""

from __future__ import annotations

import logging
from typing import Annotated

from fastapi import APIRouter, Depends, Response

from ..crypto import (
    BEHAVIOURAL_COMPOSITION_SIGNATURE_DOMAIN,
    BINARY_COMPONENT_ASSERTION_SIGNATURE_DOMAIN,
    SOFTWARE_COMPONENT_SIGNATURE_DOMAIN,
    SOFTWARE_RELEASE_SIGNATURE_DOMAIN,
    BehaviouralComposition as SignedComposition,
    BinaryComponentAssertion as SignedAssertion,
    CompositionMember as SignedMember,
    SoftwareComponent as SignedComponent,
    SoftwareRelease as SignedRelease,
    behavioural_composition_record,
    binary_component_assertion_record,
    software_component_record,
    software_release_record,
)
from ..deps import ConnDep, Identity, current_identity, require_roles
from ..schemas import (
    BehaviouralCompositionDetail,
    BehaviouralCompositionSubmission,
    BinaryComponentAssertion,
    BinaryComponentAssertionSubmission,
    SoftwareComponent,
    SoftwareComponentSubmission,
    SoftwareRelease,
    SoftwareReleaseSubmission,
)
from ._claims import admit, fields_match, verified_signature
from .catalogue import (
    BEHAVIOURAL_COMPOSITIONS,
    BINARY_COMPONENT_ASSERTIONS,
    SOFTWARE_COMPONENTS,
    SOFTWARE_RELEASES,
)

AnalystDep = Annotated[Identity, Depends(require_roles("analyst"))]

router = APIRouter(dependencies=[Depends(current_identity)], tags=["components"])
audit = logging.getLogger("relic.audit")


def _select(resource, *, detail: bool = False) -> str:
    columns = resource.columns + (", " + resource.detail if detail else "")
    return f"SELECT {columns} FROM {resource.table} AS t WHERE t.{resource.key} = %s"


# ---------------------------------------------------------------------------
# Software components
# ---------------------------------------------------------------------------

_COMPONENT_SELECT = _select(SOFTWARE_COMPONENTS)
_COMPONENT_INSERT = f"""
    INSERT INTO catalogue.software_component AS t
        (component_id, name, component_kind, namespace, purl, created_by_analyst_id, signature)
    VALUES (%s, %s, %s, %s, %s, %s, %s)
    RETURNING {SOFTWARE_COMPONENTS.columns}
"""


@router.post("/software-components", status_code=201, response_model=SoftwareComponent)
async def submit_software_component(
    body: SoftwareComponentSubmission, response: Response, analyst: AnalystDep, conn: ConnDep
):
    """Name a software component (library, application, runtime...), signed.

    It identifies software; it claims nothing about any binary. ``201``
    created; ``200`` identical retry; ``403`` bad signature or not the caller;
    ``409`` ID reused with other content.
    """
    record = software_component_record(
        SignedComponent(
            component_id=body.component_id,
            analyst_id=body.analyst_id,
            name=body.name,
            component_kind=body.component_kind,
            namespace=body.namespace,
            purl=body.purl,
        )
    )

    async def insert() -> dict:
        cur = await conn.execute(
            _COMPONENT_INSERT,
            (body.component_id, body.name, body.component_kind, body.namespace, body.purl,
             body.analyst_id, signature),
        )
        return await cur.fetchone()

    async with conn.transaction():
        signature = await verified_signature(
            conn, analyst, body.analyst_id, SOFTWARE_COMPONENT_SIGNATURE_DOMAIN, record,
            body.signature, "software component",
        )
        row = await admit(
            conn, response, select=_COMPONENT_SELECT, key=body.component_id, insert=insert,
            id_field="component_id", what="software component",
            same=lambda row: fields_match(row, {
                "signature": body.signature,
                "created_by_analyst_id": body.analyst_id,
                "name": body.name,
                "component_kind": body.component_kind,
                "namespace": body.namespace,
                "purl": body.purl,
            }),
        )
    audit.info("software component id=%s analyst=%s", body.component_id, body.analyst_id)
    return row


# ---------------------------------------------------------------------------
# Software releases
# ---------------------------------------------------------------------------

_RELEASE_SELECT = _select(SOFTWARE_RELEASES)
_RELEASE_INSERT = f"""
    INSERT INTO catalogue.software_release AS t
        (software_release_id, component_id, version, source_id, created_by_analyst_id, signature)
    VALUES (%s, %s, %s, %s, %s, %s)
    RETURNING {SOFTWARE_RELEASES.columns}
"""


@router.post("/software-releases", status_code=201, response_model=SoftwareRelease)
async def submit_software_release(
    body: SoftwareReleaseSubmission, response: Response, analyst: AnalystDep, conn: ConnDep
):
    """Name a release of a component, optionally with its version and source (signed).

    ``201`` created; ``200`` identical retry; ``403`` bad signature or not the
    caller; ``409`` ID reused with other content, or the component or source
    is revoked; ``422`` unknown component or source.
    """
    record = software_release_record(
        SignedRelease(
            software_release_id=body.software_release_id,
            analyst_id=body.analyst_id,
            component_id=body.component_id,
            version=body.version,
            source_id=body.source_id,
        )
    )

    async def insert() -> dict:
        cur = await conn.execute(
            _RELEASE_INSERT,
            (body.software_release_id, body.component_id, body.version, body.source_id,
             body.analyst_id, signature),
        )
        return await cur.fetchone()

    async with conn.transaction():
        signature = await verified_signature(
            conn, analyst, body.analyst_id, SOFTWARE_RELEASE_SIGNATURE_DOMAIN, record,
            body.signature, "software release",
        )
        row = await admit(
            conn, response, select=_RELEASE_SELECT, key=body.software_release_id,
            insert=insert, id_field="software_release_id", what="software release",
            same=lambda row: fields_match(row, {
                "signature": body.signature,
                "created_by_analyst_id": body.analyst_id,
                "component_id": body.component_id,
                "version": body.version,
                "source_id": body.source_id,
            }),
        )
    audit.info(
        "software release id=%s component=%s analyst=%s",
        body.software_release_id, body.component_id, body.analyst_id,
    )
    return row


# ---------------------------------------------------------------------------
# Binary-component assertions
# ---------------------------------------------------------------------------

_ASSERTION_SELECT = _select(BINARY_COMPONENT_ASSERTIONS)
_ASSERTION_INSERT = f"""
    INSERT INTO catalogue.binary_component_assertion AS t
        (binary_component_assertion_id, binary_id, software_release_id, relationship, basis,
         confidence, evidence_provenance_id, submitted_by_analyst_id, signature)
    VALUES (%s, %s, %s, %s::catalogue.binary_component_relationship,
            %s::catalogue.component_assertion_basis, %s::numeric, %s, %s, %s)
    RETURNING {BINARY_COMPONENT_ASSERTIONS.columns}
"""


@router.post(
    "/binary-component-assertions", status_code=201, response_model=BinaryComponentAssertion
)
async def submit_binary_component_assertion(
    body: BinaryComponentAssertionSubmission,
    response: Response,
    analyst: AnalystDep,
    conn: ConnDep,
):
    """Claim how a binary relates to a software release (signed).

    ``201`` created; ``200`` identical retry; ``403`` bad signature or not the
    caller; ``409`` ID reused with other content, or the binary, release or
    its component is revoked; ``422`` unknown binary, release or evidence.
    """
    record = binary_component_assertion_record(
        SignedAssertion(
            binary_component_assertion_id=body.binary_component_assertion_id,
            analyst_id=body.analyst_id,
            binary_id=body.binary_id,
            software_release_id=body.software_release_id,
            relationship=body.relationship,
            basis=body.basis,
            confidence=body.confidence,
            evidence_provenance_id=body.evidence_provenance_id,
        )
    )

    async def insert() -> dict:
        cur = await conn.execute(
            _ASSERTION_INSERT,
            (body.binary_component_assertion_id, body.binary_id, body.software_release_id,
             body.relationship, body.basis, body.confidence, body.evidence_provenance_id,
             body.analyst_id, signature),
        )
        return await cur.fetchone()

    async with conn.transaction():
        signature = await verified_signature(
            conn, analyst, body.analyst_id, BINARY_COMPONENT_ASSERTION_SIGNATURE_DOMAIN, record,
            body.signature, "binary-component assertion",
        )
        row = await admit(
            conn, response, select=_ASSERTION_SELECT, key=body.binary_component_assertion_id,
            insert=insert, id_field="binary_component_assertion_id",
            what="binary-component assertion",
            same=lambda row: fields_match(row, {
                "signature": body.signature,
                "submitted_by_analyst_id": body.analyst_id,
                "binary_id": body.binary_id,
                "software_release_id": body.software_release_id,
                "relationship": body.relationship,
                "basis": body.basis,
                "confidence": body.confidence,
                "evidence_provenance_id": body.evidence_provenance_id,
            }),
        )
    audit.info(
        "binary-component assertion id=%s binary=%s release=%s analyst=%s",
        body.binary_component_assertion_id, body.binary_id, body.software_release_id,
        body.analyst_id,
    )
    return row


# ---------------------------------------------------------------------------
# Behavioural compositions
# ---------------------------------------------------------------------------

_COMPOSITION_SELECT = _select(BEHAVIOURAL_COMPOSITIONS, detail=True)
_COMPOSITION_INSERT = """
    INSERT INTO catalogue.behavioural_composition
        (behavioural_composition_id, name, description, evidence_provenance_id, member_count,
         submitted_by_analyst_id, signature)
    VALUES (%s, %s, %s, %s, %s, %s, %s)
"""
_MEMBER_INSERT = """
    INSERT INTO catalogue.composition_member
        (behavioural_composition_id, target_type, target_id, member_role, sequence_number)
    VALUES (%s, %s::catalogue.corpus_target_type, %s, %s, %s)
"""


def _member_set(members) -> set[tuple[str, str, str, int | None]]:
    return {
        (m["target_type"], str(m["target_id"]), m["member_role"], m["sequence_number"])
        for m in members
    }


@router.post(
    "/behavioural-compositions", status_code=201, response_model=BehaviouralCompositionDetail
)
async def submit_behavioural_composition(
    body: BehaviouralCompositionSubmission,
    response: Response,
    analyst: AnalystDep,
    conn: ConnDep,
):
    """Define a set or sequence of binaries and functions, all members signed together.

    The composition and its members are written in one transaction, and the
    database refuses members added later. ``201`` created; ``200`` identical
    retry; ``403`` bad signature or not the caller; ``409`` ID reused with
    other content, or a member is revoked; ``422`` unknown member or evidence.
    """
    members = tuple(
        SignedMember(
            target_type=m.target_type,
            target_id=m.target_id,
            member_role=m.member_role,
            sequence_number=m.sequence_number,
        )
        for m in body.members
    )
    record = behavioural_composition_record(
        SignedComposition(
            behavioural_composition_id=body.behavioural_composition_id,
            analyst_id=body.analyst_id,
            name=body.name,
            description=body.description,
            evidence_provenance_id=body.evidence_provenance_id,
            members=members,
        )
    )

    async def insert() -> dict:
        key = body.behavioural_composition_id
        await conn.execute(
            _COMPOSITION_INSERT,
            (key, body.name, body.description, body.evidence_provenance_id, len(members),
             body.analyst_id, signature),
        )
        async with conn.cursor() as cur:
            await cur.executemany(
                _MEMBER_INSERT,
                [(key, m.target_type, m.target_id, m.member_role, m.sequence_number)
                 for m in members],
            )
        cur = await conn.execute(_COMPOSITION_SELECT, (key,))
        return await cur.fetchone()

    async with conn.transaction():
        signature = await verified_signature(
            conn, analyst, body.analyst_id, BEHAVIOURAL_COMPOSITION_SIGNATURE_DOMAIN, record,
            body.signature, "behavioural composition",
        )
        row = await admit(
            conn, response, select=_COMPOSITION_SELECT, key=body.behavioural_composition_id,
            insert=insert, id_field="behavioural_composition_id",
            what="behavioural composition",
            same=lambda row: fields_match(row, {
                "signature": body.signature,
                "submitted_by_analyst_id": body.analyst_id,
                "name": body.name,
                "description": body.description,
                "evidence_provenance_id": body.evidence_provenance_id,
            }) and _member_set(row["members"]) == _member_set(m.model_dump() for m in body.members),
        )
    audit.info(
        "behavioural composition id=%s members=%d analyst=%s",
        body.behavioural_composition_id, len(members), body.analyst_id,
    )
    return row
