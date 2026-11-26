"""Read-only catalogue routes. Every route requires an active account.

Lists use cursor paging: results are ordered by primary key, and the next
page is requested with ``after=<last id of this page>``. An empty page means
the end. There are no totals, because counting large tables would hit the
statement timeout.

Lists never include large JSON documents (BSim objects, provenance seals,
classification evidence); the single-object routes do. Internal storage
paths are never returned.
"""

from __future__ import annotations

import os
import re
import stat
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request
from fastapi.responses import StreamingResponse
from psycopg import sql

from ..deps import ConnDep, CurrentIdentity, SettingsDep, current_identity
from ..schemas import (
    Batch,
    BehaviouralComposition,
    BehaviouralCompositionDetail,
    Binary,
    BinaryComponentAssertion,
    Bsim,
    BsimDetail,
    Classification,
    ClassificationDetail,
    ClassificationTarget,
    Fidbf,
    Flag,
    FlagResponse,
    Function,
    FunctionBsim,
    IntegrityEntry,
    LicenseAssertion,
    Md5,
    MemberType,
    MmrCheckpoint,
    Provenance,
    ProvenanceDetail,
    Sha256,
    SoftwareComponent,
    SoftwareRelease,
    Source,
    TargetType,
    UserPublic,
)

# Every catalogue read requires an authenticated, non-revoked human account.
router = APIRouter(tags=["catalogue"], dependencies=[Depends(current_identity)])

Limit = Annotated[int, Query(ge=1, le=500)]
BIGINT_MAX = 2**63 - 1
IntCursor = Annotated[int | None, Query(ge=0, le=BIGINT_MAX)]

# ---------------------------------------------------------------------------
# Users (offset paging, unchanged)
# ---------------------------------------------------------------------------

_USER_COLUMNS = """
    SELECT user_id, role::text AS role, owner_type::text AS owner_type,
           encode(public_key, 'hex') AS public_key, created_at,
           catalogue.account_is_revoked(user_id) AS revoked
      FROM catalogue.user_public
"""


@router.get("/users", response_model=list[UserPublic])
async def list_users(
    conn: ConnDep,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0, le=1_000_000),
):
    """Public identities only: never names, email addresses or organisations."""
    cur = await conn.execute(
        _USER_COLUMNS + " ORDER BY created_at, user_id LIMIT %s OFFSET %s",
        (limit, offset),
    )
    return await cur.fetchall()


@router.get("/users/{user_id}", response_model=UserPublic)
async def get_user(user_id: UUID, conn: ConnDep):
    cur = await conn.execute(_USER_COLUMNS + " WHERE user_id = %s", (user_id,))
    row = await cur.fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="User not found")
    return row


# ---------------------------------------------------------------------------
# Shared query building
# ---------------------------------------------------------------------------


def _revoked(target_type: str, key: str) -> str:
    """Whether an approved revocation targets this exact row (constant SQL)."""
    return f"""EXISTS (
        SELECT 1 FROM catalogue.revocation AS r
         WHERE r.target_type = '{target_type}'
           AND r.target_id = t.{key}
           AND r.decision = 'approved'
    ) AS revoked"""


def _is_revoked(target_type: str, expression: str) -> str:
    """Whether an approved revocation targets the row ``expression`` names (constant SQL)."""
    return f"""EXISTS (
        SELECT 1 FROM catalogue.revocation AS r
         WHERE r.target_type = '{target_type}'
           AND r.target_id = {expression}
           AND r.decision = 'approved')"""


def _ancestor_revoked(*conditions: str) -> str:
    """Whether a row this one depends on is revoked: the row itself stays as stored."""
    return "(" + "\n        OR ".join(conditions) + ") AS ancestor_revoked"


_RELEASE_COMPONENT = (
    "(SELECT sr.component_id FROM catalogue.software_release AS sr"
    " WHERE sr.software_release_id = t.software_release_id)"
)

_REVOKED_COMPOSITION_MEMBER = """EXISTS (
            SELECT 1 FROM catalogue.composition_member AS am
              JOIN catalogue.revocation AS ar
                ON ar.target_type = am.target_type AND ar.target_id = am.target_id
               AND ar.decision = 'approved'
             WHERE am.behavioural_composition_id = t.behavioural_composition_id)"""


@dataclass(frozen=True)
class _Resource:
    table: str  # schema-qualified table, aliased as t
    key: str  # primary key column, also the cursor
    columns: str  # select list for lists and single rows (constant SQL)
    detail: str = ""  # extra columns for the single-object route only
    name: str = "Object"


@dataclass(frozen=True)
class _Filter:
    column: str
    value: Any
    cast: str | None = None  # e.g. an enum type, so the index stays usable


async def _list(
    conn: ConnDep,
    resource: _Resource,
    *,
    after: Any,
    limit: int,
    filters: Sequence[_Filter] = (),
    extra: tuple[str, Sequence[Any]] | None = None,
) -> list[dict]:
    """``extra`` is a constant SQL condition on ``t`` with its parameters."""
    clauses: list[sql.Composable] = []
    params: list[Any] = []
    if extra is not None:
        clauses.append(sql.SQL(extra[0]))
        params.extend(extra[1])
    for item in filters:
        if item.value is None:
            continue
        placeholder = sql.SQL("%s::{}").format(sql.SQL(item.cast)) if item.cast else sql.SQL("%s")
        clauses.append(sql.SQL("t.{} = {}").format(sql.Identifier(item.column), placeholder))
        params.append(item.value)
    if after is not None:
        clauses.append(sql.SQL("t.{} > %s").format(sql.Identifier(resource.key)))
        params.append(after)
    where = sql.SQL(" WHERE ") + sql.SQL(" AND ").join(clauses) if clauses else sql.SQL("")
    query = sql.SQL("SELECT {columns} FROM {table} AS t{where} ORDER BY t.{key} LIMIT %s").format(
        columns=sql.SQL(resource.columns),
        table=sql.SQL(resource.table),
        where=where,
        key=sql.Identifier(resource.key),
    )
    cur = await conn.execute(query, [*params, limit])
    return await cur.fetchall()


async def _get(conn: ConnDep, resource: _Resource, key: Any) -> dict:
    columns = resource.columns + (", " + resource.detail if resource.detail else "")
    query = sql.SQL("SELECT {columns} FROM {table} AS t WHERE t.{key} = %s").format(
        columns=sql.SQL(columns),
        table=sql.SQL(resource.table),
        key=sql.Identifier(resource.key),
    )
    cur = await conn.execute(query, (key,))
    row = await cur.fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail=f"{resource.name} not found")
    return row


# ---------------------------------------------------------------------------
# Resources
# ---------------------------------------------------------------------------

SOURCES = _Resource(
    table="catalogue.source",
    key="source_id",
    name="Source",
    columns=f"""t.source_id, t.name, t.source_type, t.reference, t.snapshot_version,
        t.retrieved_at, t.is_ecological, t.submitted_by_analyst_id,
        encode(t.signature, 'hex') AS signature, {_revoked('source', 'source_id')}""",
)

BATCHES = _Resource(
    table="catalogue.batch",
    key="batch_id",
    name="Batch",
    columns=f"""t.batch_id, t.md5, t.content_sha256, t.created_at, t.analyst_user_id,
        encode(t.signature, 'hex') AS signature, {_revoked('batch', 'batch_id')}""",
)

BINARIES = _Resource(
    table="catalogue.binary_record",
    key="binary_id",
    name="Binary",
    columns=f"""t.binary_id, t.batch_id, t.source_id, t.content_sha256, t.content_md5,
        t.size_bytes, t.original_filename, t.format, t.architecture, t.bit_width,
        t.endianness, t.platform, t.abi, t.object_type,
        t.entry_point::text AS entry_point, t.image_base::text AS image_base,
        t.build_id, t.is_stripped, t.compiler, t.version, t.created_at, t.created_by,
        {_revoked('binary', 'binary_id')}""",
)

FUNCTIONS = _Resource(
    table="catalogue.function_record",
    key="function_id",
    name="Function",
    columns=f"""t.function_id, t.binary_id, t.fidbf_id, t.name, t.full_hash, t.specific_hash,
        t.file_offset, t.virtual_address::text AS virtual_address, t.size_bytes,
        t.section_name, t.symbol_name, t.mangled_name, t.demangled_name,
        t.is_import, t.is_export, t.is_thunk, {_revoked('function', 'function_id')}""",
)

FIDBF = _Resource(
    table="catalogue.fidbf",
    key="fidbf_id",
    name="FIDBF object",
    columns=f"""t.fidbf_id, t.binary_id, t.source_id, t.sha256, t.md5, t.created_at,
        t.submitted_by_user_id, encode(t.signature, 'hex') AS signature,
        {_revoked('fidbf', 'fidbf_id')}""",
)

BSIM = _Resource(
    table="catalogue.bsim",
    key="bsim_id",
    name="BSim object",
    columns=f"""t.bsim_id, t.source_id, t.sha256, t.md5, t.created_at, t.submitted_by_user_id,
        encode(t.signature, 'hex') AS signature, {_revoked('bsim', 'bsim_id')}""",
    detail="t.object_data, t.object_json",
)

FUNCTION_BSIM = _Resource(
    table="catalogue.function_bsim",
    key="function_bsim_id",
    columns="t.function_bsim_id, t.function_id, t.binary_id, t.bsim_id, t.created_at",
)

PROVENANCE = _Resource(
    table="catalogue.provenance",
    key="provenance_id",
    name="Provenance",
    columns=f"""t.provenance_id, t.source_id, t.fidbf_id, t.bsim_id, t.binary_id,
        t.schema_name, t.schema_version, t.sha256, t.md5, t.created_at,
        t.submitted_by_user_id, encode(t.signature, 'hex') AS signature,
        (t.object_data IS NOT NULL) AS has_object_data,
        {_revoked('provenance', 'provenance_id')}""",
    detail="t.object_data, t.object_json",
)

LICENSE_ASSERTIONS = _Resource(
    table="catalogue.license_assertion",
    key="license_assertion_id",
    name="Licence assertion",
    columns=f"""t.license_assertion_id,
        CASE WHEN t.source_id IS NOT NULL THEN 'source' ELSE 'binary' END AS target_type,
        coalesce(t.source_id, t.binary_id) AS target_id, t.source_id, t.binary_id, t.spdx_expression,
        t.basis::text AS basis, t.confidence::text AS confidence, t.evidence_provenance_id,
        t.created_at, t.submitted_by_analyst_id, encode(t.signature, 'hex') AS signature,
        {_revoked('license_assertion', 'license_assertion_id')}""",
)

CLASSIFICATIONS = _Resource(
    table="catalogue.classification",
    key="classification_id",
    name="Classification",
    columns=f"""t.classification_id, t.target_type::text AS target_type, t.target_id, t.label,
        t.confidence::text AS confidence, t.analyst_id, t.misp_universe, t.misp_uuid,
        t.created_at, encode(t.signature, 'hex') AS signature,
        {_revoked('classification', 'classification_id')}""",
    detail="t.evidence, t.evidence_json",
)

SOFTWARE_COMPONENTS = _Resource(
    table="catalogue.software_component",
    key="component_id",
    name="Software component",
    columns=f"""t.component_id, t.name, t.component_kind, t.namespace, t.purl, t.created_at,
        t.created_by_analyst_id, encode(t.signature, 'hex') AS signature,
        {_revoked('software_component', 'component_id')}""",
)

SOFTWARE_RELEASES = _Resource(
    table="catalogue.software_release",
    key="software_release_id",
    name="Software release",
    columns=f"""t.software_release_id, t.component_id, t.version, t.source_id, t.created_at,
        t.created_by_analyst_id, encode(t.signature, 'hex') AS signature,
        {_revoked('software_release', 'software_release_id')},
        {_ancestor_revoked(
            _is_revoked('software_component', 't.component_id'),
            _is_revoked('source', 't.source_id'),
        )}""",
)

BINARY_COMPONENT_ASSERTIONS = _Resource(
    table="catalogue.binary_component_assertion",
    key="binary_component_assertion_id",
    name="Binary-component assertion",
    columns=f"""t.binary_component_assertion_id, t.binary_id, t.software_release_id,
        t.relationship::text AS relationship, t.basis::text AS basis,
        t.confidence::text AS confidence, t.evidence_provenance_id, t.created_at,
        t.submitted_by_analyst_id, encode(t.signature, 'hex') AS signature,
        {_revoked('binary_component_assertion', 'binary_component_assertion_id')},
        {_ancestor_revoked(
            _is_revoked('binary', 't.binary_id'),
            _is_revoked('software_release', 't.software_release_id'),
            _is_revoked('software_component', _RELEASE_COMPONENT),
            _is_revoked('provenance', 't.evidence_provenance_id'),
        )}""",
)

BEHAVIOURAL_COMPOSITIONS = _Resource(
    table="catalogue.behavioural_composition",
    key="behavioural_composition_id",
    name="Behavioural composition",
    columns=f"""t.behavioural_composition_id, t.name, t.description, t.evidence_provenance_id,
        t.member_count, t.created_at, t.submitted_by_analyst_id,
        encode(t.signature, 'hex') AS signature,
        {_revoked('behavioural_composition', 'behavioural_composition_id')},
        {_ancestor_revoked(
            _is_revoked('provenance', 't.evidence_provenance_id'),
            _REVOKED_COMPOSITION_MEMBER,
        )}""",
    detail="""coalesce((
        SELECT json_agg(json_build_object(
                   'target_type', m.target_type, 'target_id', m.target_id,
                   'member_role', m.member_role, 'sequence_number', m.sequence_number)
                 ORDER BY m.sequence_number NULLS LAST, m.target_type, m.target_id,
                          m.member_role)
          FROM catalogue.composition_member AS m
         WHERE m.behavioural_composition_id = t.behavioural_composition_id), '[]'::json)
        AS members""",
)

FLAGS = _Resource(
    table="catalogue.flag",
    key="flag_id",
    name="Flag",
    columns=f"""t.flag_id, t.viewer_request_id AS viewer_id, t.target_type::text AS target_type,
        t.target_id, t.note, t.created_at, encode(t.signature, 'hex') AS signature,
        {_revoked('flag', 'flag_id')}""",
)

FLAG_RESPONSES = _Resource(
    table="catalogue.flag_response",
    key="flag_response_id",
    name="Flag response",
    columns=f"""t.flag_response_id, t.flag_id, t.analyst_request_id AS analyst_id, t.note,
        t.created_at, encode(t.signature, 'hex') AS signature,
        {_revoked('flag_response', 'flag_response_id')}""",
)

INTEGRITY = _Resource(
    table="catalogue.integrity",
    key="integrity_id",
    name="Integrity entry",
    columns="""t.integrity_id, t.source_id, t.source_type, t.record_hash, t.prev_hash,
        t.chain_hash, t.format_version, t.created_at, t.system_uid,
        encode(t.system_signature, 'hex') AS system_signature""",
)

MMR_CHECKPOINTS = _Resource(
    table="catalogue.mmr_checkpoint",
    key="mmr_checkpoint_id",
    name="MMR checkpoint",
    columns="""t.mmr_checkpoint_id, t.last_integrity_id, t.leaf_count, t.peaks, t.commitment,
        t.format_version, t.created_at, t.system_uid,
        encode(t.system_signature, 'hex') AS system_signature""",
)

_TARGET_TYPE = "catalogue.corpus_target_type"

# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.get("/sources", response_model=list[Source])
async def list_sources(conn: ConnDep, after: UUID | None = None, limit: Limit = 100):
    return await _list(conn, SOURCES, after=after, limit=limit)


@router.get("/sources/{source_id}", response_model=Source)
async def get_source(source_id: UUID, conn: ConnDep):
    return await _get(conn, SOURCES, source_id)


@router.get("/batches", response_model=list[Batch])
async def list_batches(conn: ConnDep, after: UUID | None = None, limit: Limit = 100):
    return await _list(conn, BATCHES, after=after, limit=limit)


@router.get("/batches/{batch_id}", response_model=Batch)
async def get_batch(batch_id: UUID, conn: ConnDep):
    return await _get(conn, BATCHES, batch_id)


@router.get("/binaries", response_model=list[Binary])
async def list_binaries(
    conn: ConnDep,
    batch_id: UUID | None = None,
    source_id: UUID | None = None,
    sha256: Sha256 | None = None,
    md5: Md5 | None = None,
    after: UUID | None = None,
    limit: Limit = 100,
):
    filters = [
        _Filter("batch_id", batch_id),
        _Filter("source_id", source_id),
        _Filter("content_sha256", sha256),
        _Filter("content_md5", md5),
    ]
    return await _list(conn, BINARIES, after=after, limit=limit, filters=filters)


@router.get("/binaries/{binary_id}", response_model=Binary)
async def get_binary(binary_id: UUID, conn: ConnDep):
    return await _get(conn, BINARIES, binary_id)


@router.get("/functions", response_model=list[Function])
async def list_functions(
    conn: ConnDep,
    binary_id: UUID | None = None,
    fidbf_id: UUID | None = None,
    after: UUID | None = None,
    limit: Limit = 100,
):
    filters = [_Filter("binary_id", binary_id), _Filter("fidbf_id", fidbf_id)]
    return await _list(conn, FUNCTIONS, after=after, limit=limit, filters=filters)


@router.get("/functions/{function_id}", response_model=Function)
async def get_function(function_id: UUID, conn: ConnDep):
    return await _get(conn, FUNCTIONS, function_id)


@router.get("/fidbf", response_model=list[Fidbf])
async def list_fidbf(
    conn: ConnDep,
    binary_id: UUID | None = None,
    source_id: UUID | None = None,
    sha256: Sha256 | None = None,
    after: UUID | None = None,
    limit: Limit = 100,
):
    filters = [
        _Filter("binary_id", binary_id),
        _Filter("source_id", source_id),
        _Filter("sha256", sha256),
    ]
    return await _list(conn, FIDBF, after=after, limit=limit, filters=filters)


@router.get("/fidbf/{fidbf_id}", response_model=Fidbf)
async def get_fidbf(fidbf_id: UUID, conn: ConnDep):
    return await _get(conn, FIDBF, fidbf_id)


_CANONICAL_STORAGE = re.compile(r"[0-9a-f]{2}/([0-9a-f]{64})\.fidbf")
_CHUNK = 1 << 16


def _read_chunks(descriptor: int) -> Iterator[bytes]:
    try:
        while chunk := os.read(descriptor, _CHUNK):
            yield chunk
    finally:
        os.close(descriptor)


@router.get(
    "/fidbf/{fidbf_id}/download",
    response_class=StreamingResponse,
    responses={200: {"content": {"application/octet-stream": {}}}},
)
async def download_fidbf(
    fidbf_id: UUID,
    request: Request,
    identity: CurrentIdentity,
    conn: ConnDep,
    settings: SettingsDep,
):
    """The FIDBF object's exact bytes.

    ``X-Content-SHA256`` and ``X-Content-MD5`` carry the catalogue's digests
    (also in ``GET /v1/fidbf/{id}``) for the client to check. ``404`` for an
    unknown FIDBF or one admitted before the object store existed; ``410``
    once revoked (Moderators can still download it, to investigate);
    ``429`` past ``download_rate_limit_per_hour`` downloads by this account.
    """
    retry_after = request.app.state.rate_limiter.hit(
        "download", str(identity.user_id), settings.download_rate_limit_per_hour, 3600
    )
    if retry_after is not None:
        raise HTTPException(
            status_code=429, detail="Too many downloads",
            headers={"Retry-After": str(int(retry_after) + 1)},
        )
    cur = await conn.execute(
        f"SELECT storage_path, sha256::text AS sha256, md5::text AS md5,"
        f" {_revoked('fidbf', 'fidbf_id')} FROM catalogue.fidbf AS t WHERE fidbf_id = %s",
        (fidbf_id,),
    )
    row = await cur.fetchone()
    if row is not None and row["revoked"] and identity.role != "moderator":
        raise HTTPException(status_code=410, detail="FIDBF object has been revoked")
    match = _CANONICAL_STORAGE.fullmatch(row["storage_path"]) if row else None
    if match is None or match.group(1) != row["sha256"]:
        raise HTTPException(status_code=404, detail="FIDBF object not available")
    try:
        descriptor = os.open(settings.fidbf_root / row["storage_path"], os.O_RDONLY | os.O_NOFOLLOW)
    except OSError as error:
        raise HTTPException(status_code=404, detail="FIDBF object not available") from error
    info = os.fstat(descriptor)
    if not stat.S_ISREG(info.st_mode):
        os.close(descriptor)
        raise HTTPException(status_code=404, detail="FIDBF object not available")
    return StreamingResponse(
        _read_chunks(descriptor),
        media_type="application/octet-stream",
        headers={
            "Content-Length": str(info.st_size),
            "Content-Disposition": f'attachment; filename="{fidbf_id}.fidbf"',
            "ETag": f'"{row["sha256"]}"',
            "X-Content-SHA256": row["sha256"],
            "X-Content-MD5": row["md5"],
        },
    )


@router.get("/bsim", response_model=list[Bsim])
async def list_bsim(
    conn: ConnDep,
    source_id: UUID | None = None,
    sha256: Sha256 | None = None,
    after: UUID | None = None,
    limit: Limit = 100,
):
    filters = [_Filter("source_id", source_id), _Filter("sha256", sha256)]
    return await _list(conn, BSIM, after=after, limit=limit, filters=filters)


@router.get("/bsim/{bsim_id}", response_model=BsimDetail)
async def get_bsim(bsim_id: UUID, conn: ConnDep):
    return await _get(conn, BSIM, bsim_id)


@router.get("/function-bsim", response_model=list[FunctionBsim])
async def list_function_bsim(
    conn: ConnDep,
    function_id: UUID | None = None,
    binary_id: UUID | None = None,
    bsim_id: UUID | None = None,
    after: UUID | None = None,
    limit: Limit = 100,
):
    filters = [
        _Filter("function_id", function_id),
        _Filter("binary_id", binary_id),
        _Filter("bsim_id", bsim_id),
    ]
    return await _list(conn, FUNCTION_BSIM, after=after, limit=limit, filters=filters)


@router.get("/provenance", response_model=list[Provenance])
async def list_provenance(
    conn: ConnDep,
    source_id: UUID | None = None,
    fidbf_id: UUID | None = None,
    bsim_id: UUID | None = None,
    binary_id: UUID | None = None,
    after: UUID | None = None,
    limit: Limit = 100,
):
    filters = [
        _Filter("source_id", source_id),
        _Filter("fidbf_id", fidbf_id),
        _Filter("bsim_id", bsim_id),
        _Filter("binary_id", binary_id),
    ]
    return await _list(conn, PROVENANCE, after=after, limit=limit, filters=filters)


@router.get("/provenance/{provenance_id}", response_model=ProvenanceDetail)
async def get_provenance(provenance_id: UUID, conn: ConnDep):
    return await _get(conn, PROVENANCE, provenance_id)


@router.get("/license-assertions", response_model=list[LicenseAssertion])
async def list_license_assertions(
    conn: ConnDep,
    source_id: UUID | None = None,
    binary_id: UUID | None = None,
    after: UUID | None = None,
    limit: Limit = 100,
):
    filters = [_Filter("source_id", source_id), _Filter("binary_id", binary_id)]
    return await _list(conn, LICENSE_ASSERTIONS, after=after, limit=limit, filters=filters)


@router.get("/license-assertions/{license_assertion_id}", response_model=LicenseAssertion)
async def get_license_assertion(license_assertion_id: UUID, conn: ConnDep):
    return await _get(conn, LICENSE_ASSERTIONS, license_assertion_id)


@router.get("/classifications", response_model=list[Classification])
async def list_classifications(
    conn: ConnDep,
    target_type: ClassificationTarget | None = None,
    target_id: UUID | None = None,
    after: UUID | None = None,
    limit: Limit = 100,
):
    filters = [_Filter("target_type", target_type, _TARGET_TYPE), _Filter("target_id", target_id)]
    return await _list(conn, CLASSIFICATIONS, after=after, limit=limit, filters=filters)


@router.get("/classifications/{classification_id}", response_model=ClassificationDetail)
async def get_classification(classification_id: UUID, conn: ConnDep):
    return await _get(conn, CLASSIFICATIONS, classification_id)


@router.get("/software-components", response_model=list[SoftwareComponent])
async def list_software_components(
    conn: ConnDep,
    purl: Annotated[str | None, Query(max_length=1000)] = None,
    after: UUID | None = None,
    limit: Limit = 100,
):
    """``purl`` finds a component by its exact package URL."""
    filters = [_Filter("purl", purl)]
    return await _list(conn, SOFTWARE_COMPONENTS, after=after, limit=limit, filters=filters)


@router.get("/software-components/{component_id}", response_model=SoftwareComponent)
async def get_software_component(component_id: UUID, conn: ConnDep):
    return await _get(conn, SOFTWARE_COMPONENTS, component_id)


@router.get("/software-releases", response_model=list[SoftwareRelease])
async def list_software_releases(
    conn: ConnDep,
    component_id: UUID | None = None,
    source_id: UUID | None = None,
    after: UUID | None = None,
    limit: Limit = 100,
):
    filters = [_Filter("component_id", component_id), _Filter("source_id", source_id)]
    return await _list(conn, SOFTWARE_RELEASES, after=after, limit=limit, filters=filters)


@router.get("/software-releases/{software_release_id}", response_model=SoftwareRelease)
async def get_software_release(software_release_id: UUID, conn: ConnDep):
    return await _get(conn, SOFTWARE_RELEASES, software_release_id)


@router.get("/binary-component-assertions", response_model=list[BinaryComponentAssertion])
async def list_binary_component_assertions(
    conn: ConnDep,
    binary_id: UUID | None = None,
    software_release_id: UUID | None = None,
    after: UUID | None = None,
    limit: Limit = 100,
):
    filters = [
        _Filter("binary_id", binary_id),
        _Filter("software_release_id", software_release_id),
    ]
    return await _list(
        conn, BINARY_COMPONENT_ASSERTIONS, after=after, limit=limit, filters=filters
    )


@router.get(
    "/binary-component-assertions/{binary_component_assertion_id}",
    response_model=BinaryComponentAssertion,
)
async def get_binary_component_assertion(binary_component_assertion_id: UUID, conn: ConnDep):
    return await _get(conn, BINARY_COMPONENT_ASSERTIONS, binary_component_assertion_id)


_HAS_MEMBER = """EXISTS (
    SELECT 1 FROM catalogue.composition_member AS m
     WHERE m.behavioural_composition_id = t.behavioural_composition_id
       AND m.target_type = %s::catalogue.corpus_target_type AND m.target_id = %s)"""


@router.get("/behavioural-compositions", response_model=list[BehaviouralComposition])
async def list_behavioural_compositions(
    conn: ConnDep,
    member_type: MemberType | None = None,
    member_id: UUID | None = None,
    after: UUID | None = None,
    limit: Limit = 100,
):
    """``member_type`` with ``member_id`` lists the compositions containing that binary or function."""
    if (member_type is None) != (member_id is None):
        raise HTTPException(
            status_code=422, detail="member_type and member_id are given together or not at all"
        )
    extra = (_HAS_MEMBER, (member_type, member_id)) if member_id is not None else None
    return await _list(conn, BEHAVIOURAL_COMPOSITIONS, after=after, limit=limit, extra=extra)


@router.get(
    "/behavioural-compositions/{behavioural_composition_id}",
    response_model=BehaviouralCompositionDetail,
)
async def get_behavioural_composition(behavioural_composition_id: UUID, conn: ConnDep):
    return await _get(conn, BEHAVIOURAL_COMPOSITIONS, behavioural_composition_id)


@router.get("/flags", response_model=list[Flag])
async def list_flags(
    conn: ConnDep,
    target_type: TargetType | None = None,
    target_id: UUID | None = None,
    after: UUID | None = None,
    limit: Limit = 100,
):
    filters = [_Filter("target_type", target_type, _TARGET_TYPE), _Filter("target_id", target_id)]
    return await _list(conn, FLAGS, after=after, limit=limit, filters=filters)


@router.get("/flags/{flag_id}", response_model=Flag)
async def get_flag(flag_id: UUID, conn: ConnDep):
    return await _get(conn, FLAGS, flag_id)


@router.get("/flag-responses", response_model=list[FlagResponse])
async def list_flag_responses(
    conn: ConnDep,
    flag_id: UUID | None = None,
    after: UUID | None = None,
    limit: Limit = 100,
):
    return await _list(
        conn, FLAG_RESPONSES, after=after, limit=limit, filters=[_Filter("flag_id", flag_id)]
    )


@router.get("/flag-responses/{flag_response_id}", response_model=FlagResponse)
async def get_flag_response(flag_response_id: UUID, conn: ConnDep):
    return await _get(conn, FLAG_RESPONSES, flag_response_id)


# /revocations and /revocations/{id} are served by routers/revocations.py.


@router.get("/integrity", response_model=list[IntegrityEntry])
async def list_integrity(
    conn: ConnDep,
    source_id: UUID | None = None,
    after: IntCursor = None,
    limit: Limit = 100,
):
    """The integrity chain in insertion order (``integrity_id`` ascending)."""
    filters = [_Filter("source_id", source_id)]
    return await _list(conn, INTEGRITY, after=after, limit=limit, filters=filters)


@router.get("/integrity/{integrity_id}", response_model=IntegrityEntry)
async def get_integrity(integrity_id: Annotated[int, Path(ge=1, le=BIGINT_MAX)], conn: ConnDep):
    return await _get(conn, INTEGRITY, integrity_id)


@router.get("/mmr-checkpoints", response_model=list[MmrCheckpoint])
async def list_mmr_checkpoints(
    conn: ConnDep,
    after: IntCursor = None,
    limit: Limit = 100,
):
    return await _list(conn, MMR_CHECKPOINTS, after=after, limit=limit)


@router.get("/mmr-checkpoints/latest", response_model=MmrCheckpoint)
async def latest_mmr_checkpoint(conn: ConnDep):
    """The checkpoint covering the most integrity rows."""
    cur = await conn.execute(
        f"""SELECT {MMR_CHECKPOINTS.columns} FROM catalogue.mmr_checkpoint AS t
             ORDER BY t.leaf_count DESC, t.mmr_checkpoint_id DESC LIMIT 1"""
    )
    row = await cur.fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="No MMR checkpoint yet")
    return row


@router.get("/mmr-checkpoints/{mmr_checkpoint_id}", response_model=MmrCheckpoint)
async def get_mmr_checkpoint(
    mmr_checkpoint_id: Annotated[int, Path(ge=1, le=BIGINT_MAX)], conn: ConnDep
):
    return await _get(conn, MMR_CHECKPOINTS, mmr_checkpoint_id)
