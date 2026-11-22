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

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Path, Query
from psycopg import sql

from ..deps import ConnDep, current_identity
from ..schemas import (
    Batch,
    Binary,
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
    MmrCheckpoint,
    Provenance,
    ProvenanceDetail,
    Sha256,
    Source,
    TargetType,
    UserPublic,
)
from ._stubs import todo

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
    conn: ConnDep, resource: _Resource, *, after: Any, limit: int, filters: Sequence[_Filter] = ()
) -> list[dict]:
    clauses: list[sql.Composable] = []
    params: list[Any] = []
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
    detail="t.object_data",
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
    detail="t.object_data",
)

LICENSE_ASSERTIONS = _Resource(
    table="catalogue.license_assertion",
    key="license_assertion_id",
    name="Licence assertion",
    columns=f"""t.license_assertion_id, t.source_id, t.binary_id, t.spdx_expression,
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
    detail="t.evidence",
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


@router.get("/fidbf/{fidbf_id}/download")
async def download_fidbf(fidbf_id: UUID):
    # Waits for the object-storage design.
    todo()


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
