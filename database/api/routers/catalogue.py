from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query

from ..deps import ConnDep, current_identity
from ..schemas import UserPublic
from ._stubs import todo

# Every catalogue read requires an authenticated, non-revoked human account.
router = APIRouter(tags=["catalogue"], dependencies=[Depends(current_identity)])

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


@router.get("/sources")
async def list_sources(limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0)):
    todo()


@router.get("/sources/{source_id}")
async def get_source(source_id: UUID):
    todo()


@router.get("/batches")
async def list_batches(limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0)):
    todo()


@router.get("/batches/{batch_id}")
async def get_batch(batch_id: UUID):
    todo()


@router.get("/binaries")
async def list_binaries(limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0)):
    todo()


@router.get("/binaries/{binary_id}")
async def get_binary(binary_id: UUID):
    todo()


@router.get("/functions")
async def list_functions(limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0)):
    todo()


@router.get("/functions/{function_id}")
async def get_function(function_id: UUID):
    todo()


@router.get("/fidbf")
async def list_fidbf(limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0)):
    todo()


@router.get("/fidbf/{fidbf_id}")
async def get_fidbf(fidbf_id: UUID):
    todo()


@router.get("/fidbf/{fidbf_id}/download")
async def download_fidbf(fidbf_id: UUID):
    todo()


@router.get("/bsim")
async def list_bsim(limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0)):
    todo()


@router.get("/bsim/{bsim_id}")
async def get_bsim(bsim_id: UUID):
    todo()


@router.get("/function-bsim")
async def list_function_bsim(limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0)):
    todo()


@router.get("/provenance")
async def list_provenance(limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0)):
    todo()


@router.get("/provenance/{provenance_id}")
async def get_provenance(provenance_id: UUID):
    todo()


@router.get("/license-assertions")
async def list_license_assertions(limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0)):
    todo()


@router.get("/license-assertions/{license_assertion_id}")
async def get_license_assertion(license_assertion_id: UUID):
    todo()


@router.get("/classifications")
async def list_classifications(limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0)):
    todo()


@router.get("/classifications/{classification_id}")
async def get_classification(classification_id: UUID):
    todo()


@router.get("/flags")
async def list_flags(limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0)):
    todo()


@router.get("/flags/{flag_id}")
async def get_flag(flag_id: UUID):
    todo()


@router.get("/flag-responses")
async def list_flag_responses(limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0)):
    todo()


# /revocations and /revocations/{id} are served by routers/revocations.py.


@router.get("/integrity")
async def list_integrity(limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0)):
    todo()


@router.get("/integrity/{integrity_id}")
async def get_integrity(integrity_id: int):
    todo()


@router.get("/mmr-checkpoints")
async def list_mmr_checkpoints(limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0)):
    todo()


@router.get("/mmr-checkpoints/latest")
async def latest_mmr_checkpoint():
    todo()


@router.get("/mmr-checkpoints/{mmr_checkpoint_id}")
async def get_mmr_checkpoint(mmr_checkpoint_id: int):
    todo()
