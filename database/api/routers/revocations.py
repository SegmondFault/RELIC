from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends

from ..deps import current_identity
from ._stubs import todo

router = APIRouter(dependencies=[Depends(current_identity)], tags=["revocations"])


@router.post("/revocations", status_code=201)
async def request_revocation():
    todo()


@router.post("/revocations/{revocation_id}/decision")
async def decide_revocation(revocation_id: UUID):
    todo()
