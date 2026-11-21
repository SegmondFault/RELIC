from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends

from ..deps import current_identity
from ._stubs import todo

router = APIRouter(dependencies=[Depends(current_identity)], tags=["flags"])


@router.post("/flags", status_code=201)
async def submit_flag():
    todo()


@router.post("/flags/{flag_id}/responses", status_code=201)
async def respond_to_flag(flag_id: UUID):
    todo()
