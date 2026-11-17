from __future__ import annotations

from fastapi import APIRouter

from ._stubs import todo

router = APIRouter(tags=["accounts"])


@router.post("/accounts", status_code=201)
async def create_account():
    todo()
