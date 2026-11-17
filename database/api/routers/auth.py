from __future__ import annotations

from fastapi import APIRouter

from ._stubs import todo

router = APIRouter(tags=["auth"])


@router.post("/auth/login")
async def login():
    todo()


@router.get("/me")
async def me():
    todo()
