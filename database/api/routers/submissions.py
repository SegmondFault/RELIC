from __future__ import annotations

from fastapi import APIRouter, Depends

from ..deps import current_identity
from ._stubs import todo

router = APIRouter(dependencies=[Depends(current_identity)], tags=["submissions"])


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


@router.post("/license-assertions", status_code=201)
async def submit_license_assertion():
    todo()


@router.post("/classifications", status_code=201)
async def submit_classification():
    todo()
