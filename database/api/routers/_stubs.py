from __future__ import annotations

from fastapi import HTTPException


def todo() -> None:
    raise HTTPException(status_code=501, detail="Not implemented yet, come back later")
