"""Inclusion proofs: show that an integrity row is covered by a signed MMR checkpoint.

The proof is built from the integrity chain and checked against the stored,
signed checkpoint before it is returned, so the API never serves a proof the
checkpoint would not accept.
"""

from __future__ import annotations

import logging
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request
from starlette.concurrency import run_in_threadpool

from .. import mmr
from ..deps import ConnDep, CurrentIdentity, SettingsDep, current_identity
from ..schemas import MmrInclusionProof
from .catalogue import BIGINT_MAX, MMR_CHECKPOINTS

router = APIRouter(dependencies=[Depends(current_identity)], tags=["integrity proofs"])
log = logging.getLogger("relic.api")

# The checkpoint format whose leaves and nodes `mmr.py` knows how to hash.
SUPPORTED_CHECKPOINT_FORMAT = 1


@router.get("/integrity/{integrity_id}/proof", response_model=MmrInclusionProof)
async def get_inclusion_proof(
    integrity_id: Annotated[int, Path(ge=1, le=BIGINT_MAX)],
    request: Request,
    conn: ConnDep,
    settings: SettingsDep,
    identity: CurrentIdentity,
    checkpoint_id: Annotated[
        int | None,
        Query(ge=1, le=BIGINT_MAX, description="Default: the newest checkpoint"),
    ] = None,
):
    """Proof that an integrity row is covered by a signed MMR checkpoint.

    The client takes the checkpoint from ``GET /v1/mmr-checkpoints/{id}``,
    verifies its system signature, and checks that the proof leads from the
    row's ``chain_hash`` to one of the checkpoint's peaks.

    ``404`` unknown entry or checkpoint; ``409`` the entry is not covered yet
    (or not by that checkpoint); ``429`` too many proofs requested by this
    account; ``501`` the checkpoint uses a format this server cannot prove;
    ``503`` the entry sits in a peak too large to prove on demand.
    """
    retry_after = request.app.state.rate_limiter.hit(
        "proof", str(identity.user_id), settings.proof_rate_limit_per_minute, 60
    )
    if retry_after is not None:
        raise HTTPException(
            status_code=429,
            detail="Too many proofs requested",
            headers={"Retry-After": str(int(retry_after) + 1)},
        )

    cur = await conn.execute(
        """SELECT chain_hash::text AS chain_hash,
                  (SELECT count(*) FROM catalogue.integrity AS earlier
                    WHERE earlier.integrity_id < entry.integrity_id) AS leaf_index
             FROM catalogue.integrity AS entry
            WHERE entry.integrity_id = %s""",
        (integrity_id,),
    )
    entry = await cur.fetchone()
    if entry is None:
        raise HTTPException(status_code=404, detail="Integrity entry not found")
    leaf_index: int = entry["leaf_index"]

    if checkpoint_id is None:
        cur = await conn.execute(
            f"""SELECT {MMR_CHECKPOINTS.columns} FROM catalogue.mmr_checkpoint AS t
                 ORDER BY t.leaf_count DESC, t.mmr_checkpoint_id DESC LIMIT 1"""
        )
    else:
        cur = await conn.execute(
            f"""SELECT {MMR_CHECKPOINTS.columns} FROM catalogue.mmr_checkpoint AS t
                 WHERE t.mmr_checkpoint_id = %s""",
            (checkpoint_id,),
        )
    checkpoint = await cur.fetchone()
    if checkpoint is None:
        if checkpoint_id is not None:
            raise HTTPException(status_code=404, detail="MMR checkpoint not found")
        raise HTTPException(status_code=409, detail="No MMR checkpoint covers this entry yet")
    leaf_count: int = checkpoint["leaf_count"]
    if leaf_index >= leaf_count:
        detail = (
            f"MMR checkpoint {checkpoint['mmr_checkpoint_id']} covers only the first "
            f"{leaf_count} integrity entries"
            if checkpoint_id is not None
            else "No MMR checkpoint covers this entry yet"
        )
        raise HTTPException(status_code=409, detail=detail)
    if checkpoint["format_version"] != SUPPORTED_CHECKPOINT_FORMAT:
        raise HTTPException(
            status_code=501,
            detail=f"Checkpoint format {checkpoint['format_version']} cannot be proven here",
        )

    try:
        start, height = mmr.locate_peak(leaf_index, leaf_count)
    except mmr.ProofError as error:
        log.error("inclusion proof: %s", error)
        raise _unverifiable() from error
    if 1 << height > settings.proof_max_peak_leaves:
        raise HTTPException(
            status_code=503,
            detail=f"The entry is in a peak of {1 << height} entries, too large to prove on demand",
        )

    # The chain in leaf order. The result is checked against the signed
    # checkpoint below, so a wrong ordering can only produce a refusal.
    cur = await conn.execute(
        "SELECT chain_hash::text AS chain_hash FROM catalogue.integrity"
        " ORDER BY integrity_id OFFSET %s LIMIT %s",
        (start, 1 << height),
    )
    window = [bytes.fromhex(row["chain_hash"]) for row in await cur.fetchall()]

    try:
        siblings = await run_in_threadpool(_prove, window, start, height, leaf_index, checkpoint)
    except mmr.ProofError as error:
        log.error(
            "inclusion proof refused entry=%s checkpoint=%s: %s",
            integrity_id,
            checkpoint["mmr_checkpoint_id"],
            error,
        )
        raise _unverifiable() from error

    return MmrInclusionProof(
        integrity_id=integrity_id,
        chain_hash=entry["chain_hash"],
        mmr_checkpoint_id=checkpoint["mmr_checkpoint_id"],
        leaf_count=leaf_count,
        commitment=checkpoint["commitment"],
        proof=mmr.encode_proof(leaf_index, leaf_count, siblings),
    )


def _prove(
    window: list[bytes], start: int, height: int, leaf_index: int, checkpoint: dict
) -> list[bytes]:
    """Build the proof and check it against the stored checkpoint's peaks."""
    siblings, _ = mmr.prove(window, start, height, leaf_index)
    chain_hash = window[leaf_index - start]
    recomputed = mmr.recompute_peak(leaf_index, checkpoint["leaf_count"], siblings, chain_hash)
    peaks = mmr.parse_peaks(checkpoint["peaks"])
    if not mmr.checkpoint_holds(peaks, checkpoint["leaf_count"], recomputed):
        raise mmr.ProofError("the proof does not lead to a peak of the stored checkpoint")
    return siblings


def _unverifiable() -> HTTPException:
    # Never serve a proof the checkpoint would reject; the detail is logged,
    # not returned, because it describes the integrity of the chain itself.
    return HTTPException(
        status_code=500, detail="The proof could not be verified against the checkpoint"
    )
