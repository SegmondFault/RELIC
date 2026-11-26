"""Inclusion proofs: show that an integrity row is covered by a signed MMR checkpoint.

The proof is built from the integrity chain and checked against the stored,
signed checkpoint before it is returned, so the API never serves a proof the
checkpoint would not accept.

Leaf order. A leaf's index is its position on the chain followed from the
genesis row through ``prev_hash``, which is how the checkpoint worker reads
the chain. This route uses ``integrity_id`` order instead, which an index
serves cheaply; migration 009 makes the two the same by refusing any entry
that does not extend the entry with the highest id below its own. The entry
is still checked to be at its leaf index before a proof is built.
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
        Query(
            ge=1,
            le=BIGINT_MAX,
            description="Default: the newest checkpoint in the format this server proves",
        ),
    ] = None,
):
    """Proof that an integrity row is covered by a signed MMR checkpoint.

    The client takes the checkpoint from ``GET /v1/mmr-checkpoints/{id}`` and
    the entry from ``GET /v1/integrity/{id}``, verifies the checkpoint's system
    signature with a pinned key, recomputes the entry's ``chain_hash`` from its
    fields, and checks that the proof leads from that hash to one of the
    checkpoint's peaks (``relic-verify-proof --entry``).

    ``404`` unknown entry or checkpoint; ``409`` the entry is not covered yet
    (or not by that checkpoint); ``429`` too many proofs requested by this
    account; ``501`` the checkpoint uses a format this server cannot prove;
    ``503`` the entry sits in a peak too large to prove on demand (the detail
    names an older checkpoint that can prove it, when one exists), or too many
    proofs are being built at this moment (with ``Retry-After``).
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
        # Only checkpoints this server can prove: a newer format must not hide
        # the valid ones of the format it knows.
        cur = await conn.execute(
            f"""SELECT {MMR_CHECKPOINTS.columns} FROM catalogue.mmr_checkpoint AS t
                 WHERE t.format_version = %s
                 ORDER BY t.leaf_count DESC, t.mmr_checkpoint_id DESC LIMIT 1""",
            (SUPPORTED_CHECKPOINT_FORMAT,),
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
    if checkpoint["format_version"] != SUPPORTED_CHECKPOINT_FORMAT:
        raise HTTPException(
            status_code=501,
            detail=f"Checkpoint format {checkpoint['format_version']} cannot be proven here",
        )
    leaf_count: int = checkpoint["leaf_count"]
    if leaf_index >= leaf_count:
        detail = (
            f"MMR checkpoint {checkpoint['mmr_checkpoint_id']} covers only the first "
            f"{leaf_count} integrity entries"
            if checkpoint_id is not None
            else "No MMR checkpoint covers this entry yet"
        )
        raise HTTPException(status_code=409, detail=detail)

    try:
        start, height = mmr.locate_peak(leaf_index, leaf_count)
    except mmr.ProofError as error:
        log.error("inclusion proof: %s", error)
        raise _unverifiable() from error
    if 1 << height > settings.proof_max_peak_leaves:
        older = await _checkpoint_with_smaller_peak(
            conn, leaf_index, settings.proof_max_peak_leaves, below_leaf_count=leaf_count
        )
        detail = f"The entry is in a peak of {1 << height} entries, too large to prove on demand; "
        detail += (
            f"MMR checkpoint {older} can prove it (checkpoint_id={older})"
            if older is not None
            else "no older MMR checkpoint holds it in a smaller peak"
        )
        raise HTTPException(status_code=503, detail=detail)

    # Building a proof is CPU-bound Python that holds the GIL: bound how many
    # run at once (one per account) rather than let a few large ones slow every
    # other request. Refuse rather than queue, so waiting requests cannot pile up.
    slots = request.app.state.proof_slots
    slot = str(identity.user_id)
    if not slots.acquire(slot, 1, settings.proof_max_concurrent):
        raise HTTPException(
            status_code=503,
            detail="Too many proofs are being built; retry shortly",
            headers={"Retry-After": "1"},
        )
    try:
        # The chain in leaf order (see the module docstring).
        cur = await conn.execute(
            "SELECT chain_hash::text AS chain_hash FROM catalogue.integrity"
            " ORDER BY integrity_id OFFSET %s LIMIT %s",
            (start, 1 << height),
        )
        window = [bytes.fromhex(row["chain_hash"]) for row in await cur.fetchall()]
        try:
            _check_window(window, start, height, leaf_index, bytes.fromhex(entry["chain_hash"]))
            siblings = await run_in_threadpool(
                _prove, window, start, height, leaf_index, checkpoint
            )
        except mmr.ProofError as error:
            log.error(
                "inclusion proof refused entry=%s checkpoint=%s: %s",
                integrity_id,
                checkpoint["mmr_checkpoint_id"],
                error,
            )
            raise _unverifiable() from error
    finally:
        slots.release(slot)

    return MmrInclusionProof(
        integrity_id=integrity_id,
        chain_hash=entry["chain_hash"],
        mmr_checkpoint_id=checkpoint["mmr_checkpoint_id"],
        leaf_count=leaf_count,
        commitment=checkpoint["commitment"],
        proof=mmr.encode_proof(leaf_index, leaf_count, siblings),
    )


async def _checkpoint_with_smaller_peak(
    conn, leaf_index: int, max_peak_leaves: int, *, below_leaf_count: int
) -> int | None:
    """The newest checkpoint older than ``below_leaf_count`` leaves that holds
    the leaf in a peak small enough to prove, if there is one."""
    limit = min(below_leaf_count, mmr.small_peak_limit(leaf_index, max_peak_leaves))
    cur = await conn.execute(
        """SELECT mmr_checkpoint_id FROM catalogue.mmr_checkpoint
            WHERE format_version = %s AND leaf_count > %s AND leaf_count < %s
            ORDER BY leaf_count DESC LIMIT 1""",
        (SUPPORTED_CHECKPOINT_FORMAT, leaf_index, limit),
    )
    row = await cur.fetchone()
    return None if row is None else row["mmr_checkpoint_id"]


def _check_window(
    window: list[bytes], start: int, height: int, leaf_index: int, chain_hash: bytes
) -> None:
    """The window must be a whole peak and hold the entry at its leaf index,
    so the proof is built from (and answers with) the entry's own chain hash."""
    if len(window) != 1 << height:
        raise mmr.ProofError(
            f"expected {1 << height} entries from leaf {start}, the chain has {len(window)}"
        )
    if window[leaf_index - start] != chain_hash:
        raise mmr.ProofError(
            f"integrity_id order does not put the entry at leaf {leaf_index}"
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
