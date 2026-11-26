"""Merkle Mountain Range inclusion proofs.

This is a deliberate, minimal port of ``crates/relic-proof`` (the leaf and
node hashes in ``lib.rs`` and ``proof.rs``). The Rust crate remains the source
of truth: ``tests/test_mmr_vectors.py`` pins this module to the vectors the
Rust test suite generates (``crates/relic-proof/tests/vectors/inclusion-v1.json``),
so any divergence fails CI on both sides.

Shape of the tree
-----------------
Every peak is a perfect binary tree whose first leaf is a multiple of the
tree's size, so the position of every node on the path from a leaf to its peak
follows from the leaf index alone. A proof is therefore only the sibling
hashes, bottom-up, plus the leaf index and the leaf count of the checkpoint it
targets. The server never trusts its own proof: the endpoint recomputes the
peak and compares it with the stored, signed checkpoint before answering.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Sequence

from .crypto import encode_fields

LEAF_DOMAIN = b"RELIC:mmr-leaf:v1"
NODE_DOMAIN = b"RELIC:mmr-node:v1"
PROOF_FORMAT_VERSION = 1
DIGEST_BYTES = 32
_MAX_SIBLINGS = 63


class ProofError(ValueError):
    """A proof could not be built, or does not hold."""


@dataclass(frozen=True)
class Peak:
    start_index: int
    height: int
    hash: bytes


def leaf_hash(leaf_index: int, chain_hash: bytes) -> bytes:
    return hashlib.sha256(
        encode_fields(LEAF_DOMAIN, [leaf_index.to_bytes(8, "big"), chain_hash])
    ).digest()


def node_hash(start_index: int, height: int, left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(
        encode_fields(
            NODE_DOMAIN,
            [start_index.to_bytes(8, "big"), height.to_bytes(4, "big"), left, right],
        )
    ).digest()


def peak_layout(leaf_count: int) -> list[tuple[int, int]]:
    """``(start_index, height)`` of every peak, left to right.

    The heights are the set bits of ``leaf_count``, largest first.
    """
    layout = []
    start = 0
    for height in range(63, -1, -1):
        if (leaf_count >> height) & 1:
            layout.append((start, height))
            start += 1 << height
    return layout


def locate_peak(leaf_index: int, leaf_count: int) -> tuple[int, int]:
    """``(start_index, height)`` of the peak that holds ``leaf_index``."""
    if not 0 <= leaf_index < leaf_count < 1 << 64:
        raise ProofError(f"leaf {leaf_index} is not covered by an MMR of {leaf_count} leaves")
    for start, height in peak_layout(leaf_count):
        if start <= leaf_index < start + (1 << height):
            return start, height
    raise ProofError("leaf outside every peak")  # pragma: no cover


def small_peak_limit(leaf_index: int, max_peak_leaves: int) -> int:
    """Exclusive upper bound on the leaf counts at which ``leaf_index`` sits
    in a peak of at most ``max_peak_leaves`` leaves.

    The peaks taller than ``h`` cover exactly the first ``leaf_count`` rounded
    down to a multiple of ``2 ** (h + 1)`` leaves, so with ``h`` the tallest
    allowed height the leaf is in an allowed peak exactly when
    ``leaf_index < leaf_count < small_peak_limit(leaf_index, max_peak_leaves)``.
    """
    if leaf_index < 0 or max_peak_leaves < 1:
        raise ProofError("leaf index and peak size must be non-negative and positive")
    span = 1 << max_peak_leaves.bit_length()  # 2 ** (h + 1), h = floor(log2(cap))
    return (leaf_index // span + 1) * span


def _levels(chain_hashes: Sequence[bytes], start: int, height: int) -> list[list[bytes]]:
    """Every level of the perfect tree of ``height`` over ``chain_hashes``.

    ``chain_hashes`` are the leaves ``start .. start + 2**height`` in order.
    ``levels[k][j]`` is the hash of the node of height ``k`` that covers the
    leaves from ``start + j * 2**k``.
    """
    if len(chain_hashes) != 1 << height:
        raise ProofError(
            f"expected {1 << height} chain hashes for a peak of height {height}, "
            f"got {len(chain_hashes)}"
        )
    level = [leaf_hash(start + offset, digest) for offset, digest in enumerate(chain_hashes)]
    levels = [level]
    for parent_height in range(1, height + 1):
        span = 1 << parent_height
        level = [
            node_hash(start + index * span, parent_height, level[2 * index], level[2 * index + 1])
            for index in range(len(level) // 2)
        ]
        levels.append(level)
    return levels


def prove(
    peak_chain_hashes: Sequence[bytes], peak_start: int, height: int, leaf_index: int
) -> tuple[list[bytes], Peak]:
    """Siblings of ``leaf_index`` and the peak they lead to.

    ``peak_chain_hashes`` are the ``chain_hash`` values of the ``2**height``
    leaves of the peak that starts at ``peak_start``, in leaf order. Only that
    peak is needed, so the work is proportional to its size.
    """
    if not peak_start <= leaf_index < peak_start + (1 << height):
        raise ProofError("leaf is not in this peak")
    levels = _levels(peak_chain_hashes, peak_start, height)
    position = leaf_index - peak_start
    siblings = [levels[level][(position >> level) ^ 1] for level in range(height)]
    return siblings, Peak(peak_start, height, levels[height][0])


def recompute_peak(
    leaf_index: int, leaf_count: int, siblings: Sequence[bytes], chain_hash: bytes
) -> Peak:
    """Fold a proof into the peak it claims to belong to."""
    start, height = locate_peak(leaf_index, leaf_count)
    if len(siblings) != height:
        raise ProofError(f"the proof has {len(siblings)} siblings but its leaf needs {height}")
    node = leaf_hash(leaf_index, chain_hash)
    for level, sibling in enumerate(siblings):
        parent_start = leaf_index & ~((1 << (level + 1)) - 1)
        if (leaf_index >> level) & 1 == 0:
            node = node_hash(parent_start, level + 1, node, sibling)
        else:
            node = node_hash(parent_start, level + 1, sibling, node)
    return Peak(start, height, node)


def parse_peaks(stored: Any) -> list[Peak]:
    """Peaks from a stored checkpoint's JSON, strictly validated."""
    if not isinstance(stored, list) or not stored:
        raise ProofError("checkpoint peaks are not a non-empty list")
    peaks = []
    for item in stored:
        if not isinstance(item, dict) or set(item) != {"start_index", "height", "hash"}:
            raise ProofError("a checkpoint peak has unexpected fields")
        start, height, digest = item["start_index"], item["height"], item["hash"]
        if (
            type(start) is not int
            or type(height) is not int
            or not isinstance(digest, str)
            or not 0 <= start < 1 << 64
            or not 0 <= height <= _MAX_SIBLINGS
            or len(digest) != 2 * DIGEST_BYTES
        ):
            raise ProofError("a checkpoint peak is malformed")
        try:
            peaks.append(Peak(start, height, bytes.fromhex(digest)))
        except ValueError as error:
            raise ProofError("a checkpoint peak hash is not hexadecimal") from error
    return peaks


def checkpoint_holds(peaks: Sequence[Peak], leaf_count: int, recomputed: Peak) -> bool:
    """Whether ``recomputed`` is a peak of a well-formed checkpoint."""
    shape = [(peak.start_index, peak.height) for peak in peaks]
    return shape == peak_layout(leaf_count) and recomputed in peaks


def encode_proof(leaf_index: int, leaf_count: int, siblings: Sequence[bytes]) -> dict[str, Any]:
    """The canonical JSON form shared with the Rust crate."""
    return {
        "format_version": PROOF_FORMAT_VERSION,
        "leaf_index": leaf_index,
        "leaf_count": leaf_count,
        "siblings": [sibling.hex() for sibling in siblings],
    }
