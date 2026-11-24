"""The Python MMR proofs against the vectors the Rust suite generates.

``crates/relic-mmr-worker/tests/vectors/inclusion-v1.json`` is written by the
Rust tests; any divergence between the two implementations fails here.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from api import mmr
from api.crypto import encode_fields

VECTORS = (
    Path(__file__).resolve().parents[3]
    / "crates/relic-mmr-worker/tests/vectors/inclusion-v1.json"
)
COMMITMENT_DOMAIN = b"RELIC:mmr-commitment:v1"

DATA = json.loads(VECTORS.read_text())
CHAIN = [bytes.fromhex(item) for item in DATA["chain_hashes"]]


def peaks_of(hashes: list[bytes]) -> list[mmr.Peak]:
    """Every peak of an MMR over ``hashes``, built with the proof code."""
    peaks = []
    for start, height in mmr.peak_layout(len(hashes)):
        window = hashes[start : start + (1 << height)]
        peaks.append(mmr.prove(window, start, height, start)[1])
    return peaks


def commitment(leaf_count: int, peaks: list[mmr.Peak]) -> bytes:
    encoded = b"".join(
        peak.start_index.to_bytes(8, "big") + peak.height.to_bytes(4, "big") + peak.hash
        for peak in peaks
    )
    return hashlib.sha256(
        encode_fields(COMMITMENT_DOMAIN, [leaf_count.to_bytes(8, "big"), encoded])
    ).digest()


def stored(peaks: list[mmr.Peak]) -> list[dict]:
    return [
        {"start_index": p.start_index, "height": p.height, "hash": p.hash.hex()} for p in peaks
    ]


def test_the_vectors_are_the_expected_version():
    assert DATA["proof_format_version"] == mmr.PROOF_FORMAT_VERSION


@pytest.mark.parametrize("mmr_case", DATA["mmrs"], ids=lambda case: str(case["leaf_count"]))
def test_peaks_and_commitment_match_rust(mmr_case):
    count = mmr_case["leaf_count"]
    peaks = peaks_of(CHAIN[:count])
    assert stored(peaks) == mmr_case["peaks"]
    assert commitment(count, peaks).hex() == mmr_case["commitment"]
    assert [(p.start_index, p.height) for p in peaks] == mmr.peak_layout(count)


@pytest.mark.parametrize("mmr_case", DATA["mmrs"], ids=lambda case: str(case["leaf_count"]))
def test_proofs_match_rust_exactly(mmr_case):
    count = mmr_case["leaf_count"]
    for case in mmr_case["proofs"]:
        leaf = case["leaf_index"]
        start, height = mmr.locate_peak(leaf, count)
        siblings, peak = mmr.prove(CHAIN[start : start + (1 << height)], start, height, leaf)
        assert mmr.encode_proof(leaf, count, siblings) == case["proof"], (count, leaf)
        assert stored([peak])[0] == case["peak"]
        recomputed = mmr.recompute_peak(leaf, count, siblings, CHAIN[leaf])
        assert recomputed == peak
        assert mmr.checkpoint_holds(mmr.parse_peaks(mmr_case["peaks"]), count, recomputed)


def test_rust_encoded_proofs_are_checked_by_python():
    """Proofs produced by Rust verify here, without Python building them."""
    for mmr_case in DATA["mmrs"]:
        peaks = mmr.parse_peaks(mmr_case["peaks"])
        for case in mmr_case["proofs"]:
            proof = case["proof"]
            recomputed = mmr.recompute_peak(
                proof["leaf_index"],
                proof["leaf_count"],
                [bytes.fromhex(s) for s in proof["siblings"]],
                CHAIN[proof["leaf_index"]],
            )
            assert mmr.checkpoint_holds(peaks, mmr_case["leaf_count"], recomputed)


def test_forged_proofs_do_not_reach_a_peak():
    thirteen = next(case for case in DATA["mmrs"] if case["leaf_count"] == 13)
    peaks = mmr.parse_peaks(thirteen["peaks"])
    assert DATA["rejected"]
    for case in DATA["rejected"]:
        proof = case["proof"]
        recomputed = mmr.recompute_peak(
            proof["leaf_index"],
            proof["leaf_count"],
            [bytes.fromhex(s) for s in proof["siblings"]],
            bytes.fromhex(case["chain_hash"]),
        )
        assert not mmr.checkpoint_holds(peaks, 13, recomputed), case["name"]


def test_every_leaf_of_every_size_proves_and_verifies():
    hashes = [hashlib.sha256(index.to_bytes(8, "big")).digest() for index in range(40)]
    for count in range(1, 41):
        peaks = peaks_of(hashes[:count])
        for leaf in range(count):
            start, height = mmr.locate_peak(leaf, count)
            siblings, _ = mmr.prove(hashes[start : start + (1 << height)], start, height, leaf)
            assert len(siblings) == height
            recomputed = mmr.recompute_peak(leaf, count, siblings, hashes[leaf])
            assert mmr.checkpoint_holds(peaks, count, recomputed), (count, leaf)


def test_tampering_is_detected():
    hashes = [hashlib.sha256(bytes([index])).digest() for index in range(20)]
    peaks = peaks_of(hashes)
    start, height = mmr.locate_peak(9, 20)
    siblings, _ = mmr.prove(hashes[start : start + (1 << height)], start, height, 9)
    assert mmr.checkpoint_holds(peaks, 20, mmr.recompute_peak(9, 20, siblings, hashes[9]))

    forged = hashlib.sha256(b"forged").digest()
    assert not mmr.checkpoint_holds(peaks, 20, mmr.recompute_peak(9, 20, siblings, forged))
    for position in range(len(siblings)):
        bad = list(siblings)
        bad[position] = forged
        assert not mmr.checkpoint_holds(peaks, 20, mmr.recompute_peak(9, 20, bad, hashes[9]))
    # The same proof does not move to another position.
    for other in (8, 10, 11):
        assert not mmr.checkpoint_holds(peaks, 20, mmr.recompute_peak(other, 20, siblings, hashes[9]))
    # Nor to another leaf count.
    with pytest.raises(mmr.ProofError):
        mmr.recompute_peak(9, 20, siblings[:-1], hashes[9])


def test_a_checkpoint_with_the_wrong_shape_holds_nothing():
    hashes = [hashlib.sha256(bytes([index])).digest() for index in range(9)]
    peaks = peaks_of(hashes)
    start, height = mmr.locate_peak(3, 9)
    siblings, peak = mmr.prove(hashes[start : start + (1 << height)], start, height, 3)
    assert mmr.checkpoint_holds(peaks, 9, peak)
    assert not mmr.checkpoint_holds(list(reversed(peaks)), 9, peak)
    assert not mmr.checkpoint_holds(peaks, 10, peak)


def test_out_of_range_and_wrong_sizes_are_rejected():
    with pytest.raises(mmr.ProofError):
        mmr.locate_peak(5, 5)
    with pytest.raises(mmr.ProofError):
        mmr.locate_peak(0, 0)
    with pytest.raises(mmr.ProofError):
        mmr.locate_peak(-1, 5)
    with pytest.raises(mmr.ProofError):
        mmr.prove(CHAIN[:3], 0, 2, 0)  # a height-2 peak needs 4 hashes
    with pytest.raises(mmr.ProofError):
        mmr.prove(CHAIN[:4], 0, 2, 4)  # leaf outside the peak


@pytest.mark.parametrize(
    "stored_peaks",
    [
        None,
        [],
        "peaks",
        [{"height": 1, "hash": "00" * 32}],  # the older, start-less shape
        [{"start_index": 0, "height": 1, "hash": "00" * 32, "extra": 1}],
        [{"start_index": 0, "height": 1, "hash": "zz" * 32}],
        [{"start_index": 0, "height": 1, "hash": "00" * 31}],
        [{"start_index": 0, "height": True, "hash": "00" * 32}],
        [{"start_index": -1, "height": 1, "hash": "00" * 32}],
        [{"start_index": 0, "height": 64, "hash": "00" * 32}],
    ],
)
def test_malformed_stored_peaks_are_rejected(stored_peaks):
    with pytest.raises(mmr.ProofError):
        mmr.parse_peaks(stored_peaks)
