"""``GET /v1/integrity/{id}/proof``: inclusion proofs against signed checkpoints.

Each test appends its own entries to the shared integrity chain and writes a
checkpoint whose peaks are computed from the *whole* chain, so the proofs are
checked against exactly what a worker would have signed.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import subprocess
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from nacl.signing import SigningKey
from psycopg.types.json import Jsonb

from api import mmr
from api.crypto import encode_fields, signing_message
from api.main import create_app

from .conftest import REPO, Database, login, make_settings
from .test_mmr_vectors import commitment, peaks_of, stored

SIG = b"\x11" * 64
MISSING = 9_000_000_000_000_000_000
CHECKPOINT_DOMAIN = b"RELIC:mmr-checkpoint:v1"
CHECKPOINT_SIGNATURE_DOMAIN = b"RELIC:mmr-system-signature:v1"
VERIFY_PROOF = REPO / "target/debug/relic-verify-proof"
EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


def sign_checkpoint(
    key: SigningKey,
    *,
    format_version: int,
    last_integrity_id: int,
    leaf_count: int,
    peaks: list[mmr.Peak],
    commitment_hex: str,
    system_uid: uuid.UUID,
    created_at_micros: int,
) -> bytes:
    """What ``relic-checkpoint-mmr`` signs: the Rust ``checkpoint_hash``, written out again."""
    encoded_peaks = b"".join(
        peak.start_index.to_bytes(8, "big") + peak.height.to_bytes(4, "big") + peak.hash
        for peak in peaks
    )
    digest = hashlib.sha256(
        encode_fields(
            CHECKPOINT_DOMAIN,
            [
                format_version.to_bytes(4, "big"),
                str(last_integrity_id).encode(),
                leaf_count.to_bytes(8, "big"),
                encoded_peaks,
                bytes.fromhex(commitment_hex),
                str(system_uid).encode(),
                created_at_micros.to_bytes(8, "big", signed=True),
            ],
        )
    ).digest()
    return key.sign(signing_message(CHECKPOINT_SIGNATURE_DOMAIN, digest)).signature


@dataclass
class Chain:
    database: Database
    source_id: uuid.UUID
    system_uid: uuid.UUID
    system_key: SigningKey

    def append(self, count: int) -> list[int]:
        """Append ``count`` entries to the chain tip; return their ids."""
        run = self.database.execute
        tip = run(
            "SELECT chain_hash FROM catalogue.integrity ORDER BY integrity_id DESC LIMIT 1"
        )
        prev_hash = tip[0][0] if tip else None
        ids = []
        for _ in range(count):
            chain_hash = secrets.token_hex(32)
            ids.append(
                run(
                    "INSERT INTO catalogue.integrity (source_id, source_type, record_hash,"
                    " prev_hash, chain_hash, format_version, system_signature, system_uid)"
                    " VALUES (%s, 'FIDBF', %s, %s, %s, 1, %s, %s) RETURNING integrity_id",
                    (self.source_id, secrets.token_hex(32), prev_hash, chain_hash, SIG,
                     self.system_uid),
                )[0][0]
            )
            prev_hash = chain_hash
        return ids

    def ids(self) -> list[int]:
        return [r[0] for r in self.database.execute(
            "SELECT integrity_id FROM catalogue.integrity ORDER BY integrity_id")]

    def hashes(self) -> list[bytes]:
        return [bytes.fromhex(r[0]) for r in self.database.execute(
            "SELECT chain_hash FROM catalogue.integrity ORDER BY integrity_id")]

    def checkpoint(self, *, format_version: int = 1, peaks=None) -> int:
        """Checkpoint the whole chain as it stands, signed by the system account.

        ``peaks`` overrides the stored JSON only; the signature always covers
        the genuine peaks, as a worker's would.
        """
        hashes = self.hashes()
        real = peaks_of(hashes)
        commitment_hex = commitment(len(hashes), real).hex()
        last_id = self.ids()[-1]
        created_at = datetime.now(timezone.utc)
        micros = (created_at - EPOCH) // timedelta(microseconds=1)
        signature = sign_checkpoint(
            self.system_key,
            format_version=format_version,
            last_integrity_id=last_id,
            leaf_count=len(hashes),
            peaks=real,
            commitment_hex=commitment_hex,
            system_uid=self.system_uid,
            created_at_micros=micros,
        )
        return self.database.execute(
            "INSERT INTO catalogue.mmr_checkpoint (last_integrity_id, leaf_count, peaks,"
            " commitment, format_version, created_at, system_uid, system_signature)"
            " VALUES (%s, %s, %s, %s, %s, %s, %s, %s) RETURNING mmr_checkpoint_id",
            (last_id, len(hashes), Jsonb(peaks if peaks is not None else stored(real)),
             commitment_hex, format_version, created_at, self.system_uid, signature),
        )[0][0]


@pytest.fixture(scope="module")
def chain(database) -> Chain:
    analyst = database.create_user("analyst")
    system = database.create_user(None, owner_type="system")
    source_id = uuid.uuid4()
    database.execute(
        "INSERT INTO catalogue.source (source_id, name, source_type, reference, snapshot_version,"
        " retrieved_at, is_ecological, submitted_by_analyst_id, signature)"
        " VALUES (%s, 'proof test', 'FIDBF', 'ref', 'v1', clock_timestamp(), true, %s, %s)",
        (source_id, analyst.user_id, SIG),
    )
    return Chain(database, source_id, system.user_id, system.key)


def headers_for(client: TestClient, database: Database, role: str = "viewer") -> dict:
    return {"Authorization": f"Bearer {login(client, database.create_user(role))}"}


def holds(client, headers, body) -> bool:
    """Check a response the way a client would: against the checkpoint it names."""
    checkpoint = client.get(
        f"/v1/mmr-checkpoints/{body['mmr_checkpoint_id']}", headers=headers
    ).json()
    proof = body["proof"]
    assert proof["leaf_count"] == checkpoint["leaf_count"] == body["leaf_count"]
    recomputed = mmr.recompute_peak(
        proof["leaf_index"],
        proof["leaf_count"],
        [bytes.fromhex(s) for s in proof["siblings"]],
        bytes.fromhex(body["chain_hash"]),
    )
    return mmr.checkpoint_holds(
        mmr.parse_peaks(checkpoint["peaks"]), checkpoint["leaf_count"], recomputed
    )


def test_every_entry_of_the_chain_has_a_valid_proof(client, database, chain):
    chain.append(11)
    checkpoint_id = chain.checkpoint()
    headers = headers_for(client, database)
    ids, hashes = chain.ids(), chain.hashes()
    for ordinal, integrity_id in enumerate(ids):
        response = client.get(
            f"/v1/integrity/{integrity_id}/proof",
            params={"checkpoint_id": checkpoint_id},
            headers=headers,
        )
        assert response.status_code == 200, (ordinal, response.text)
        body = response.json()
        assert body["integrity_id"] == integrity_id
        assert body["chain_hash"] == hashes[ordinal].hex()
        assert body["mmr_checkpoint_id"] == checkpoint_id
        assert body["leaf_count"] == len(ids)
        assert body["proof"]["format_version"] == mmr.PROOF_FORMAT_VERSION
        assert body["proof"]["leaf_index"] == ordinal
        assert len(body["proof"]["siblings"]) == mmr.locate_peak(ordinal, len(ids))[1]
        assert holds(client, headers, body), ordinal


def test_the_default_is_the_newest_checkpoint(client, database, chain):
    ids = chain.append(2)
    checkpoint_id = chain.checkpoint()
    headers = headers_for(client, database)
    body = client.get(f"/v1/integrity/{ids[0]}/proof", headers=headers).json()
    assert body["mmr_checkpoint_id"] == checkpoint_id
    assert holds(client, headers, body)


def test_older_and_newer_checkpoints_each_prove_the_same_entry(client, database, chain):
    early = chain.append(3)
    first = chain.checkpoint()
    later = chain.append(2)
    second = chain.checkpoint()
    headers = headers_for(client, database)

    def proof(integrity_id, checkpoint_id):
        return client.get(
            f"/v1/integrity/{integrity_id}/proof",
            params={"checkpoint_id": checkpoint_id},
            headers=headers,
        )

    old, new = proof(early[0], first).json(), proof(early[0], second).json()
    assert old["leaf_count"] < new["leaf_count"]
    assert holds(client, headers, old) and holds(client, headers, new)
    # The newer entries are not covered by the older checkpoint.
    refused = proof(later[0], first)
    assert refused.status_code == 409
    assert "covers only the first" in refused.json()["detail"]
    assert proof(later[0], second).status_code == 200


def test_an_entry_without_a_checkpoint_is_not_provable_yet(client, database, chain):
    chain.append(1)
    chain.checkpoint()
    (fresh,) = chain.append(1)
    response = client.get(
        f"/v1/integrity/{fresh}/proof", headers=headers_for(client, database)
    )
    assert response.status_code == 409
    assert "No MMR checkpoint covers" in response.json()["detail"]
    chain.checkpoint()  # leave the chain covered for the other tests


def test_every_role_may_ask_but_anonymous_callers_may_not(client, database, chain):
    (entry,) = chain.append(1)
    chain.checkpoint()
    assert client.get(f"/v1/integrity/{entry}/proof").status_code == 401
    assert client.get(
        f"/v1/integrity/{entry}/proof", headers={"Authorization": "Bearer nonsense"}
    ).status_code == 401
    for role in ("viewer", "analyst", "moderator"):
        response = client.get(
            f"/v1/integrity/{entry}/proof", headers=headers_for(client, database, role)
        )
        assert response.status_code == 200, role


def test_unknown_and_malformed_requests(client, database, chain):
    chain.append(1)
    chain.checkpoint()
    headers = headers_for(client, database)
    entry = chain.ids()[-1]
    assert client.get(f"/v1/integrity/{MISSING}/proof", headers=headers).status_code == 404
    assert client.get(
        f"/v1/integrity/{entry}/proof", params={"checkpoint_id": MISSING}, headers=headers
    ).status_code == 404
    for bad in (
        "/v1/integrity/0/proof",
        "/v1/integrity/-1/proof",
        f"/v1/integrity/{2**63}/proof",
        "/v1/integrity/x/proof",
        f"/v1/integrity/{entry}/proof?checkpoint_id=0",
        f"/v1/integrity/{entry}/proof?checkpoint_id={2**63}",
        f"/v1/integrity/{entry}/proof?checkpoint_id=abc",
    ):
        assert client.get(bad, headers=headers).status_code == 422, bad


def test_a_checkpoint_that_does_not_match_the_chain_is_never_served(client, database, chain):
    """A bad stored peak must produce a refusal, not a proof the client would reject."""
    (entry,) = chain.append(1)
    real = stored(peaks_of(chain.hashes()))

    wrong_hash = [dict(peak) for peak in real]
    wrong_hash[-1]["hash"] = "ff" * 32
    shifted = [dict(peak) for peak in real]
    shifted[0]["start_index"] += 1
    cases = {
        "a peak hash that is wrong": wrong_hash,
        "a peak at the wrong position": shifted,
        "peaks without start indexes": [{"height": 1, "hash": "00" * 32}],
    }
    headers = headers_for(client, database)
    for label, peaks in cases.items():
        checkpoint_id = chain.checkpoint(peaks=peaks)
        response = client.get(
            f"/v1/integrity/{entry}/proof",
            params={"checkpoint_id": checkpoint_id},
            headers=headers,
        )
        assert response.status_code == 500, label
        assert response.json() == {
            "detail": "The proof could not be verified against the checkpoint"
        }, label
        chain.append(1)  # the next checkpoint needs a new leaf count
    chain.checkpoint()


def test_a_checkpoint_in_an_unknown_format_is_not_proven(client, database, chain):
    (entry,) = chain.append(1)
    checkpoint_id = chain.checkpoint(format_version=2)
    response = client.get(
        f"/v1/integrity/{entry}/proof",
        params={"checkpoint_id": checkpoint_id},
        headers=headers_for(client, database),
    )
    assert response.status_code == 501
    chain.append(1)
    chain.checkpoint()


def make_client(database, object_dirs, **overrides):
    settings = make_settings(
        database.app_url, staging_dir=object_dirs.staging, fidbf_root=object_dirs.store, **overrides
    )
    return TestClient(create_app(settings))


def test_a_peak_that_is_too_large_to_prove_is_refused(database, object_dirs, chain):
    chain.append(5)
    checkpoint_id = chain.checkpoint()
    ids = chain.ids()
    assert len(ids) >= 4
    with make_client(database, object_dirs, proof_max_peak_leaves=2) as small:
        headers = headers_for(small, database)
        first = small.get(
            f"/v1/integrity/{ids[0]}/proof", params={"checkpoint_id": checkpoint_id},
            headers=headers,
        )
        assert first.status_code == 503
        assert "too large" in first.json()["detail"]


def test_proofs_are_rate_limited_per_account(database, object_dirs, chain):
    (entry,) = chain.append(1)
    chain.checkpoint()
    with make_client(database, object_dirs, proof_rate_limit_per_minute=2) as limited:
        headers = headers_for(limited, database)
        statuses = [
            limited.get(f"/v1/integrity/{entry}/proof", headers=headers).status_code
            for _ in range(3)
        ]
        assert statuses == [200, 200, 429]
        other = headers_for(limited, database)
        assert limited.get(f"/v1/integrity/{entry}/proof", headers=other).status_code == 200


# ---------------------------------------------------------------------------
# End to end: the API's proofs, checked by the Rust client
# ---------------------------------------------------------------------------

needs_rust = pytest.mark.skipif(
    not VERIFY_PROOF.exists(), reason="build with: cargo build -p relic-mmr-worker"
)


def verify_with_rust(tmp_path, proof: dict, checkpoint: dict, public_key: str, *extra: str):
    proof_file, checkpoint_file = tmp_path / "proof.json", tmp_path / "checkpoint.json"
    proof_file.write_text(json.dumps(proof))
    checkpoint_file.write_text(json.dumps(checkpoint))
    return subprocess.run(
        [str(VERIFY_PROOF), "--proof", str(proof_file), "--checkpoint", str(checkpoint_file),
         "--public-key", public_key, *extra],
        capture_output=True, text=True,
    )


@needs_rust
def test_the_rust_client_accepts_every_proof_the_api_serves(client, database, chain, tmp_path):
    chain.append(12)
    checkpoint_id = chain.checkpoint()
    headers = headers_for(client, database)
    checkpoint = client.get(f"/v1/mmr-checkpoints/{checkpoint_id}", headers=headers).json()
    # The key is fetched on its own, as a client pinning it would.
    system = client.get(f"/v1/users/{checkpoint['system_uid']}", headers=headers).json()
    for integrity_id in chain.ids():
        entry = client.get(f"/v1/integrity/{integrity_id}", headers=headers).json()
        proof = client.get(
            f"/v1/integrity/{integrity_id}/proof",
            params={"checkpoint_id": checkpoint_id},
            headers=headers,
        ).json()
        result = verify_with_rust(
            tmp_path, proof, checkpoint, system["public_key"],
            "--chain-hash", entry["chain_hash"],
        )
        assert result.returncode == 0, (integrity_id, result.stdout, result.stderr)
        assert result.stdout.startswith(f"VERIFIED: integrity entry {integrity_id} "), result.stdout


@needs_rust
def test_the_rust_client_rejects_what_the_api_did_not_sign_off(client, database, chain, tmp_path):
    chain.append(6)
    checkpoint_id = chain.checkpoint()
    headers = headers_for(client, database)
    checkpoint = client.get(f"/v1/mmr-checkpoints/{checkpoint_id}", headers=headers).json()
    key = client.get(f"/v1/users/{checkpoint['system_uid']}", headers=headers).json()["public_key"]
    target = chain.ids()[-2]
    proof = client.get(
        f"/v1/integrity/{target}/proof", params={"checkpoint_id": checkpoint_id}, headers=headers
    ).json()
    assert verify_with_rust(tmp_path, proof, checkpoint, key).returncode == 0

    def rejected(*extra: str, **overrides):
        used = {"proof": proof, "checkpoint": checkpoint, "key": key, **overrides}
        result = verify_with_rust(
            tmp_path, used["proof"], used["checkpoint"], used["key"], *extra
        )
        assert result.returncode == 1, (result.stdout, result.stderr)
        assert result.stdout.startswith("NOT VERIFIED:")

    flipped = "0" if proof["proof"]["siblings"][0][0] != "0" else "1"
    tampered_sibling = json.loads(json.dumps(proof))
    tampered_sibling["proof"]["siblings"][0] = flipped + proof["proof"]["siblings"][0][1:]
    rejected(proof=tampered_sibling)

    rejected(proof={**proof, "chain_hash": "ab" * 32})

    moved = json.loads(json.dumps(proof))
    moved["proof"]["leaf_index"] -= 1
    rejected(proof=moved)

    rejected(key=bytes(SigningKey.generate().verify_key).hex())
    rejected(checkpoint={**checkpoint, "created_at": "2001-01-01T00:00:00+00:00"})

    # A leaf the client recomputed itself is not the one the server proved.
    rejected("--chain-hash", "cd" * 32)
