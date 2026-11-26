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

import psycopg
import pytest
from fastapi.testclient import TestClient
from nacl.signing import SigningKey
from psycopg.types.json import Jsonb

from api import mmr
from api.crypto import encode_fields, signing_message
from api.main import create_app

from .conftest import REPO, Database, login, make_settings
from .test_auth_api import _openssh_public_key
from .test_catalogue_api import RUST_ADMISSION, _ssh_account, admit_fidbf
from .test_mmr_vectors import DATA, commitment, peaks_of, stored

SIG = b"\x11" * 64
MISSING = 9_000_000_000_000_000_000
CHECKPOINT_DOMAIN = b"RELIC:mmr-checkpoint:v1"
CHECKPOINT_SIGNATURE_DOMAIN = b"RELIC:mmr-system-signature:v1"
VERIFY_PROOF = REPO / "target/debug/relic-verify-proof"
CHECKPOINT_MMR = REPO / "target/debug/relic-checkpoint-mmr"
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
    (uncovered,) = chain.append(1)
    headers = headers_for(client, database)
    # 501 whether or not the checkpoint covers the entry: the format is
    # checked first, so the answer never depends on what it cannot read.
    for integrity_id in (entry, uncovered):
        response = client.get(
            f"/v1/integrity/{integrity_id}/proof",
            params={"checkpoint_id": checkpoint_id},
            headers=headers,
        )
        assert response.status_code == 501, (integrity_id, response.text)
    chain.checkpoint()


def test_the_default_checkpoint_is_one_this_server_can_prove(client, database, chain):
    """A newer checkpoint in another format must not hide the valid ones."""
    (entry,) = chain.append(1)
    provable = chain.checkpoint()
    chain.append(1)
    chain.checkpoint(format_version=2)  # covers more entries, unknown format
    response = client.get(
        f"/v1/integrity/{entry}/proof", headers=headers_for(client, database)
    )
    assert response.status_code == 200, response.text
    assert response.json()["mmr_checkpoint_id"] == provable
    chain.checkpoint()  # leave the newest entry covered in format 1


def make_client(database, object_dirs, **overrides):
    settings = make_settings(
        database.app_url, staging_dir=object_dirs.staging, fidbf_root=object_dirs.store, **overrides
    )
    return TestClient(create_app(settings))


def test_a_peak_that_is_too_large_to_prove_is_refused(database, object_dirs, chain):
    """With single-leaf peaks only (cap 1), an even leaf is provable exactly in
    the checkpoint that ends on it, and an odd leaf in none: the refusal must
    say which older checkpoint can prove the entry, or that none can."""
    if len(chain.ids()) % 2:
        chain.append(1)
    (even,) = chain.append(1)  # leaf index even: alone in the last peak
    ends_on_it = chain.checkpoint()
    (odd,) = chain.append(1)
    chain.append(2)
    newest = chain.checkpoint()
    with make_client(database, object_dirs, proof_max_peak_leaves=1) as small:
        headers = headers_for(small, database)

        def proof(integrity_id, checkpoint_id=None):
            params = {} if checkpoint_id is None else {"checkpoint_id": checkpoint_id}
            return small.get(f"/v1/integrity/{integrity_id}/proof", params=params, headers=headers)

        refused = proof(even)
        assert refused.status_code == 503
        detail = refused.json()["detail"]
        assert "too large" in detail and f"checkpoint_id={ends_on_it}" in detail, detail
        assert "Retry-After" not in refused.headers  # retrying will not help
        suggested = proof(even, ends_on_it)
        assert suggested.status_code == 200, suggested.text
        assert holds(small, headers, suggested.json())

        for checkpoint_id in (None, newest):
            refused = proof(odd, checkpoint_id)
            assert refused.status_code == 503
            assert "no older MMR checkpoint" in refused.json()["detail"]


def test_proofs_being_built_at_once_are_limited(database, object_dirs, chain):
    (entry,) = chain.append(1)
    chain.checkpoint()
    with make_client(database, object_dirs, proof_max_concurrent=1) as limited:
        headers = headers_for(limited, database)
        slots = limited.app.state.proof_slots
        assert slots.acquire("another account", 1, 1)  # its proof is being built
        try:
            busy = limited.get(f"/v1/integrity/{entry}/proof", headers=headers)
            assert busy.status_code == 503
            assert busy.headers["Retry-After"] == "1"
            assert "retry" in busy.json()["detail"]
        finally:
            slots.release("another account")
        assert limited.get(f"/v1/integrity/{entry}/proof", headers=headers).status_code == 200
        # Every proof gives its slot back, refused ones included.
        assert slots.total == 0


def test_integrity_ids_must_follow_the_chain(database, chain):
    """Migration 009: the proofs read the chain in integrity_id order, so an
    entry may only extend the entry with the highest id below its own."""
    chain.append(1)
    rows = database.execute(
        "SELECT integrity_id, chain_hash FROM catalogue.integrity"
        " ORDER BY integrity_id DESC LIMIT 2"
    )
    (tip_id, tip_hash), (_, before_tip_hash) = rows

    def insert(integrity_id: int, prev_hash: str | None) -> None:
        database.execute(
            "INSERT INTO catalogue.integrity (integrity_id, source_id, source_type,"
            " record_hash, prev_hash, chain_hash, format_version, system_signature,"
            " system_uid) OVERRIDING SYSTEM VALUE"
            " VALUES (%s, %s, 'FIDBF', %s, %s, %s, 1, %s, %s)",
            (integrity_id, chain.source_id, secrets.token_hex(32), prev_hash,
             secrets.token_hex(32), SIG, chain.system_uid),
        )

    cases = {
        # Below every existing id, yet claiming to extend the tip: the
        # unique-successor index alone would accept it and break the order.
        "an id below the chain": (-tip_id, tip_hash),
        "a second genesis": (tip_id + 1000, None),
        "a fork": (tip_id + 1000, before_tip_hash),
    }
    for label, (integrity_id, prev_hash) in cases.items():
        with pytest.raises(psycopg.errors.IntegrityConstraintViolation, match="highest integrity_id"):
            insert(integrity_id, prev_hash)
        assert chain.ids()[-1] == tip_id, label
    # The ordinary path still works: the next id, extending the tip.
    chain.append(1)
    chain.checkpoint()


def test_the_checkpoint_signature_matches_the_rust_vector():
    """The Python ``sign_checkpoint`` above is what forges every checkpoint in
    these tests; pin it to the signature Rust produces for the same input."""
    vector = DATA["checkpoint_signature"]
    hashes = [bytes.fromhex(item) for item in DATA["chain_hashes"][: vector["leaf_count"]]]
    peaks = peaks_of(hashes)
    assert commitment(len(hashes), peaks).hex() == vector["commitment"]
    key = SigningKey(bytes.fromhex(vector["seed"]))
    assert bytes(key.verify_key).hex() == vector["public_key"]
    signature = sign_checkpoint(
        key,
        format_version=vector["format_version"],
        last_integrity_id=vector["last_integrity_id"],
        leaf_count=vector["leaf_count"],
        peaks=peaks,
        commitment_hex=vector["commitment"],
        system_uid=uuid.UUID(vector["system_uid"]),
        created_at_micros=vector["created_at_micros"],
    )
    assert signature.hex() == vector["system_signature"]


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
    not VERIFY_PROOF.exists(), reason="build with: cargo build -p relic-proof"
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
    """The API's proofs and the Rust verifier agree on every position. The
    fixture's chain hashes are random rather than hashes of real entries, so
    this checks the proof mechanics only; see the end-to-end test below for
    proofs tied to real entries."""
    chain.append(12)
    checkpoint_id = chain.checkpoint()
    headers = headers_for(client, database)
    checkpoint = client.get(f"/v1/mmr-checkpoints/{checkpoint_id}", headers=headers).json()
    key = chain.system_key.verify_key.encode().hex()  # pinned, not read from the API
    ids = chain.ids()
    for leaf, integrity_id in enumerate(ids):
        proof = client.get(
            f"/v1/integrity/{integrity_id}/proof",
            params={"checkpoint_id": checkpoint_id},
            headers=headers,
        ).json()
        result = verify_with_rust(
            tmp_path, proof, checkpoint, key, "--system-uid", str(chain.system_uid)
        )
        assert result.returncode == 0, (integrity_id, result.stdout, result.stderr)
        assert result.stdout.startswith(
            f"VERIFIED: leaf {leaf} of the MMR checkpoint of {len(ids)} entries "
        ), result.stdout
        # The chain hash came from the server, and the verifier says so.
        assert "warning" in result.stderr

    # --entry recomputes the chain hash, which these placeholder rows fail.
    entry = client.get(f"/v1/integrity/{ids[-1]}", headers=headers).json()
    (tmp_path / "entry.json").write_text(json.dumps(entry))
    result = verify_with_rust(
        tmp_path, proof, checkpoint, key, "--entry", str(tmp_path / "entry.json")
    )
    assert result.returncode == 1
    assert "hash to" in result.stdout, result.stdout


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

    # Garbage from a tampering server is a rejection (1), not a usage error
    # (2), so a script that alerts on status 1 still alerts.
    rejected(proof={"not": "a proof"})
    rejected(checkpoint={**checkpoint, "peaks": "none"})


# ---------------------------------------------------------------------------
# End to end, on the real path: no Python stand-in for any signer
# ---------------------------------------------------------------------------

needs_real_tools = pytest.mark.skipif(
    not (VERIFY_PROOF.exists() and CHECKPOINT_MMR.exists() and RUST_ADMISSION),
    reason="build with: cargo build -p relic-proof -p relic-mmr-worker -p relic-ingest",
)


@needs_real_tools
def test_a_real_admission_is_proven_end_to_end(client, database, chain, tmp_path):
    """relic-ingest-fidbf admits a FIDBF and signs its integrity entry,
    relic-checkpoint-mmr checkpoints the chain, the API serves the proof, and
    relic-verify-proof ties it to that entry, with the key and account pinned
    from the worker's key file rather than read from the API."""
    admission = admit_fidbf(database, tmp_path)
    source_id = admission.ids["source"]
    ((integrity_id,),) = database.execute(
        "SELECT integrity_id FROM catalogue.integrity WHERE source_id = %s", (source_id,)
    )
    mmr_uid, mmr_key = _ssh_account(database, tmp_path, "mmr", None, "system")
    pin = _openssh_public_key(mmr_key.with_suffix(".pub")).hex()
    worker = subprocess.run(
        [str(CHECKPOINT_MMR), "--database-url", database.worker_url,
         "--system-user-id", str(mmr_uid), "--key", str(mmr_key)],
        capture_output=True, text=True, timeout=120,
    )
    assert worker.returncode == 0, worker.stderr
    signed = json.loads(worker.stdout)
    assert signed["inserted"] is True
    checkpoint_id = signed["mmr_checkpoint_id"]

    headers = headers_for(client, database)
    response = client.get(f"/v1/integrity/{integrity_id}/proof", headers=headers)
    assert response.status_code == 200, response.text
    assert response.json()["mmr_checkpoint_id"] == checkpoint_id  # the default
    documents = {
        "proof": response.json(),
        "checkpoint": client.get(f"/v1/mmr-checkpoints/{checkpoint_id}", headers=headers).json(),
        "entry": client.get(f"/v1/integrity/{integrity_id}", headers=headers).json(),
    }
    pins = {
        "--public-key": pin,
        "--system-uid": str(mmr_uid),
        "--commitment": signed["commitment"],
        "--source-id": str(source_id),
    }

    def verify(changes=None, **flags):
        files = []
        for name, document in {**documents, **(changes or {})}.items():
            path = tmp_path / f"{name}.json"
            path.write_text(json.dumps(document))
            files += [f"--{name}", str(path)]
        options = [item for pair in {**pins, **flags}.items() for item in pair]
        return subprocess.run(
            [str(VERIFY_PROOF), *files, *options], capture_output=True, text=True
        )

    verified = verify()
    assert verified.returncode == 0, verified.stdout + verified.stderr
    assert f"signed by system account {mmr_uid}" in verified.stdout
    assert "recomputed from the integrity entry" in verified.stdout
    assert f"source {source_id} (FIDBF)" in verified.stdout
    assert verified.stderr == ""

    entry = documents["entry"]
    for label, result in {
        "another record hash": verify({"entry": {**entry, "record_hash": "ab" * 32}}),
        "another source": verify({"entry": {**entry, "source_id": str(uuid.uuid4())}}),
        "a source I did not submit": verify(**{"--source-id": str(uuid.uuid4())}),
        "another system account": verify(**{"--system-uid": str(chain.system_uid)}),
        "another key": verify(**{"--public-key": SigningKey.generate().verify_key.encode().hex()}),
        "another checkpoint": verify(**{"--commitment": "00" * 32}),
    }.items():
        assert result.returncode == 1, (label, result.stdout, result.stderr)
        assert result.stdout.startswith("NOT VERIFIED:"), label
