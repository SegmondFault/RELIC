"""Read-only catalogue routes: shape, encoding, filters, cursor paging, access."""

from __future__ import annotations

import hashlib
import json
import secrets
import subprocess
import uuid
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path

import pytest
from psycopg.types.json import Jsonb

from .conftest import REPO, User, login
from .test_auth_api import _openssh_public_key

U64_MAX = 2**64 - 1
SECRET_PATH = "/srv/relic/objects/internal-only"


def bearer(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _hex(n: int) -> str:
    return secrets.token_hex(n)


@dataclass
class Corpus:
    analyst: User
    viewer: User
    source_id: uuid.UUID
    batch_id: uuid.UUID
    binary_id: uuid.UUID
    binary_sha256: str
    fidbf_id: uuid.UUID
    function_ids: list[uuid.UUID]
    bsim_id: uuid.UUID
    function_bsim_id: uuid.UUID
    provenance_id: uuid.UUID
    license_assertion_id: uuid.UUID
    classification_id: uuid.UUID
    flag_id: uuid.UUID
    flag_response_id: uuid.UUID
    integrity_ids: list[int]
    tip_before: int
    mmr_checkpoint_id: int


@pytest.fixture(scope="session")
def corpus(database) -> Corpus:
    """One row of every catalogue type, inserted as the database owner."""
    run = database.execute
    analyst = database.create_user("analyst")
    viewer = database.create_user("viewer")
    moderator = database.create_user("moderator")
    system = database.create_user(None, owner_type="system")
    sig = b"\x11" * 64

    source_id, batch_id, binary_id, fidbf_id = (uuid.uuid4() for _ in range(4))
    run(
        "INSERT INTO catalogue.source (source_id, name, source_type, reference, snapshot_version,"
        " retrieved_at, is_ecological, submitted_by_analyst_id, signature)"
        " VALUES (%s, 'catalogue test', 'FIDBF', 'ref', 'v1', clock_timestamp(), true, %s, %s)",
        (source_id, analyst.user_id, sig),
    )
    run(
        "INSERT INTO catalogue.batch (batch_id, md5, content_sha256, analyst_user_id, signature)"
        " VALUES (%s, %s, %s, %s, %s)",
        (batch_id, _hex(16), _hex(32), analyst.user_id, sig),
    )
    binary_sha256 = _hex(32)
    run(
        "INSERT INTO catalogue.binary_record (binary_id, batch_id, source_id, content_sha256,"
        " content_md5, size_bytes, format, bit_width, entry_point, image_base, created_by)"
        " VALUES (%s, %s, %s, %s, %s, 123, 'ELF', 64, %s, 0, %s)",
        (binary_id, batch_id, source_id, binary_sha256, _hex(16), Decimal(U64_MAX), analyst.user_id),
    )
    run(
        "INSERT INTO catalogue.fidbf (fidbf_id, binary_id, storage_path, sha256, md5,"
        " submitted_by_user_id, signature, source_id) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
        (fidbf_id, binary_id, SECRET_PATH + ".fidbf", _hex(32), _hex(16), analyst.user_id, sig, source_id),
    )
    function_ids = [uuid.uuid4() for _ in range(3)]
    for index, function_id in enumerate(function_ids):
        run(
            "INSERT INTO catalogue.function_record (function_id, name, binary_id, fidbf_id,"
            " full_hash, specific_hash, virtual_address, is_export)"
            " VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
            (function_id, f"f{index}", binary_id, fidbf_id, _hex(8), _hex(8),
             Decimal(U64_MAX - index), index == 0),
        )
    bsim_id, function_bsim_id = uuid.uuid4(), uuid.uuid4()
    run(
        "INSERT INTO catalogue.bsim (bsim_id, object_data, sha256, md5, submitted_by_user_id,"
        " signature, source_id) VALUES (%s, %s, %s, %s, %s, %s, %s)",
        (bsim_id, Jsonb({"features": [1, 2, 3]}), _hex(32), _hex(16), analyst.user_id, sig, source_id),
    )
    run(
        "INSERT INTO catalogue.function_bsim (function_bsim_id, function_id, binary_id, bsim_id)"
        " VALUES (%s, %s, %s, %s)",
        (function_bsim_id, function_ids[0], binary_id, bsim_id),
    )
    provenance_id = uuid.uuid4()
    run(
        "INSERT INTO catalogue.provenance (provenance_id, fidbf_id, binary_id, schema_name,"
        " schema_version, storage_path, object_data, sha256, md5, submitted_by_user_id,"
        " signature, source_id) VALUES (%s, %s, %s, 'ocsf', '1.3.0', %s, %s, %s, %s, %s, %s, %s)",
        (provenance_id, fidbf_id, binary_id, SECRET_PATH + ".json",
         Jsonb({"class_uid": 1, "unmapped": {"relic": {"recipe": "make"}}}),
         _hex(32), _hex(16), analyst.user_id, sig, source_id),
    )
    license_assertion_id = uuid.uuid4()
    run(
        "INSERT INTO catalogue.license_assertion (license_assertion_id, binary_id, spdx_expression,"
        " basis, confidence, evidence_provenance_id, submitted_by_analyst_id, signature)"
        " VALUES (%s, %s, 'MIT OR Apache-2.0', 'detected', 0.8500, %s, %s, %s)",
        (license_assertion_id, binary_id, provenance_id, analyst.user_id, sig),
    )
    classification_id = uuid.uuid4()
    run(
        "INSERT INTO catalogue.classification (classification_id, target_type, target_id, label,"
        " confidence, analyst_id, evidence, signature)"
        " VALUES (%s, 'binary', %s, 'packer', 0.1234, %s, %s, %s)",
        (classification_id, binary_id, analyst.user_id, Jsonb({"why": "entropy"}), sig),
    )
    flag_id, flag_response_id = uuid.uuid4(), uuid.uuid4()
    run(
        "INSERT INTO catalogue.flag (flag_id, viewer_request_id, note, signature, target_type,"
        " target_id) VALUES (%s, %s, 'looks mislabelled', %s, 'binary', %s)",
        (flag_id, viewer.user_id, sig, binary_id),
    )
    run(
        "INSERT INTO catalogue.flag_response (flag_response_id, analyst_request_id, note,"
        " signature, flag_id) VALUES (%s, %s, 'checked', %s, %s)",
        (flag_response_id, analyst.user_id, sig, flag_id),
    )

    # Append two entries to the chain tip, then checkpoint the whole chain.
    tip = run("SELECT integrity_id, chain_hash FROM catalogue.integrity ORDER BY integrity_id DESC LIMIT 1")
    tip_before, prev_hash = (tip[0][0], tip[0][1]) if tip else (0, None)
    integrity_ids = []
    for _ in range(2):
        chain_hash = _hex(32)
        integrity_ids.append(
            run(
                "INSERT INTO catalogue.integrity (source_id, source_type, record_hash, prev_hash,"
                " chain_hash, format_version, system_signature, system_uid)"
                " VALUES (%s, 'FIDBF', %s, %s, %s, 1, %s, %s) RETURNING integrity_id",
                (source_id, _hex(32), prev_hash, chain_hash, sig, system.user_id),
            )[0][0]
        )
        prev_hash = chain_hash
    leaf_count = run("SELECT count(*) FROM catalogue.integrity")[0][0]
    mmr_checkpoint_id = run(
        "INSERT INTO catalogue.mmr_checkpoint (last_integrity_id, leaf_count, peaks, commitment,"
        " format_version, system_uid, system_signature)"
        " VALUES (%s, %s, %s, %s, 1, %s, %s) RETURNING mmr_checkpoint_id",
        (integrity_ids[-1], leaf_count, Jsonb([{"height": 1, "hash": _hex(32)}]), _hex(32),
         system.user_id, sig),
    )[0][0]

    # The FIDBF object is revoked; nothing else is.
    revocation_id = run(
        "INSERT INTO catalogue.revocation (analyst_request_id, target_type, target_id, reason,"
        " request_signature) VALUES (%s, 'fidbf', %s, 'corrupt', %s) RETURNING revocation_id",
        (analyst.user_id, fidbf_id, sig),
    )[0][0]
    run(
        "UPDATE catalogue.revocation SET moderator_id = %s, decision = 'approved',"
        " decided_at = clock_timestamp(), decision_signature = %s WHERE revocation_id = %s",
        (moderator.user_id, sig, revocation_id),
    )

    return Corpus(
        analyst, viewer, source_id, batch_id, binary_id, binary_sha256, fidbf_id, function_ids,
        bsim_id, function_bsim_id, provenance_id, license_assertion_id, classification_id,
        flag_id, flag_response_id, integrity_ids, tip_before, mmr_checkpoint_id,
    )


@pytest.fixture
def headers(client, corpus) -> dict:
    # Any active account can read; use the least privileged role.
    return bearer(login(client, corpus.viewer))


def _routes(c: Corpus) -> list[tuple[str, str, str]]:
    """(list path with a filter that selects the fixture row, detail path, id field)."""
    return [
        ("/v1/sources?limit=500", f"/v1/sources/{c.source_id}", "source_id"),
        ("/v1/batches?limit=500", f"/v1/batches/{c.batch_id}", "batch_id"),
        (f"/v1/binaries?source_id={c.source_id}", f"/v1/binaries/{c.binary_id}", "binary_id"),
        (f"/v1/functions?binary_id={c.binary_id}", f"/v1/functions/{c.function_ids[0]}", "function_id"),
        (f"/v1/fidbf?binary_id={c.binary_id}", f"/v1/fidbf/{c.fidbf_id}", "fidbf_id"),
        (f"/v1/bsim?source_id={c.source_id}", f"/v1/bsim/{c.bsim_id}", "bsim_id"),
        (f"/v1/provenance?fidbf_id={c.fidbf_id}", f"/v1/provenance/{c.provenance_id}", "provenance_id"),
        (f"/v1/license-assertions?binary_id={c.binary_id}",
         f"/v1/license-assertions/{c.license_assertion_id}", "license_assertion_id"),
        (f"/v1/classifications?target_type=binary&target_id={c.binary_id}",
         f"/v1/classifications/{c.classification_id}", "classification_id"),
        (f"/v1/flags?target_type=binary&target_id={c.binary_id}", f"/v1/flags/{c.flag_id}", "flag_id"),
        (f"/v1/integrity?source_id={c.source_id}", f"/v1/integrity/{c.integrity_ids[0]}", "integrity_id"),
        ("/v1/mmr-checkpoints?limit=500", f"/v1/mmr-checkpoints/{c.mmr_checkpoint_id}",
         "mmr_checkpoint_id"),
    ]


def test_every_list_and_detail_route_serves_the_fixture(client, corpus, headers):
    for list_path, detail_path, key in _routes(corpus):
        listed = client.get(list_path, headers=headers)
        assert listed.status_code == 200, (list_path, listed.text)
        detail = client.get(detail_path, headers=headers)
        assert detail.status_code == 200, (detail_path, detail.text)
        assert detail.json()[key] in {row[key] for row in listed.json()}, list_path


def test_link_tables_are_listed(client, corpus, headers):
    links = client.get(f"/v1/function-bsim?bsim_id={corpus.bsim_id}", headers=headers).json()
    assert [(row["function_bsim_id"], row["function_id"]) for row in links] == [
        (str(corpus.function_bsim_id), str(corpus.function_ids[0]))
    ]
    responses = client.get(f"/v1/flag-responses?flag_id={corpus.flag_id}", headers=headers).json()
    assert [row["flag_response_id"] for row in responses] == [str(corpus.flag_response_id)]
    assert responses[0]["analyst_id"] == str(corpus.analyst.user_id)


def test_reads_require_login(client, corpus):
    for list_path, detail_path, _ in _routes(corpus):
        assert client.get(list_path).status_code == 401
        assert client.get(detail_path).status_code == 401


def test_unknown_ids_are_404(client, corpus, headers):
    for path in ("/v1/sources", "/v1/binaries", "/v1/fidbf", "/v1/bsim", "/v1/flags"):
        assert client.get(f"{path}/{uuid.uuid4()}", headers=headers).status_code == 404
    assert client.get("/v1/integrity/9000000000000000000", headers=headers).status_code == 404


def test_signatures_are_hex_and_large_numbers_are_exact(client, corpus, headers):
    source = client.get(f"/v1/sources/{corpus.source_id}", headers=headers).json()
    assert source["signature"] == "11" * 64
    binary = client.get(f"/v1/binaries/{corpus.binary_id}", headers=headers).json()
    assert binary["entry_point"] == str(U64_MAX) and binary["image_base"] == "0"
    function = client.get(f"/v1/functions/{corpus.function_ids[1]}", headers=headers).json()
    assert function["virtual_address"] == str(U64_MAX - 1)
    licence = client.get(
        f"/v1/license-assertions/{corpus.license_assertion_id}", headers=headers
    ).json()
    assert licence["confidence"] == "0.8500"
    integrity = client.get(f"/v1/integrity/{corpus.integrity_ids[0]}", headers=headers).json()
    assert integrity["system_signature"] == "11" * 64


def test_storage_paths_are_never_returned(client, corpus, headers):
    for list_path, detail_path, _ in _routes(corpus):
        for path in (list_path, detail_path):
            body = client.get(path, headers=headers).text
            assert "storage_path" not in body and SECRET_PATH not in body, path


def test_large_documents_only_on_detail_routes(client, corpus, headers):
    for list_path, detail_path, field in [
        (f"/v1/bsim?source_id={corpus.source_id}", f"/v1/bsim/{corpus.bsim_id}", "object_data"),
        (f"/v1/provenance?fidbf_id={corpus.fidbf_id}", f"/v1/provenance/{corpus.provenance_id}",
         "object_data"),
        (f"/v1/classifications?target_id={corpus.binary_id}",
         f"/v1/classifications/{corpus.classification_id}", "evidence"),
    ]:
        assert all(field not in row for row in client.get(list_path, headers=headers).json())
        assert client.get(detail_path, headers=headers).json()[field]
    provenance = client.get(f"/v1/provenance/{corpus.provenance_id}", headers=headers).json()
    assert provenance["has_object_data"] is True
    assert provenance["object_data"]["unmapped"]["relic"] == {"recipe": "make"}


def test_revoked_flag_marks_exactly_the_revoked_object(client, corpus, headers):
    assert client.get(f"/v1/fidbf/{corpus.fidbf_id}", headers=headers).json()["revoked"] is True
    assert client.get(f"/v1/binaries/{corpus.binary_id}", headers=headers).json()["revoked"] is False
    functions = client.get(f"/v1/functions?fidbf_id={corpus.fidbf_id}", headers=headers).json()
    assert {row["revoked"] for row in functions} == {False}


def test_cursor_paging_walks_every_row_once(client, corpus, headers):
    seen, after = [], None
    while True:
        params = {"binary_id": str(corpus.binary_id), "limit": 1}
        if after:
            params["after"] = after
        page = client.get("/v1/functions", params=params, headers=headers).json()
        if not page:
            break
        assert len(page) == 1
        seen.append(page[0]["function_id"])
        after = page[0]["function_id"]
    assert seen == sorted(seen, key=uuid.UUID)
    assert set(seen) == {str(function_id) for function_id in corpus.function_ids}


def test_integrity_chain_reads_in_order(client, corpus, headers):
    rows = client.get(
        "/v1/integrity", params={"after": corpus.tip_before, "limit": 2}, headers=headers
    ).json()
    assert [row["integrity_id"] for row in rows] == corpus.integrity_ids
    assert rows[1]["prev_hash"] == rows[0]["chain_hash"]

    latest = client.get("/v1/mmr-checkpoints/latest", headers=headers).json()
    assert latest["mmr_checkpoint_id"] == corpus.mmr_checkpoint_id
    assert latest["last_integrity_id"] == corpus.integrity_ids[-1]
    assert latest["peaks"][0]["height"] == 1


def test_filters_narrow_results(client, corpus, headers):
    by_hash = client.get(f"/v1/binaries?sha256={corpus.binary_sha256}", headers=headers).json()
    assert [row["binary_id"] for row in by_hash] == [str(corpus.binary_id)]
    assert client.get(f"/v1/binaries?sha256={'0' * 64}", headers=headers).json() == []
    flags = client.get(f"/v1/flags?target_type=fidbf&target_id={corpus.binary_id}", headers=headers)
    assert flags.json() == []


@pytest.mark.parametrize(
    "path",
    [
        "/v1/binaries?sha256=ABC",
        "/v1/binaries?md5=" + "0" * 31,
        "/v1/functions?after=not-a-uuid",
        "/v1/sources?limit=0",
        "/v1/sources?limit=501",
        "/v1/integrity?after=-1",
        f"/v1/integrity?after={2**63}",
        f"/v1/integrity/{2**63}",
        "/v1/integrity/0",
        "/v1/classifications?target_type=source",
        "/v1/flags?target_type=integrity",
    ],
)
def test_invalid_parameters_are_422(client, corpus, headers, path):
    assert client.get(path, headers=headers).status_code == 422


def test_download_is_still_501(client, corpus, headers):
    assert client.get(f"/v1/fidbf/{corpus.fidbf_id}/download", headers=headers).status_code == 501


# ---------------------------------------------------------------------------
# End to end: admit through the Rust signer and ingester, read through the API
# ---------------------------------------------------------------------------

SIGN_FIDBF = REPO / "target/debug/relic-sign-fidbf"
INGEST_FIDBF = REPO / "target/debug/relic-ingest-fidbf"


def _ssh_account(database, tmp_path: Path, name: str, role: str | None, owner: str) -> tuple[uuid.UUID, Path]:
    key_path = tmp_path / name
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key_path)], check=True)
    user_id = database.execute(
        "INSERT INTO catalogue.user_public (public_key, role, owner_type)"
        " VALUES (%s, %s::catalogue.account_role, %s::catalogue.account_owner_type) RETURNING user_id",
        (_openssh_public_key(key_path.with_suffix(".pub")), role, owner),
    )[0][0]
    return user_id, key_path


@pytest.mark.skipif(
    not (SIGN_FIDBF.exists() and INGEST_FIDBF.exists()),
    reason="build with: cargo build -p relic-ingest",
)
def test_rust_admitted_fidbf_reads_back_exactly(client, database, corpus, headers, tmp_path: Path):
    analyst_id, analyst_key = _ssh_account(database, tmp_path, "analyst", "analyst", "human")
    system_id, system_key = _ssh_account(database, tmp_path, "integrity", None, "system")

    obj = tmp_path / "object.fidbf"
    obj.write_bytes(b"opaque fidbf " + secrets.token_bytes(16))
    data = obj.read_bytes()
    ids = {name: uuid.uuid4() for name in ("source", "batch", "binary", "fidbf", "f1", "f2")}
    manifest = {
        "analyst_user_id": str(analyst_id),
        "source": {
            "source_id": str(ids["source"]), "name": "rust e2e", "source_type": "FIDBF",
            "reference": None, "snapshot_version": "v1",
            "retrieved_at": "2026-11-22T12:00:00Z", "is_ecological": False,
        },
        "batch": {"batch_id": str(ids["batch"])},
        "binary": {
            "binary_id": str(ids["binary"]), "content_sha256": _hex(32), "content_md5": _hex(16),
            "size_bytes": 4096, "original_filename": "e2e.bin", "format": "ELF",
            "architecture": "x86_64", "bit_width": 64, "endianness": "little", "platform": "linux",
            "abi": None, "object_type": None, "entry_point": str(U64_MAX), "image_base": "0",
            "build_id": None, "is_stripped": False, "compiler": "gcc", "version": None,
        },
        "fidbf": {
            "fidbf_id": str(ids["fidbf"]), "storage_path": SECRET_PATH + "/e2e.fidbf",
            "sha256": hashlib.sha256(data).hexdigest(), "md5": hashlib.md5(data).hexdigest(),
        },
        "functions": [
            {"function_id": str(ids[name]), "name": name, "full_hash": _hex(8),
             "specific_hash": _hex(8), "file_offset": 0, "virtual_address": str(U64_MAX - n),
             "size_bytes": 16, "section_name": ".text", "symbol_name": None,
             "mangled_name": None, "demangled_name": None}
            for n, name in enumerate(("f1", "f2"))
        ],
    }
    manifest_path, signed_path = tmp_path / "manifest.json", tmp_path / "signed.json"
    manifest_path.write_text(json.dumps(manifest))
    subprocess.run(
        [str(SIGN_FIDBF), "--manifest", str(manifest_path), "--fidbf-object", str(obj),
         "--analyst-key", str(analyst_key), "--output", str(signed_path)],
        check=True, capture_output=True, text=True,
    )
    signatures = json.loads(signed_path.read_text())["analyst_signatures"]
    subprocess.run(
        [str(INGEST_FIDBF), "--database-url", database.worker_url, "--manifest", str(signed_path),
         "--fidbf-object", str(obj), "--integrity-system-user-id", str(system_id),
         "--integrity-key", str(system_key)],
        check=True, capture_output=True, text=True,
    )

    get = lambda path: client.get(path, headers=headers)  # noqa: E731
    assert get(f"/v1/sources/{ids['source']}").json()["signature"] == signatures["source"]
    assert get(f"/v1/batches/{ids['batch']}").json()["signature"] == signatures["batch"]
    fidbf = get(f"/v1/fidbf/{ids['fidbf']}").json()
    assert fidbf["signature"] == signatures["fidbf"]
    assert fidbf["sha256"] == manifest["fidbf"]["sha256"] and fidbf["revoked"] is False
    binary = get(f"/v1/binaries/{ids['binary']}").json()
    assert binary["entry_point"] == str(U64_MAX)
    functions = get(f"/v1/functions?fidbf_id={ids['fidbf']}").json()
    assert {row["function_id"] for row in functions} == {str(ids["f1"]), str(ids["f2"])}
    entries = get(f"/v1/integrity?source_id={ids['source']}").json()
    assert len(entries) == 1 and entries[0]["system_uid"] == str(system_id)
    assert len(bytes.fromhex(entries[0]["system_signature"])) == 64
    assert SECRET_PATH not in get(f"/v1/fidbf?source_id={ids['source']}").text
