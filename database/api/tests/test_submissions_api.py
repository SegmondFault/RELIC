"""FIDBF, BSim and provenance submissions: staged by the API, admitted by relic-admit.

The API never holds the integrity key. These tests drive the whole path:
the Analyst signs on their machine (relic-sign-fidbf, relic-sign-challenge),
the API stages, relic-admit (as relic_worker, with the integrity key) admits
or rejects, the catalogue serves the result and relic-verify agrees. They
also play a compromised API: staged rows and files it could forge are
rejected and change nothing.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import subprocess
import uuid
from dataclasses import dataclass
from pathlib import Path

import psycopg
import pytest
from fastapi.testclient import TestClient

from api.main import create_app

from .conftest import REPO, make_settings
from .test_auth_api import _login_with_cli
from .test_catalogue_api import SIGN_FIDBF, U64_MAX, _hex, _ssh_account

SIGNER = REPO / "target/debug/relic-sign-challenge"
ADMIT = REPO / "target/debug/relic-admit"
VERIFY = REPO / "target/debug/relic-verify"

pytestmark = pytest.mark.skipif(
    not all(path.exists() for path in (SIGN_FIDBF, SIGNER, ADMIT, VERIFY)),
    reason="build with: cargo build -p relic-ingest -p relic-verify",
)


def bearer(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


@dataclass
class Setup:
    analyst_id: uuid.UUID
    analyst_key: Path
    headers: dict
    system_id: uuid.UUID
    system_key: Path
    tmp: Path


@pytest.fixture
def setup(client, database, tmp_path: Path) -> Setup:
    analyst_id, analyst_key = _ssh_account(database, tmp_path, "analyst", "analyst", "human")
    system_id, system_key = _ssh_account(database, tmp_path, "integrity", None, "system")
    headers = bearer(_login_with_cli(client, analyst_id, analyst_key, tmp_path))
    return Setup(analyst_id, analyst_key, headers, system_id, system_key, tmp_path)


def run_admit(database, object_dirs, setup: Setup) -> str:
    result = subprocess.run(
        [str(ADMIT), "--database-url", database.worker_url, "--once",
         "--integrity-system-user-id", str(setup.system_id),
         "--integrity-key", str(setup.system_key),
         "--staging-dir", str(object_dirs.staging), "--fidbf-root", str(object_dirs.store)],
        capture_output=True, text=True, timeout=120,
    )
    assert result.returncode == 0, result.stderr
    return result.stdout


def cli(*args: str) -> dict:
    result = subprocess.run([str(SIGNER), *args], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


@dataclass
class Fidbf:
    data: bytes
    sha256: str
    signed: dict
    ids: dict[str, uuid.UUID]


def signed_fidbf(setup: Setup, *, key: Path | None = None, canonical: bool = True) -> Fidbf:
    data = b"fidbf object " + secrets.token_bytes(64)
    obj = setup.tmp / f"{uuid.uuid4()}.fidbf"
    obj.write_bytes(data)
    sha256 = hashlib.sha256(data).hexdigest()
    ids = {name: uuid.uuid4() for name in ("source", "batch", "binary", "fidbf", "f1", "f2")}
    manifest = {
        "analyst_user_id": str(setup.analyst_id),
        "source": {
            "source_id": str(ids["source"]), "name": "staged", "source_type": "FIDBF",
            "reference": None, "snapshot_version": "v1",
            "retrieved_at": "2026-11-23T12:00:00Z", "is_ecological": False,
        },
        "batch": {"batch_id": str(ids["batch"])},
        "binary": {
            "binary_id": str(ids["binary"]), "content_sha256": _hex(32), "content_md5": _hex(16),
            "size_bytes": 4096, "original_filename": "a.bin", "format": "ELF",
            "architecture": "x86_64", "bit_width": 64, "endianness": "little", "platform": "linux",
            "abi": None, "object_type": None, "entry_point": str(U64_MAX), "image_base": "0",
            "build_id": None, "is_stripped": False, "compiler": "gcc", "version": None,
        },
        "fidbf": {
            "fidbf_id": str(ids["fidbf"]), "storage_path": "chosen/by/analyst.fidbf",
            "sha256": sha256, "md5": hashlib.md5(data).hexdigest(),
        },
        "functions": [
            {"function_id": str(ids[name]), "name": name, "full_hash": _hex(8),
             "specific_hash": _hex(8), "file_offset": 0, "virtual_address": str(n),
             "size_bytes": 16, "section_name": ".text", "symbol_name": None,
             "mangled_name": None, "demangled_name": None}
            for n, name in enumerate(("f1", "f2"))
        ],
    }
    manifest_path, signed_path = setup.tmp / "manifest.json", setup.tmp / "signed.json"
    manifest_path.write_text(json.dumps(manifest))
    subprocess.run(
        [str(SIGN_FIDBF), "--manifest", str(manifest_path), "--fidbf-object", str(obj),
         "--analyst-key", str(key or setup.analyst_key), "--output", str(signed_path),
         *(["--canonical-storage-path"] if canonical else [])],
        check=True, capture_output=True, text=True,
    )
    return Fidbf(data, sha256, json.loads(signed_path.read_text()), ids)


def upload(client, setup: Setup, fidbf: Fidbf):
    return client.put(
        f"/v1/fidbf-objects/{fidbf.sha256}", content=fidbf.data,
        headers={**setup.headers, "content-type": "application/octet-stream"},
    )


def status(client, setup: Setup, submission_id) -> dict:
    response = client.get(f"/v1/submissions/{submission_id}", headers=setup.headers)
    assert response.status_code == 200, response.text
    return response.json()


def verify_report(database) -> dict:
    result = subprocess.run(
        [str(VERIFY), "--database-url", database.auditor_url, "--json"],
        capture_output=True, text=True, timeout=120,
    )
    return json.loads(result.stdout)


def failures(report: dict, row_id) -> list[str]:
    return [f["problem"] for f in report["failures"] if f["id"] == str(row_id)]


def admitted_fidbf(client, database, object_dirs, setup: Setup) -> Fidbf:
    fidbf = signed_fidbf(setup)
    assert upload(client, setup, fidbf).status_code == 201
    assert client.post("/v1/fidbf", json=fidbf.signed, headers=setup.headers).status_code == 202
    run_admit(database, object_dirs, setup)
    assert status(client, setup, fidbf.ids["fidbf"])["status"] == "admitted"
    return fidbf


# ---------------------------------------------------------------------------
# FIDBF: upload, stage, admit, download
# ---------------------------------------------------------------------------


def test_fidbf_is_staged_admitted_and_downloadable(client, database, object_dirs, setup):
    fidbf = signed_fidbf(setup)
    first = upload(client, setup, fidbf)
    assert first.status_code == 201, first.text
    assert first.json() == {"sha256": fidbf.sha256, "md5": hashlib.md5(fidbf.data).hexdigest(),
                            "size_bytes": len(fidbf.data)}
    assert upload(client, setup, fidbf).status_code == 200  # already staged
    assert (object_dirs.staging / f"{fidbf.sha256}.fidbf").read_bytes() == fidbf.data

    staged = client.post("/v1/fidbf", json=fidbf.signed, headers=setup.headers)
    assert staged.status_code == 202, staged.text
    body = staged.json()
    fidbf_id = str(fidbf.ids["fidbf"])
    assert (body["submission_id"], body["kind"], body["status"]) == (fidbf_id, "fidbf", "pending")
    assert body["status_url"] == f"/v1/submissions/{fidbf_id}"
    assert client.post("/v1/fidbf", json=fidbf.signed, headers=setup.headers).status_code == 200
    # Nothing is in the catalogue before relic-admit runs.
    assert client.get(f"/v1/fidbf/{fidbf_id}", headers=setup.headers).status_code == 404

    output = run_admit(database, object_dirs, setup)
    assert f"admitted fidbf {fidbf_id}" in output
    done = status(client, setup, fidbf_id)
    assert done["status"] == "admitted" and done["decided_at"] and done["error"] is None
    assert done["result"]["function_count"] == 2 and done["result"]["integrity_id"] > 0
    assert client.get(f"/v1/fidbf/{fidbf_id}", headers=setup.headers).json()["sha256"] == fidbf.sha256
    assert not (object_dirs.staging / f"{fidbf.sha256}.fidbf").exists()
    stored = object_dirs.store / fidbf.sha256[:2] / f"{fidbf.sha256}.fidbf"
    assert stored.read_bytes() == fidbf.data

    download = client.get(f"/v1/fidbf/{fidbf_id}/download", headers=setup.headers)
    assert download.status_code == 200 and download.content == fidbf.data
    assert download.headers["x-content-sha256"] == fidbf.sha256
    assert download.headers["content-type"] == "application/octet-stream"
    assert fidbf_id in download.headers["content-disposition"]

    report = verify_report(database)
    for row_id in (fidbf.ids["fidbf"], fidbf.ids["source"]):
        assert failures(report, row_id) == []
    # Retrying after admission returns the admitted status.
    again = client.post("/v1/fidbf", json=fidbf.signed, headers=setup.headers)
    assert again.status_code == 200 and again.json()["status"] == "admitted"


def test_upload_rules(client, setup, object_dirs, database):
    fidbf = signed_fidbf(setup)
    wrong = client.put(f"/v1/fidbf-objects/{'0' * 64}", content=fidbf.data, headers=setup.headers)
    assert wrong.status_code == 422 and "SHA-256" in wrong.json()["detail"]
    empty = hashlib.sha256(b"").hexdigest()
    assert client.put(f"/v1/fidbf-objects/{empty}", content=b"", headers=setup.headers).status_code == 422
    assert client.put("/v1/fidbf-objects/NOTHEX", content=b"x", headers=setup.headers).status_code == 422
    assert list(object_dirs.staging.glob("*.part")) == []
    assert not (object_dirs.staging / f"{'0' * 64}.fidbf").exists()

    viewer_id, viewer_key = _ssh_account(database, setup.tmp, "viewer", "viewer", "human")
    viewer = bearer(_login_with_cli(client, viewer_id, viewer_key, setup.tmp))
    assert client.put(f"/v1/fidbf-objects/{fidbf.sha256}", content=fidbf.data,
                      headers=viewer).status_code == 403


def test_upload_limit(database, object_dirs, setup):
    settings = make_settings(database.app_url, staging_dir=object_dirs.staging,
                             fidbf_root=object_dirs.store, max_object_bytes=1024)
    data = secrets.token_bytes(2048)
    with TestClient(create_app(settings)) as small:
        response = small.put(f"/v1/fidbf-objects/{hashlib.sha256(data).hexdigest()}",
                             content=data, headers=setup.headers)
    assert response.status_code == 413
    assert list(object_dirs.staging.glob("*.part")) == []


def test_manifest_rules(client, database, setup):
    fidbf = signed_fidbf(setup)
    missing = client.post("/v1/fidbf", json=fidbf.signed, headers=setup.headers)
    assert missing.status_code == 422 and "Upload the object first" in missing.json()["detail"]
    assert upload(client, setup, fidbf).status_code == 201

    chosen = signed_fidbf(setup, canonical=False)
    upload(client, setup, chosen)
    path = client.post("/v1/fidbf", json=chosen.signed, headers=setup.headers)
    assert path.status_code == 422 and "storage_path" in path.json()["detail"]

    other_id, _ = _ssh_account(database, setup.tmp, "other", "analyst", "human")
    someone_else = {**fidbf.signed, "analyst_user_id": str(other_id)}
    assert client.post("/v1/fidbf", json=someone_else, headers=setup.headers).status_code == 403

    assert client.post("/v1/fidbf", json=fidbf.signed, headers=setup.headers).status_code == 202
    changed = json.loads(json.dumps(fidbf.signed))
    changed["source"]["name"] = "changed"
    reused = client.post("/v1/fidbf", json=changed, headers=setup.headers)
    assert reused.status_code == 409


def test_forged_fidbf_is_rejected_and_admits_nothing(client, database, object_dirs, setup):
    fidbf = signed_fidbf(setup, key=_ssh_account(database, setup.tmp, "thief", "analyst", "human")[1])
    upload(client, setup, fidbf)
    assert client.post("/v1/fidbf", json=fidbf.signed, headers=setup.headers).status_code == 202
    run_admit(database, object_dirs, setup)
    done = status(client, setup, fidbf.ids["fidbf"])
    assert done["status"] == "rejected" and "signature" in done["error"]
    assert client.get(f"/v1/fidbf/{fidbf.ids['fidbf']}", headers=setup.headers).status_code == 404
    assert client.get(f"/v1/sources/{fidbf.ids['source']}", headers=setup.headers).status_code == 404


# ---------------------------------------------------------------------------
# BSim and provenance
# ---------------------------------------------------------------------------


def test_bsim_and_provenance_are_admitted_and_verify(client, database, object_dirs, setup):
    fidbf = admitted_fidbf(client, database, object_dirs, setup)
    obj = setup.tmp / "bsim.json"
    obj.write_text('{"signature": [1, 2, 3],  "vector": {"b": 0.5, "a": 1e3}}\n')
    links = setup.tmp / "links.json"
    links.write_text(json.dumps([
        {"function_id": str(fidbf.ids[name]), "binary_id": str(fidbf.ids["binary"])}
        for name in ("f2", "f1")
    ]))
    common = ("--analyst-id", str(setup.analyst_id), "--source-id", str(fidbf.ids["source"]),
              "--key", str(setup.analyst_key))
    bsim = cli("sign-bsim", *common, "--object", str(obj), "--functions", str(links))
    staged = client.post("/v1/bsim", json=bsim, headers=setup.headers)
    assert staged.status_code == 202, staged.text

    seal = setup.tmp / "seal.json"
    seal.write_text('{"class_uid": 5020, "unmapped": {"relic": {"recipe": "make all"}}}')
    provenance = cli("sign-provenance", *common, "--bsim-id", bsim["bsim_id"],
                     "--schema-name", "ocsf", "--schema-version", "1.3.0", "--object", str(seal))
    assert client.post("/v1/provenance", json=provenance, headers=setup.headers).status_code == 202

    output = run_admit(database, object_dirs, setup)
    assert f"admitted bsim {bsim['bsim_id']}" in output, output
    assert f"admitted provenance {provenance['provenance_id']}" in output, output

    detail = client.get(f"/v1/bsim/{bsim['bsim_id']}", headers=setup.headers).json()
    assert detail["object_data"] == json.loads(obj.read_text())
    assert detail["sha256"] == hashlib.sha256(obj.read_bytes()).hexdigest()
    links_read = client.get(f"/v1/function-bsim?bsim_id={bsim['bsim_id']}", headers=setup.headers)
    assert len(links_read.json()) == 2
    read = client.get(f"/v1/provenance/{provenance['provenance_id']}", headers=setup.headers)
    assert read.json()["bsim_id"] == bsim["bsim_id"]

    report = verify_report(database)
    assert failures(report, bsim["bsim_id"]) == []
    assert failures(report, provenance["provenance_id"]) == []
    assert report["checked"]["BSim objects"] >= 1 and report["checked"]["provenance seals"] >= 1
    assert report["checked"]["provenance chain entries"] >= 1
    assert not any("BSim" in kind for kind in report["unchecked"])


def test_bsim_and_provenance_validation(client, setup):
    base = {"bsim_id": str(uuid.uuid4()), "analyst_id": str(setup.analyst_id),
            "source_id": str(uuid.uuid4()), "object_json": "{}",
            "functions": [{"function_id": str(uuid.uuid4()), "binary_id": str(uuid.uuid4())}],
            "signature": "00" * 64}
    for change in ({"object_json": "[1]"}, {"functions": []}, {"functions": base["functions"] * 2},
                   {"unknown": 1}, {"object_json": '{"a": 1, "a": 2}'}):
        response = client.post("/v1/bsim", json={**base, **change}, headers=setup.headers)
        assert response.status_code == 422, change
    no_target = {"provenance_id": str(uuid.uuid4()), "analyst_id": str(setup.analyst_id),
                 "source_id": str(uuid.uuid4()), "object_json": "{}", "signature": "00" * 64}
    assert client.post("/v1/provenance", json=no_target, headers=setup.headers).status_code == 422


# ---------------------------------------------------------------------------
# A compromised API
# ---------------------------------------------------------------------------


def _stage_as_app(database, submission_id, kind: str, analyst_id, payload: str, sha256=None):
    with psycopg.connect(database.app_url, autocommit=True) as conn:
        conn.execute(
            "INSERT INTO catalogue.submission (submission_id, kind, analyst_id, payload_json,"
            " object_sha256) VALUES (%s, %s, %s, %s, %s)",
            (submission_id, kind, analyst_id, payload, sha256),
        )


def test_altered_payloads_are_rejected(client, database, object_dirs, setup):
    fidbf = admitted_fidbf(client, database, object_dirs, setup)
    obj = setup.tmp / "bsim.json"
    obj.write_text('{"k": 1}')
    links = setup.tmp / "links.json"
    links.write_text(json.dumps([{"function_id": str(fidbf.ids["f1"]),
                                  "binary_id": str(fidbf.ids["binary"])}]))
    bsim = cli("sign-bsim", "--analyst-id", str(setup.analyst_id), "--source-id",
               str(fidbf.ids["source"]), "--object", str(obj), "--functions", str(links),
               "--key", str(setup.analyst_key))
    # The API rewrites the object after the Analyst signed it.
    altered = {**bsim, "object_json": '{"k": 2}'}
    _stage_as_app(database, bsim["bsim_id"], "bsim", setup.analyst_id, json.dumps(altered))
    # A submission whose ID is not its object's.
    other = str(uuid.uuid4())
    _stage_as_app(database, other, "bsim", setup.analyst_id, json.dumps(bsim))
    run_admit(database, object_dirs, setup)
    assert "signature" in status(client, setup, bsim["bsim_id"])["error"]
    assert "ID does not match" in status(client, setup, other)["error"]
    assert client.get(f"/v1/bsim/{bsim['bsim_id']}", headers=setup.headers).status_code == 404


def test_staged_symlink_is_never_followed(client, database, object_dirs, setup):
    """The API could stage a link to a host file and claim its digest."""
    secret = setup.tmp / "host-secret"
    secret.write_bytes(b"-----BEGIN OPENSSH PRIVATE KEY----- not really")
    sha256 = hashlib.sha256(secret.read_bytes()).hexdigest()
    os.symlink(secret, object_dirs.staging / f"{sha256}.fidbf")
    fidbf = signed_fidbf(setup)
    manifest = json.loads(json.dumps(fidbf.signed))
    manifest["fidbf"].update(sha256=sha256, md5=hashlib.md5(secret.read_bytes()).hexdigest(),
                             storage_path=f"{sha256[:2]}/{sha256}.fidbf")
    _stage_as_app(database, fidbf.ids["fidbf"], "fidbf", setup.analyst_id, json.dumps(manifest), sha256)
    run_admit(database, object_dirs, setup)
    done = status(client, setup, fidbf.ids["fidbf"])
    assert done["status"] == "rejected" and "not staged" in done["error"]
    assert not (object_dirs.store / sha256[:2] / f"{sha256}.fidbf").exists()
    (object_dirs.staging / f"{sha256}.fidbf").unlink()


def test_submission_rows_are_guarded(database, setup):
    submission_id = uuid.uuid4()
    _stage_as_app(database, submission_id, "provenance", setup.analyst_id, "{}")
    with psycopg.connect(database.app_url, autocommit=True) as conn:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute("UPDATE catalogue.submission SET status = 'admitted',"
                         " result = '{}' WHERE submission_id = %s", (submission_id,))
    with psycopg.connect(database.worker_url, autocommit=True) as conn:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute("UPDATE catalogue.submission SET payload_json = 'x'"
                         " WHERE submission_id = %s", (submission_id,))
        conn.execute("UPDATE catalogue.submission SET status = 'rejected', error = 'test'"
                     " WHERE submission_id = %s", (submission_id,))
        with pytest.raises(psycopg.errors.IntegrityConstraintViolation, match="already rejected"):
            conn.execute("UPDATE catalogue.submission SET status = 'pending', error = NULL,"
                         " decided_at = NULL WHERE submission_id = %s", (submission_id,))


def test_status_is_private_to_submitter_and_moderators(client, database, setup):
    submission_id = uuid.uuid4()
    _stage_as_app(database, submission_id, "provenance", setup.analyst_id, "{}")
    other_id, other_key = _ssh_account(database, setup.tmp, "other", "analyst", "human")
    other = bearer(_login_with_cli(client, other_id, other_key, setup.tmp))
    assert client.get(f"/v1/submissions/{submission_id}", headers=other).status_code == 404
    moderator_id, moderator_key = _ssh_account(database, setup.tmp, "mod", "moderator", "human")
    moderator = bearer(_login_with_cli(client, moderator_id, moderator_key, setup.tmp))
    assert client.get(f"/v1/submissions/{submission_id}", headers=moderator).status_code == 200
    own = client.get("/v1/submissions?status=pending", headers=setup.headers).json()
    assert str(submission_id) in [row["submission_id"] for row in own]
    assert client.get("/v1/submissions", headers=other).json() == []


# ---------------------------------------------------------------------------
# Limits: upload slots, daily budget, staging cap, downloads
# ---------------------------------------------------------------------------


def _small_app(database, object_dirs, **limits) -> TestClient:
    settings = make_settings(database.app_url, staging_dir=object_dirs.staging,
                             fidbf_root=object_dirs.store, **limits)
    return TestClient(create_app(settings))


def _object(size: int = 4096) -> tuple[bytes, str]:
    data = secrets.token_bytes(size)
    return data, hashlib.sha256(data).hexdigest()


def test_upload_needs_a_content_length(client, setup):
    data, sha256 = _object()
    response = client.put(f"/v1/fidbf-objects/{sha256}", content=iter([data]),
                          headers=setup.headers)
    assert response.status_code == 411


def test_upload_slots_per_analyst_and_overall(client, database, setup):
    slots = client.app.state.upload_slots
    key = str(setup.analyst_id)
    data, sha256 = _object()
    # Two uploads of this Analyst already in progress.
    assert slots.acquire(key, 2, 8) and slots.acquire(key, 2, 8)
    try:
        busy = client.put(f"/v1/fidbf-objects/{sha256}", content=data, headers=setup.headers)
        assert busy.status_code == 429 and busy.headers["retry-after"] == "30"
    finally:
        slots.release(key)
        slots.release(key)
    # Eight in progress across other Analysts: everyone waits.
    others = [str(uuid.uuid4()) for _ in range(8)]
    for other in others:
        assert slots.acquire(other, 2, 8)
    try:
        assert client.put(f"/v1/fidbf-objects/{sha256}", content=data,
                          headers=setup.headers).status_code == 503
    finally:
        for other in others:
            slots.release(other)
    assert client.put(f"/v1/fidbf-objects/{sha256}", content=data,
                      headers=setup.headers).status_code == 201


def test_daily_upload_budget_per_analyst(database, object_dirs, setup):
    with _small_app(database, object_dirs, upload_bytes_per_analyst_per_day=10_000) as small:
        first, first_sha = _object(6000)
        second, second_sha = _object(6000)
        assert small.put(f"/v1/fidbf-objects/{first_sha}", content=first,
                         headers=setup.headers).status_code == 201
        refused = small.put(f"/v1/fidbf-objects/{second_sha}", content=second,
                            headers=setup.headers)
        assert refused.status_code == 429 and "budget" in refused.json()["detail"]
        assert not (object_dirs.staging / f"{second_sha}.fidbf").exists()
        # Another Analyst has a budget of their own.
        other_id, other_key = _ssh_account(database, setup.tmp, "other", "analyst", "human")
        other = bearer(_login_with_cli(small, other_id, other_key, setup.tmp))
        assert small.put(f"/v1/fidbf-objects/{second_sha}", content=second,
                         headers=other).status_code == 201


def test_staging_cap_counts_the_incoming_object(database, object_dirs, setup):
    used = sum(f.stat().st_size for f in object_dirs.staging.iterdir() if f.is_file())
    data, sha256 = _object(8192)
    with _small_app(database, object_dirs, max_staging_bytes=used + 8191) as small:
        full = small.put(f"/v1/fidbf-objects/{sha256}", content=data, headers=setup.headers)
    assert full.status_code == 507
    with _small_app(database, object_dirs, max_staging_bytes=used + 8192) as small:
        assert small.put(f"/v1/fidbf-objects/{sha256}", content=data,
                         headers=setup.headers).status_code == 201


def test_downloads_are_limited_and_revoked_objects_withheld(client, database, object_dirs, setup):
    fidbf = admitted_fidbf(client, database, object_dirs, setup)
    url = f"/v1/fidbf/{fidbf.ids['fidbf']}/download"
    with _small_app(database, object_dirs, download_rate_limit_per_hour=2) as small:
        assert [small.get(url, headers=setup.headers).status_code for _ in range(3)] == [200, 200, 429]
        # The limit is per account, not per address.
        viewer_id, viewer_key = _ssh_account(database, setup.tmp, "viewer", "viewer", "human")
        viewer = bearer(_login_with_cli(small, viewer_id, viewer_key, setup.tmp))
        assert small.get(url, headers=viewer).status_code == 200

    database.revoke(fidbf.ids["fidbf"], "fidbf")
    gone = client.get(url, headers=setup.headers)
    assert gone.status_code == 410
    moderator_id, moderator_key = _ssh_account(database, setup.tmp, "mod", "moderator", "human")
    moderator = bearer(_login_with_cli(client, moderator_id, moderator_key, setup.tmp))
    assert client.get(url, headers=moderator).content == fidbf.data


# ---------------------------------------------------------------------------
# Rejection reasons and worker start-up
# ---------------------------------------------------------------------------


def test_rejection_reasons_never_carry_database_detail(client, database, object_dirs, setup):
    fidbf = admitted_fidbf(client, database, object_dirs, setup)
    obj = setup.tmp / "bsim.json"
    obj.write_text('{"k": 1}')
    links = setup.tmp / "links.json"
    unknown_function = uuid.uuid4()
    links.write_text(json.dumps([{"function_id": str(unknown_function),
                                  "binary_id": str(fidbf.ids["binary"])}]))
    bsim = cli("sign-bsim", "--analyst-id", str(setup.analyst_id), "--source-id",
               str(fidbf.ids["source"]), "--object", str(obj), "--functions", str(links),
               "--key", str(setup.analyst_key))
    assert client.post("/v1/bsim", json=bsim, headers=setup.headers).status_code == 202
    output = run_admit(database, object_dirs, setup)
    error = status(client, setup, bsim["bsim_id"])["error"]
    assert error.startswith("rejected by the database:") and "foreign key" in error
    assert str(unknown_function) not in error and "Key (" not in error
    # The worker's own log keeps the detail.
    assert str(unknown_function) in output


def test_worker_refuses_to_start_with_the_wrong_integrity_key(database, object_dirs, setup):
    _, other_key = _ssh_account(database, setup.tmp, "not-integrity", None, "system")
    result = subprocess.run(
        [str(ADMIT), "--database-url", database.worker_url, "--once",
         "--integrity-system-user-id", str(setup.system_id), "--integrity-key", str(other_key),
         "--staging-dir", str(object_dirs.staging), "--fidbf-root", str(object_dirs.store)],
        capture_output=True, text=True, timeout=60,
    )
    assert result.returncode != 0 and "integrity account" in result.stderr


# ---------------------------------------------------------------------------
# Long transfers hold no database connection
# ---------------------------------------------------------------------------


def _connections_in_use(app) -> int:
    stats = app.state.pool.get_stats()
    return stats["pool_size"] - stats["pool_available"]


def test_transfers_hold_no_pooled_connection(client, database, object_dirs, setup, monkeypatch):
    """A slow upload or download must not keep a connection from the pool of 10:
    a few slow clients would otherwise make every route fail."""
    from api.routers import catalogue, submissions

    seen: dict[str, int] = {}
    receive, read_chunks = submissions._receive_object, catalogue._read_chunks

    async def receiving(*args, **kwargs):
        seen["upload"] = _connections_in_use(client.app)
        return await receive(*args, **kwargs)

    def reading(descriptor):
        seen["download"] = _connections_in_use(client.app)
        yield from read_chunks(descriptor)

    monkeypatch.setattr(submissions, "_receive_object", receiving)
    monkeypatch.setattr(catalogue, "_read_chunks", reading)
    fidbf = admitted_fidbf(client, database, object_dirs, setup)
    assert client.get(f"/v1/fidbf/{fidbf.ids['fidbf']}/download",
                      headers=setup.headers).content == fidbf.data
    assert seen == {"upload": 0, "download": 0}
