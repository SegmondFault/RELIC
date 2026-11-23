"""relic-verify: genuine rows verify; rows a compromised API could write are reported.

The session database also holds fixture rows with placeholder signatures
(written as the owner), which relic-verify rightly reports. These tests
therefore check specific rows by ID rather than an overall clean result;
docs/workers.md describes the clean run.
"""

from __future__ import annotations

import json
import subprocess
import uuid
from pathlib import Path

import psycopg
import pytest
from nacl.signing import SigningKey

from .conftest import REPO, decision_body, login, registration_body
from .test_catalogue_api import RUST_ADMISSION, admit_fidbf
from .test_flags_api import flag_body, response_body
from .test_revocations_api import decision_body as revocation_decision
from .test_revocations_api import request_body as revocation_request

VERIFY = REPO / "target/debug/relic-verify"

pytestmark = pytest.mark.skipif(
    not (VERIFY.exists() and RUST_ADMISSION),
    reason="build with: cargo build -p relic-verify -p relic-ingest",
)


def bearer(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def run_verify(url: str, *args: str) -> tuple[int, str]:
    result = subprocess.run(
        [str(VERIFY), "--database-url", url, *args], capture_output=True, text=True, timeout=120
    )
    return result.returncode, result.stdout + result.stderr


def verify_json(database) -> tuple[int, dict]:
    code, output = run_verify(database.auditor_url, "--json")
    return code, json.loads(output)


def failures_for(report: dict, row_id) -> list[str]:
    return [f["problem"] for f in report["failures"] if f["id"] == str(row_id)]


def _register(client, role: str) -> str:
    body = registration_body(client, SigningKey.generate(), role=role)
    response = client.post("/v1/accounts", json=body)
    assert response.status_code == 202, response.text
    return response.json()["registration_request_id"]


def _approve(client, moderator, request_id: str):
    headers = bearer(login(client, moderator))
    request = client.get(f"/v1/registrations/{request_id}", headers=headers).json()
    return client.post(
        f"/v1/registrations/{request_id}/decision",
        json=decision_body(request, moderator),
        headers=headers,
    )


def test_genuine_rows_verify_and_forgeries_are_reported(client, database, tmp_path: Path):
    moderators = [database.create_user("moderator") for _ in range(2)]
    analyst = database.create_user("analyst")
    viewer = database.create_user("viewer")
    analyst_headers = bearer(login(client, analyst))
    viewer_headers = bearer(login(client, viewer))

    # --- Genuine rows, written through the API and the Rust tools ----------
    analyst_request = _register(client, "analyst")
    assert _approve(client, moderators[0], analyst_request).status_code == 200
    moderator_request = _register(client, "moderator")
    assert _approve(client, moderators[0], moderator_request).status_code == 202
    assert _approve(client, moderators[1], moderator_request).status_code == 200

    # Accounts are revoked at a Moderator's request.
    revocation = client.post(
        "/v1/revocations", json=revocation_request(moderators[0], viewer.user_id),
        headers=bearer(login(client, moderators[0])),
    ).json()
    decided = client.post(
        f"/v1/revocations/{revocation['revocation_id']}/decision",
        json=revocation_decision(revocation, moderators[1], "rejected"),
        headers=bearer(login(client, moderators[1])),
    )
    assert decided.status_code == 200, decided.text

    flag = client.post(
        "/v1/flags",
        json=flag_body(viewer, analyst.user_id, target_type="user", note="Check this account"),
        headers=viewer_headers,
    ).json()
    answer = client.post(
        f"/v1/flags/{flag['flag_id']}/responses",
        json=response_body(flag, analyst),
        headers=analyst_headers,
    ).json()
    admission = admit_fidbf(database, tmp_path)

    genuine = [
        analyst_request, moderator_request, revocation["revocation_id"], flag["flag_id"],
        answer["flag_response_id"], admission.ids["fidbf"], admission.ids["source"],
    ]
    code, report = verify_json(database)
    for row_id in genuine:
        assert failures_for(report, row_id) == [], row_id
    for kind in (
        "registration proofs", "registration decisions", "first approvals",
        "revocation requests", "revocation decisions", "flags", "flag responses",
        "sources", "FIDBF admissions", "integrity entries",
    ):
        assert report["checked"].get(kind, 0) > 0, kind

    # --- Forgeries: user-signed rows as a compromised API (relic_app) could
    # write them, and an admission altered with a stolen worker login ------
    forged_flag, forged_revocation = uuid.uuid4(), uuid.uuid4()
    forged_registration = _register(client, "analyst")
    with psycopg.connect(database.app_url, autocommit=True) as conn:
        conn.execute(
            "INSERT INTO catalogue.flag (flag_id, viewer_request_id, note, signature,"
            " target_type, target_id) VALUES (%s, %s, 'forged', %s, 'user', %s)",
            (forged_flag, viewer.user_id, b"\x07" * 64, moderators[0].user_id),
        )
        conn.execute(
            "INSERT INTO catalogue.revocation (revocation_id, requester_id, target_type,"
            " target_id, reason, request_signature) VALUES (%s, %s, 'user', %s, 'forged', %s)",
            (forged_revocation, moderators[1].user_id, analyst.user_id, b"\x08" * 64),
        )
        conn.execute(
            "SELECT catalogue.decide_registration(%s, %s, 'approved', %s)",
            (forged_registration, moderators[0].user_id, b"\x09" * 64),
        )
    with psycopg.connect(database.worker_url, autocommit=True) as conn:
        # An extra function slipped into an admitted binary.
        conn.execute(
            "INSERT INTO catalogue.function_record (function_id, binary_id, fidbf_id,"
            " full_hash, specific_hash) VALUES (%s, %s, %s, %s, %s)",
            (uuid.uuid4(), admission.ids["binary"], admission.ids["fidbf"],
             "00" * 8, "11" * 8),
        )

    code, report = verify_json(database)
    assert code == 1
    expected = {
        forged_flag: "does not verify",
        forged_revocation: "does not verify",
        forged_registration: "does not verify",
        admission.ids["fidbf"]: "batch",  # its batch signature no longer covers the functions
    }
    for row_id, problem in expected.items():
        problems = failures_for(report, row_id)
        assert any(problem in text for text in problems), (row_id, problems)
    for row_id in genuine:
        if row_id != admission.ids["fidbf"]:
            assert failures_for(report, row_id) == [], row_id

    # Text output names each forgery on a FAIL line.
    code, text = run_verify(database.auditor_url, "--quiet")
    assert code == 1 and f"FAIL flag {forged_flag}" in text and "VERIFIED" not in text


def test_forged_second_approval_is_reported_by_relic_verify(client, database):
    """The database accepts two approvals by different active Moderators without
    checking their signatures, so a compromised API can add a Moderator with
    forged ones. relic-verify must report every forged signature."""
    first, second = (database.create_user("moderator") for _ in range(2))
    request_id = _register(client, "moderator")
    with psycopg.connect(database.app_url, autocommit=True) as conn:
        conn.execute(
            "INSERT INTO catalogue.registration_approval"
            " (registration_request_id, moderator_id, approval_signature) VALUES (%s, %s, %s)",
            (request_id, first.user_id, b"\x0a" * 64),
        )
        created = conn.execute(
            "SELECT catalogue.decide_registration(%s, %s, 'approved', %s)",
            (request_id, second.user_id, b"\x0b" * 64),
        ).fetchone()[0]
    assert created is not None  # the database alone cannot tell

    code, report = verify_json(database)
    assert code == 1
    problems = [
        f"{f['kind']}: {f['problem']}" for f in report["failures"] if f["id"] == request_id
    ]
    assert any(p.startswith("registration approval:") for p in problems), problems
    assert any("without a second Moderator" in p for p in problems), problems
    assert any(str(second.user_id) in p for p in problems), problems


def test_owner_fixture_chain_entries_are_reported(database, client, tmp_path: Path):
    """Chain entries with placeholder system signatures (written as the owner)."""
    entries = database.execute(
        "SELECT integrity_id FROM catalogue.integrity WHERE system_signature = %s",
        (b"\x11" * 64,),
    )
    if not entries:
        pytest.skip("no placeholder chain entries in this session")
    _, report = verify_json(database)
    for (integrity_id,) in entries:
        assert any("does not verify" in p for p in failures_for(report, integrity_id))


def test_unreachable_database_exits_2():
    code, output = run_verify("postgresql://nobody:wrong@127.0.0.1:1/relic")
    assert code == 2 and "could not run" in output


def test_component_model_rows_verify_and_forgeries_are_reported(client, database):
    """Components, releases, component assertions and compositions written through
    the API verify; rows a compromised API writes with bad signatures do not."""
    from .test_components_api import (
        assertion_body, component_body, composition_body, default_members, release_body,
    )

    analyst = database.create_user("analyst")
    headers = bearer(login(client, analyst))
    owner = database.create_user("analyst")
    source, batch, binary, function = (uuid.uuid4() for _ in range(4))
    database.execute(
        "INSERT INTO catalogue.source (source_id, name, source_type, retrieved_at,"
        " submitted_by_analyst_id, signature) VALUES (%s, 'v', 'FIDBF', clock_timestamp(), %s, %s)",
        (source, owner.user_id, b"\x11" * 64),
    )
    database.execute(
        "INSERT INTO catalogue.batch (batch_id, md5, content_sha256, analyst_user_id, signature)"
        " VALUES (%s, %s, %s, %s, %s)",
        (batch, "a" * 32, "b" * 64, owner.user_id, b"\x11" * 64),
    )
    database.execute(
        "INSERT INTO catalogue.binary_record (binary_id, batch_id, source_id, content_sha256,"
        " content_md5, size_bytes, created_by) VALUES (%s, %s, %s, %s, %s, 1, %s)",
        (binary, batch, source, uuid.uuid4().hex * 2, uuid.uuid4().hex, owner.user_id),
    )
    database.execute(
        "INSERT INTO catalogue.function_record (function_id, binary_id, full_hash, specific_hash)"
        " VALUES (%s, %s, %s, %s)",
        (function, binary, "0" * 16, "1" * 16),
    )

    class Objects:
        binary_id, function_id = binary, function

    def created(path: str, body: dict, key: str) -> uuid.UUID:
        response = client.post(f"/v1/{path}", json=body, headers=headers)
        assert response.status_code == 201, response.text
        return uuid.UUID(response.json()[key])

    component = created("software-components", component_body(analyst), "component_id")
    release = created(
        "software-releases", release_body(analyst, component, source_id=source),
        "software_release_id",
    )
    assertion = created(
        "binary-component-assertions", assertion_body(analyst, binary, release),
        "binary_component_assertion_id",
    )
    composition = created(
        "behavioural-compositions", composition_body(analyst, default_members(Objects)),
        "behavioural_composition_id",
    )
    genuine = [component, release, assertion, composition]
    code, report = verify_json(database)
    for row_id in genuine:
        assert failures_for(report, row_id) == [], row_id
    for kind in ("software components", "software releases", "binary-component assertions",
                 "behavioural compositions"):
        assert report["checked"].get(kind, 0) > 0, kind
    assert not any("composition" in kind or "component" in kind for kind in report["unchecked"])

    # As a compromised API (relic_app) could write them: valid shape, bad signature.
    forged_component, forged_composition = uuid.uuid4(), uuid.uuid4()
    with psycopg.connect(database.app_url) as conn:
        conn.execute(
            "INSERT INTO catalogue.software_component (component_id, name, component_kind,"
            " created_by_analyst_id, signature) VALUES (%s, 'forged', 'library', %s, %s)",
            (forged_component, analyst.user_id, b"\x0c" * 64),
        )
        conn.execute(
            "INSERT INTO catalogue.behavioural_composition (behavioural_composition_id, name,"
            " member_count, submitted_by_analyst_id, signature) VALUES (%s, 'forged', 1, %s, %s)",
            (forged_composition, analyst.user_id, b"\x0d" * 64),
        )
        conn.execute(
            "INSERT INTO catalogue.composition_member (behavioural_composition_id, target_type,"
            " target_id, member_role) VALUES (%s, 'binary', %s, 'x')",
            (forged_composition, binary),
        )
    code, report = verify_json(database)
    assert code == 1
    for row_id in (forged_component, forged_composition):
        assert any("does not verify" in p for p in failures_for(report, row_id)), row_id
    for row_id in genuine:
        assert failures_for(report, row_id) == [], row_id
