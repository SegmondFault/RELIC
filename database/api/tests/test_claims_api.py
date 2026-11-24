"""Signed licence assertions and classifications (Analysts).

Covers the negative acceptance tests required for every signed route (wrong
key, another User ID, altered content, another domain, wrong or revoked
identity, no change on failure) plus each route's own rules.
"""

from __future__ import annotations

import json
import subprocess
import uuid
from dataclasses import dataclass
from pathlib import Path

import psycopg
import pytest
from nacl.signing import SigningKey

from api.crypto import (
    CLASSIFICATION_SIGNATURE_DOMAIN,
    FLAG_SIGNATURE_DOMAIN,
    LICENSE_ASSERTION_SIGNATURE_DOMAIN,
    Classification,
    LicenseAssertion,
    classification_record,
    license_assertion_record,
    verify,
)

from .conftest import REPO, User, login, sign
from .test_auth_api import SIGNER, _login_with_cli
from .test_revocations_api import _ssh_user
from .test_revocations_api import request_body as revocation_body

VERIFY = REPO / "target/debug/relic-verify"


def bearer(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


@dataclass
class Objects:
    source_id: uuid.UUID
    binary_id: uuid.UUID
    function_id: uuid.UUID


@pytest.fixture
def objects(database) -> Objects:
    """A fresh source, binary and function to make claims about."""
    owner = database.create_user("analyst")
    source, batch, binary, function = (uuid.uuid4() for _ in range(4))
    sig = b"\x11" * 64
    run = database.execute
    run(
        "INSERT INTO catalogue.source (source_id, name, source_type, retrieved_at,"
        " submitted_by_analyst_id, signature) VALUES (%s, 'claims', 'FIDBF', clock_timestamp(), %s, %s)",
        (source, owner.user_id, sig),
    )
    run(
        "INSERT INTO catalogue.batch (batch_id, md5, content_sha256, analyst_user_id, signature)"
        " VALUES (%s, %s, %s, %s, %s)",
        (batch, "a" * 32, "b" * 64, owner.user_id, sig),
    )
    run(
        "INSERT INTO catalogue.binary_record (binary_id, batch_id, source_id, content_sha256,"
        " content_md5, size_bytes, created_by) VALUES (%s, %s, %s, %s, %s, 1, %s)",
        (binary, batch, source, uuid.uuid4().hex * 2, uuid.uuid4().hex, owner.user_id),
    )
    run(
        "INSERT INTO catalogue.function_record (function_id, binary_id, full_hash, specific_hash)"
        " VALUES (%s, %s, %s, %s)",
        (function, binary, "0" * 16, "1" * 16),
    )
    return Objects(source, binary, function)


@pytest.fixture
def analyst(database) -> User:
    return database.create_user("analyst")


@pytest.fixture
def analyst_headers(client, analyst) -> dict:
    return bearer(login(client, analyst))


def license_body(
    analyst: User,
    target_id: uuid.UUID,
    *,
    target_type: str = "binary",
    spdx: str = "MIT OR Apache-2.0",
    basis: str = "detected",
    confidence: str | None = "0.9500",
    evidence_provenance_id: uuid.UUID | None = None,
    license_assertion_id: uuid.UUID | None = None,
    signer: SigningKey | None = None,
    domain: bytes = LICENSE_ASSERTION_SIGNATURE_DOMAIN,
    **signed_overrides,
) -> dict:
    """``signed_overrides`` change only what is signed, not what is sent."""
    fields = {
        "license_assertion_id": license_assertion_id or uuid.uuid4(),
        "analyst_id": analyst.user_id,
        "target_type": target_type,
        "target_id": target_id,
        "spdx_expression": spdx,
        "basis": basis,
        "confidence": confidence,
        "evidence_provenance_id": evidence_provenance_id,
    }
    record = license_assertion_record(LicenseAssertion(**{**fields, **signed_overrides}))
    body = {key: (str(value) if isinstance(value, uuid.UUID) else value) for key, value in fields.items()}
    body["signature"] = sign(signer or analyst.key, domain, record)
    return body


EVIDENCE = '{"tool": "capa",   "rules": ["aes"], "score": 0.93, "nested": {"b": 1, "a": 2}}'


def classification_body(
    analyst: User,
    target_id: uuid.UUID,
    *,
    target_type: str = "function",
    label: str = "crypto/aes",
    confidence: str | None = "0.8000",
    misp: tuple[str, uuid.UUID] | None = None,
    evidence_json: str | None = EVIDENCE,
    classification_id: uuid.UUID | None = None,
    signer: SigningKey | None = None,
    domain: bytes = CLASSIFICATION_SIGNATURE_DOMAIN,
    **signed_overrides,
) -> dict:
    fields = {
        "classification_id": classification_id or uuid.uuid4(),
        "analyst_id": analyst.user_id,
        "target_type": target_type,
        "target_id": target_id,
        "label": label,
        "confidence": confidence,
        "misp_universe": misp[0] if misp else None,
        "misp_uuid": misp[1] if misp else None,
        "evidence_json": evidence_json,
    }
    record = classification_record(Classification(**{**fields, **signed_overrides}))
    body = {key: (str(value) if isinstance(value, uuid.UUID) else value) for key, value in fields.items()}
    body["signature"] = sign(signer or analyst.key, domain, record)
    return body


def _count(database, table: str, key: str, value) -> int:
    return database.execute(f"SELECT count(*) FROM catalogue.{table} WHERE {key} = %s", (value,))[0][0]


# ---------------------------------------------------------------------------
# Licence assertions
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("target_type", ["source", "binary"])
def test_analyst_asserts_and_any_account_can_read(client, database, analyst, analyst_headers, objects, target_type):
    target = objects.source_id if target_type == "source" else objects.binary_id
    body = license_body(analyst, target, target_type=target_type)
    response = client.post("/v1/license-assertions", json=body, headers=analyst_headers)
    assert response.status_code == 201, response.text
    stored = response.json()
    assert (stored["target_type"], stored["target_id"], stored["confidence"]) == (
        target_type, str(target), "0.9500",
    )
    assert stored[f"{target_type}_id"] == str(target)

    viewer = bearer(login(client, database.create_user("viewer")))
    read = client.get(f"/v1/license-assertions/{body['license_assertion_id']}", headers=viewer).json()
    assert read == stored
    record = license_assertion_record(
        LicenseAssertion(
            license_assertion_id=uuid.UUID(read["license_assertion_id"]),
            analyst_id=uuid.UUID(read["submitted_by_analyst_id"]),
            target_type=read["target_type"],
            target_id=uuid.UUID(read["target_id"]),
            spdx_expression=read["spdx_expression"],
            basis=read["basis"],
            confidence=read["confidence"],
            evidence_provenance_id=None,
        )
    )
    assert verify(bytes(analyst.key.verify_key), LICENSE_ASSERTION_SIGNATURE_DOMAIN, record,
                  bytes.fromhex(read["signature"]))


def test_license_retry_and_conflict(client, database, analyst, analyst_headers, objects):
    body = license_body(analyst, objects.binary_id, confidence=None)
    first = client.post("/v1/license-assertions", json=body, headers=analyst_headers)
    again = client.post("/v1/license-assertions", json=body, headers=analyst_headers)
    assert (first.status_code, again.status_code) == (201, 200)
    assert again.json() == first.json()
    other = license_body(analyst, objects.binary_id, spdx="GPL-3.0-only",
                         license_assertion_id=uuid.UUID(body["license_assertion_id"]))
    assert client.post("/v1/license-assertions", json=other, headers=analyst_headers).status_code == 409
    assert _count(database, "license_assertion", "binary_id", objects.binary_id) == 1


@pytest.mark.parametrize(
    "case",
    ["another_key", "another_users_id", "another_users_signed", "altered_spdx",
     "altered_target", "altered_confidence", "flag_domain"],
)
def test_forged_license_assertions_are_rejected(client, database, analyst, analyst_headers, objects, case):
    other = database.create_user("analyst")
    target = objects.binary_id
    body = {
        "another_key": lambda: license_body(analyst, target, signer=SigningKey.generate()),
        "another_users_id": lambda: license_body(analyst, target, analyst_id=other.user_id)
        | {"analyst_id": str(other.user_id)},
        "another_users_signed": lambda: license_body(other, target),
        "altered_spdx": lambda: license_body(analyst, target, spdx_expression="MIT"),
        # Signed for another binary, sent for this one.
        "altered_target": lambda: license_body(analyst, uuid.uuid4()) | {"target_id": str(target)},
        "altered_confidence": lambda: license_body(analyst, target, confidence="0.1000")
        | {"confidence": "0.9500"},
        "flag_domain": lambda: license_body(analyst, target, domain=FLAG_SIGNATURE_DOMAIN),
    }[case]()
    response = client.post("/v1/license-assertions", json=body, headers=analyst_headers)
    assert response.status_code == 403, response.text
    assert _count(database, "license_assertion", "binary_id", target) == 0


@pytest.mark.parametrize("role", ["viewer", "moderator"])
def test_only_analysts_assert(client, database, objects, role):
    user = database.create_user(role)
    response = client.post(
        "/v1/license-assertions", json=license_body(user, objects.binary_id),
        headers=bearer(login(client, user)),
    )
    assert response.status_code == 403


@pytest.mark.parametrize(
    "overrides, status",
    [
        ({"spdx": "MIT and Apache-2.0"}, 422),
        ({"spdx": "LicenseRef-"}, 422),
        ({"confidence": "0.5"}, 422),        # must be written with four decimals
        ({"confidence": "1.5000"}, 422),
        ({"basis": "guessed"}, 422),
        ({"target_type": "function"}, 422),
        ({"evidence_provenance_id": uuid.uuid4()}, 422),
    ],
)
def test_invalid_license_assertions(client, analyst, analyst_headers, objects, overrides, status):
    body = license_body(analyst, objects.binary_id, **overrides)
    assert client.post("/v1/license-assertions", json=body, headers=analyst_headers).status_code == status


def test_unknown_or_revoked_license_target(client, database, analyst, analyst_headers, objects):
    unknown = license_body(analyst, uuid.uuid4())
    assert client.post("/v1/license-assertions", json=unknown, headers=analyst_headers).status_code == 422
    database.revoke(objects.binary_id, "binary")
    response = client.post(
        "/v1/license-assertions", json=license_body(analyst, objects.binary_id), headers=analyst_headers
    )
    assert response.status_code == 409 and "is revoked" in response.json()["detail"]


def test_correction_is_a_new_assertion_and_a_revocation(client, database, analyst, analyst_headers, objects):
    wrong = client.post(
        "/v1/license-assertions", json=license_body(analyst, objects.binary_id, spdx="MIT"),
        headers=analyst_headers,
    ).json()
    right = client.post(
        "/v1/license-assertions", json=license_body(analyst, objects.binary_id, spdx="BSD-3-Clause"),
        headers=analyst_headers,
    )
    assert right.status_code == 201
    other = database.create_user("analyst")
    requested = client.post(
        "/v1/revocations",
        json=revocation_body(other, uuid.UUID(wrong["license_assertion_id"]),
                             target_type="license_assertion", reason="Superseded"),
        headers=bearer(login(client, other)),
    )
    assert requested.status_code == 201, requested.text
    with pytest.raises(psycopg.Error, match="immutable"):
        database.execute(
            "UPDATE catalogue.license_assertion SET spdx_expression = 'MIT' WHERE license_assertion_id = %s",
            (right.json()["license_assertion_id"],),
        )


# ---------------------------------------------------------------------------
# Classifications
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("target_type", ["binary", "function"])
def test_analyst_classifies_with_verbatim_evidence(client, database, analyst, analyst_headers, objects, target_type):
    target = objects.binary_id if target_type == "binary" else objects.function_id
    misp = ("mitre-attack-pattern", uuid.uuid4())
    body = classification_body(analyst, target, target_type=target_type, misp=misp)
    response = client.post("/v1/classifications", json=body, headers=analyst_headers)
    assert response.status_code == 201, response.text
    stored = response.json()
    # The exact text is kept (spacing, key order); evidence is the same value parsed.
    assert stored["evidence_json"] == EVIDENCE
    assert stored["evidence"] == json.loads(EVIDENCE)

    viewer = bearer(login(client, database.create_user("viewer")))
    read = client.get(f"/v1/classifications/{body['classification_id']}", headers=viewer).json()
    assert read == stored
    record = classification_record(
        Classification(
            classification_id=uuid.UUID(read["classification_id"]),
            analyst_id=uuid.UUID(read["analyst_id"]),
            target_type=read["target_type"],
            target_id=uuid.UUID(read["target_id"]),
            label=read["label"],
            confidence=read["confidence"],
            misp_universe=read["misp_universe"],
            misp_uuid=uuid.UUID(read["misp_uuid"]),
            evidence_json=read["evidence_json"],
        )
    )
    assert verify(bytes(analyst.key.verify_key), CLASSIFICATION_SIGNATURE_DOMAIN, record,
                  bytes.fromhex(read["signature"]))


def test_classification_retry_and_conflict(client, database, analyst, analyst_headers, objects):
    body = classification_body(analyst, objects.function_id, evidence_json=None, confidence=None)
    first = client.post("/v1/classifications", json=body, headers=analyst_headers)
    again = client.post("/v1/classifications", json=body, headers=analyst_headers)
    assert (first.status_code, again.status_code) == (201, 200)
    other = classification_body(analyst, objects.function_id, label="other",
                                classification_id=uuid.UUID(body["classification_id"]))
    assert client.post("/v1/classifications", json=other, headers=analyst_headers).status_code == 409


@pytest.mark.parametrize(
    "case", ["another_key", "another_users_id", "altered_label", "altered_evidence", "license_domain"]
)
def test_forged_classifications_are_rejected(client, database, analyst, analyst_headers, objects, case):
    other = database.create_user("analyst")
    target = objects.function_id
    body = {
        "another_key": lambda: classification_body(analyst, target, signer=SigningKey.generate()),
        "another_users_id": lambda: classification_body(analyst, target, analyst_id=other.user_id)
        | {"analyst_id": str(other.user_id)},
        "altered_label": lambda: classification_body(analyst, target, label="benign")
        | {"label": "malicious"},
        # Same JSON value, different text: the signature covers the exact text.
        "altered_evidence": lambda: classification_body(analyst, target)
        | {"evidence_json": json.dumps(json.loads(EVIDENCE))},
        "license_domain": lambda: classification_body(
            analyst, target, domain=LICENSE_ASSERTION_SIGNATURE_DOMAIN
        ),
    }[case]()
    response = client.post("/v1/classifications", json=body, headers=analyst_headers)
    assert response.status_code == 403, response.text
    assert _count(database, "classification", "target_id", target) == 0


@pytest.mark.parametrize(
    "overrides",
    [
        {"target_type": "source"},
        {"evidence_json": "[1, 2]"},
        {"evidence_json": '{"a": 1, "a": 2}'},
        {"evidence_json": '{"a": NaN}'},
        {"evidence_json": "{" * 40 + "}" * 40},
        {"label": " padded"},
        {"confidence": "0.80"},
    ],
)
def test_invalid_classifications(client, analyst, analyst_headers, objects, overrides):
    body = classification_body(analyst, objects.function_id, **overrides)
    assert client.post("/v1/classifications", json=body, headers=analyst_headers).status_code == 422


def test_misp_fields_come_together(client, analyst, analyst_headers, objects):
    body = classification_body(analyst, objects.function_id)
    body["misp_universe"] = "mitre-attack-pattern"
    assert client.post("/v1/classifications", json=body, headers=analyst_headers).status_code == 422


def test_unknown_or_revoked_classification_target(client, database, analyst, analyst_headers, objects):
    unknown = classification_body(analyst, uuid.uuid4())
    assert client.post("/v1/classifications", json=unknown, headers=analyst_headers).status_code == 422
    database.revoke(objects.function_id, "function")
    response = client.post(
        "/v1/classifications", json=classification_body(analyst, objects.function_id),
        headers=analyst_headers,
    )
    assert response.status_code == 409 and "is revoked" in response.json()["detail"]


def test_classifications_are_immutable_and_evidence_verbatim(database, client, analyst, analyst_headers, objects):
    stored = client.post(
        "/v1/classifications", json=classification_body(analyst, objects.function_id),
        headers=analyst_headers,
    ).json()
    for statement in (
        "UPDATE catalogue.classification SET label = 'x' WHERE classification_id = %s",
        "DELETE FROM catalogue.classification WHERE classification_id = %s",
    ):
        with pytest.raises(psycopg.Error, match="immutable"):
            database.execute(statement, (stored["classification_id"],))
    with pytest.raises(psycopg.Error, match="classification_evidence_verbatim"):
        database.execute(
            "INSERT INTO catalogue.classification (target_type, target_id, label, analyst_id,"
            " evidence, evidence_json, signature) VALUES ('function', %s, 'x', %s, %s::jsonb, %s, %s)",
            (objects.function_id, analyst.user_id, '{"a": 1}', '{"a": 2}', b"\x01" * 64),
        )


# ---------------------------------------------------------------------------
# Rust client and relic-verify
# ---------------------------------------------------------------------------


def _signer(*args: str) -> dict:
    result = subprocess.run([str(SIGNER), *args], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


@pytest.mark.skipif(not (SIGNER.exists() and VERIFY.exists()),
                    reason="build with: cargo build -p relic-ingest -p relic-verify")
def test_rust_client_claims_verify_and_forgeries_are_reported(client, database, objects, tmp_path: Path):
    analyst_id, key = _ssh_user(database, tmp_path, "analyst_ed25519", "analyst")
    headers = bearer(_login_with_cli(client, analyst_id, key, tmp_path))
    license_ = _signer(
        "assert-license", "--analyst-id", str(analyst_id), "--target-type", "source",
        "--target-id", str(objects.source_id), "--spdx", "GPL-2.0-only WITH Classpath-exception-2.0",
        "--basis", "declared", "--confidence", "1.0000", "--key", str(key),
    )
    assert client.post("/v1/license-assertions", json=license_, headers=headers).status_code == 201
    evidence = tmp_path / "evidence.json"
    evidence.write_text('{ "rule":"aes",\n  "hits": [1,2] }\n')
    label = _signer(
        "classify", "--analyst-id", str(analyst_id), "--target-type", "binary",
        "--target-id", str(objects.binary_id), "--label", "crypto", "--evidence", str(evidence),
        "--misp-universe", "mitre-attack-pattern", "--misp-uuid", str(uuid.uuid4()), "--key", str(key),
    )
    created = client.post("/v1/classifications", json=label, headers=headers)
    assert created.status_code == 201, created.text
    assert created.json()["evidence_json"] == evidence.read_text()

    refused = subprocess.run(
        [str(SIGNER), "assert-license", "--analyst-id", str(analyst_id), "--target-type", "source",
         "--target-id", str(objects.source_id), "--spdx", "MIT", "--basis", "declared",
         "--confidence", "0.5", "--key", str(key)],
        capture_output=True, text=True,
    )
    assert refused.returncode != 0 and "four decimals" in refused.stderr

    forged = uuid.uuid4()
    with psycopg.connect(database.app_url, autocommit=True) as conn:  # a compromised API
        conn.execute(
            "INSERT INTO catalogue.license_assertion (license_assertion_id, binary_id,"
            " spdx_expression, basis, submitted_by_analyst_id, signature)"
            " VALUES (%s, %s, 'MIT', 'declared', %s, %s)",
            (forged, objects.binary_id, analyst_id, b"\x05" * 64),
        )
    report = json.loads(subprocess.run(
        [str(VERIFY), "--database-url", database.auditor_url, "--json"],
        capture_output=True, text=True,
    ).stdout)
    failing = {f["id"] for f in report["failures"]}
    assert license_["license_assertion_id"] not in failing
    assert label["classification_id"] not in failing
    assert str(forged) in failing
    assert report["checked"]["licence assertions"] >= 1 and report["checked"]["classifications"] >= 1
