"""Signed revocation requests (Analysts) and decisions (Moderators).

Covers the negative acceptance tests required for every signed route in
docs/api-handoff.md: wrong key, another User ID, altered content, another
domain, wrong or revoked identity, and no change to the table on failure.
"""

from __future__ import annotations

import json
import subprocess
import uuid
from pathlib import Path

import pytest
from nacl.signing import SigningKey

from api.crypto import (
    REGISTRATION_DECISION_SIGNATURE_DOMAIN,
    REVOCATION_DECISION_SIGNATURE_DOMAIN,
    REVOCATION_REQUEST_SIGNATURE_DOMAIN,
    RevocationRequest,
    revocation_decision_record,
    revocation_request_record,
    verify,
)

from .conftest import User, login, login_body, sign
from .test_auth_api import SIGNER, _login_with_cli, _openssh_public_key


def bearer(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def request_body(
    analyst: User,
    target_id: uuid.UUID,
    *,
    target_type: str = "user",
    reason: str = "Key reported lost",
    revocation_id: uuid.UUID | None = None,
    signer: SigningKey | None = None,
    domain: bytes = REVOCATION_REQUEST_SIGNATURE_DOMAIN,
    **signed_overrides,
) -> dict:
    """A request as ``analyst`` would send it; ``signed_overrides`` change only what is signed."""
    fields = {
        "revocation_id": revocation_id or uuid.uuid4(),
        "analyst_id": analyst.user_id,
        "target_type": target_type,
        "target_id": target_id,
        "reason": reason,
    }
    record = revocation_request_record(RevocationRequest(**{**fields, **signed_overrides}))
    body = {key: str(value) for key, value in fields.items()}
    body["signature"] = sign(signer or analyst.key, domain, record)
    return body


def decision_body(
    stored: dict,
    moderator: User,
    decision: str = "approved",
    *,
    signer: SigningKey | None = None,
    signed_decision: str | None = None,
    signed_moderator_id: uuid.UUID | None = None,
    domain: bytes = REVOCATION_DECISION_SIGNATURE_DOMAIN,
    **signed_overrides,
) -> dict:
    """Sign a decision over ``stored`` as returned by GET /v1/revocations/{id}."""
    details = {**stored, **signed_overrides}
    record = revocation_decision_record(
        RevocationRequest(
            revocation_id=uuid.UUID(details["revocation_id"]),
            analyst_id=uuid.UUID(details["analyst_id"]),
            target_type=details["target_type"],
            target_id=uuid.UUID(details["target_id"]),
            reason=details["reason"],
        ),
        moderator_id=signed_moderator_id or moderator.user_id,
        decision=signed_decision or decision,
    )
    return {
        "moderator_id": str(moderator.user_id),
        "decision": decision,
        "signature": sign(signer or moderator.key, domain, record),
    }


@pytest.fixture
def analyst(database) -> User:
    return database.create_user("analyst")


@pytest.fixture
def analyst_headers(client, analyst) -> dict:
    return bearer(login(client, analyst))


@pytest.fixture
def moderator(database) -> User:
    return database.create_user("moderator")


@pytest.fixture
def moderator_headers(client, moderator) -> dict:
    return bearer(login(client, moderator))


@pytest.fixture
def target(database) -> User:
    return database.create_user("viewer")


@pytest.fixture
def pending(client, analyst, analyst_headers, target) -> dict:
    """A stored, pending revocation of ``target``'s account."""
    response = client.post(
        "/v1/revocations", json=request_body(analyst, target.user_id), headers=analyst_headers
    )
    assert response.status_code == 201, response.text
    return response.json()


def _count(database, target_id) -> int:
    return database.execute(
        "SELECT count(*) FROM catalogue.revocation WHERE target_id = %s", (target_id,)
    )[0][0]


def _decide(client, headers, stored, body):
    return client.post(
        f"/v1/revocations/{stored['revocation_id']}/decision", json=body, headers=headers
    )


def _state(database, revocation_id) -> tuple:
    return database.execute(
        "SELECT decision::text, moderator_id FROM catalogue.revocation WHERE revocation_id = %s",
        (revocation_id,),
    )[0]


# ---------------------------------------------------------------------------
# Requests
# ---------------------------------------------------------------------------


def test_analyst_requests_and_any_account_can_read(client, database, pending, analyst, target):
    assert pending["status"] == "pending"
    assert (pending["analyst_id"], pending["target_id"]) == (
        str(analyst.user_id),
        str(target.user_id),
    )
    assert pending["moderator_id"] is None and pending["decision_signature"] is None

    viewer_headers = bearer(login(client, database.create_user("viewer")))
    one = client.get(f"/v1/revocations/{pending['revocation_id']}", headers=viewer_headers)
    assert one.status_code == 200 and one.json() == pending
    listed = client.get(
        "/v1/revocations",
        params={"status": "pending", "target_type": "user", "target_id": str(target.user_id)},
        headers=viewer_headers,
    ).json()
    assert [row["revocation_id"] for row in listed] == [pending["revocation_id"]]
    assert client.get("/v1/revocations").status_code == 401


def test_stored_request_signature_verifies_offline(pending, analyst):
    record = revocation_request_record(
        RevocationRequest(
            revocation_id=uuid.UUID(pending["revocation_id"]),
            analyst_id=uuid.UUID(pending["analyst_id"]),
            target_type=pending["target_type"],
            target_id=uuid.UUID(pending["target_id"]),
            reason=pending["reason"],
        )
    )
    assert verify(
        bytes(analyst.key.verify_key),
        REVOCATION_REQUEST_SIGNATURE_DOMAIN,
        record,
        bytes.fromhex(pending["request_signature"]),
    )


def test_identical_retry_returns_the_stored_request(client, database, analyst, analyst_headers, target):
    body = request_body(analyst, target.user_id)
    first = client.post("/v1/revocations", json=body, headers=analyst_headers)
    again = client.post("/v1/revocations", json=body, headers=analyst_headers)
    assert (first.status_code, again.status_code) == (201, 200)
    assert again.json() == first.json()
    assert _count(database, target.user_id) == 1


def test_reused_id_with_different_content_conflicts(client, analyst, analyst_headers, pending, database):
    other = database.create_user("viewer")
    body = request_body(analyst, other.user_id, revocation_id=uuid.UUID(pending["revocation_id"]))
    response = client.post("/v1/revocations", json=body, headers=analyst_headers)
    assert response.status_code == 409
    assert _count(database, other.user_id) == 0


@pytest.mark.parametrize(
    "case",
    [
        "another_key",
        "another_users_id",
        "another_users_signed_request",
        "altered_reason",
        "altered_target",
        "decision_domain",
        "registration_domain",
    ],
)
def test_forged_requests_are_rejected_without_change(client, database, analyst, analyst_headers, target, case):
    other = database.create_user("analyst")
    body = {
        "another_key": lambda: request_body(analyst, target.user_id, signer=SigningKey.generate()),
        # Claims another Analyst's User ID, signed by the caller.
        "another_users_id": lambda: {
            **request_body(analyst, target.user_id, analyst_id=other.user_id),
            "analyst_id": str(other.user_id),
        },
        # A request genuinely signed by another Analyst, replayed by the caller.
        "another_users_signed_request": lambda: request_body(other, target.user_id),
        "altered_reason": lambda: request_body(analyst, target.user_id, reason="Signed reason")
        | {"reason": "Sent reason"},
        # Signed for another target, sent for this one.
        "altered_target": lambda: request_body(analyst, database.create_user("viewer").user_id)
        | {"target_id": str(target.user_id)},
        "decision_domain": lambda: request_body(
            analyst, target.user_id, domain=REVOCATION_DECISION_SIGNATURE_DOMAIN
        ),
        "registration_domain": lambda: request_body(
            analyst, target.user_id, domain=REGISTRATION_DECISION_SIGNATURE_DOMAIN
        ),
    }[case]()
    response = client.post("/v1/revocations", json=body, headers=analyst_headers)
    assert response.status_code == 403, response.text
    assert _count(database, target.user_id) == 0


@pytest.mark.parametrize("role", ["viewer", "moderator"])
def test_only_analysts_can_request(client, database, target, role):
    user = database.create_user(role)
    response = client.post(
        "/v1/revocations",
        json=request_body(user, target.user_id),
        headers=bearer(login(client, user)),
    )
    assert response.status_code == 403
    assert _count(database, target.user_id) == 0


def test_revoked_analyst_cannot_request(client, database, analyst, analyst_headers, target):
    database.revoke(analyst.user_id)
    response = client.post(
        "/v1/revocations", json=request_body(analyst, target.user_id), headers=analyst_headers
    )
    assert response.status_code == 401
    assert _count(database, target.user_id) == 0


def test_unknown_target_is_rejected(client, analyst, analyst_headers):
    for target_type in ("user", "fidbf"):
        response = client.post(
            "/v1/revocations",
            json=request_body(analyst, uuid.uuid4(), target_type=target_type),
            headers=analyst_headers,
        )
        assert response.status_code == 422, response.text


def test_one_open_request_per_target(client, database, analyst_headers, pending, target):
    second_analyst = database.create_user("analyst")
    response = client.post(
        "/v1/revocations",
        json=request_body(second_analyst, target.user_id),
        headers=bearer(login(client, second_analyst)),
    )
    assert response.status_code == 409
    assert response.json()["detail"] == "This target already has an open revocation request"


@pytest.mark.parametrize(
    "field, value",
    [
        ("reason", ""),
        ("reason", " padded"),
        ("reason", "two\nlines"),
        ("reason", "x" * 2001),
        ("target_type", "integrity"),
        ("target_id", "not-a-uuid"),
        ("signature", "00" * 63),
        ("unexpected", "field"),
    ],
)
def test_malformed_requests_are_rejected(client, analyst, analyst_headers, target, field, value):
    body = request_body(analyst, target.user_id)
    body[field] = value
    assert client.post("/v1/revocations", json=body, headers=analyst_headers).status_code == 422


# ---------------------------------------------------------------------------
# Decisions
# ---------------------------------------------------------------------------


def test_approved_account_revocation_takes_effect_immediately(
    client, database, pending, moderator, moderator_headers, target
):
    target_headers = bearer(login(client, target))
    assert client.get("/v1/me", headers=target_headers).status_code == 200

    response = _decide(client, moderator_headers, pending, decision_body(pending, moderator))
    assert response.status_code == 200, response.text
    assert response.json()["decision"] == "approved"

    assert client.get("/v1/me", headers=target_headers).status_code == 401
    login_attempt = client.post("/v1/auth/login", json=login_body(client, target))
    assert login_attempt.status_code == 403
    user = client.get(f"/v1/users/{target.user_id}", headers=moderator_headers).json()
    assert user["revoked"] is True

    # The stored decision can be re-verified from the row alone.
    stored = client.get(f"/v1/revocations/{pending['revocation_id']}", headers=moderator_headers).json()
    assert (stored["status"], stored["moderator_id"]) == ("approved", str(moderator.user_id))
    record = revocation_decision_record(
        RevocationRequest(
            revocation_id=uuid.UUID(stored["revocation_id"]),
            analyst_id=uuid.UUID(stored["analyst_id"]),
            target_type=stored["target_type"],
            target_id=uuid.UUID(stored["target_id"]),
            reason=stored["reason"],
        ),
        moderator_id=moderator.user_id,
        decision="approved",
    )
    assert verify(
        bytes(moderator.key.verify_key),
        REVOCATION_DECISION_SIGNATURE_DOMAIN,
        record,
        bytes.fromhex(stored["decision_signature"]),
    )


def test_revoked_target_cannot_be_requested_again(client, database, analyst, analyst_headers, pending, moderator, moderator_headers, target):
    assert _decide(client, moderator_headers, pending, decision_body(pending, moderator)).status_code == 200
    response = client.post(
        "/v1/revocations", json=request_body(analyst, target.user_id), headers=analyst_headers
    )
    assert response.status_code == 409
    assert "already revoked" in response.json()["detail"]


def test_rejection_leaves_the_target_active_and_allows_a_new_request(
    client, analyst, analyst_headers, pending, moderator, moderator_headers, target
):
    response = _decide(client, moderator_headers, pending, decision_body(pending, moderator, "rejected"))
    assert response.status_code == 200, response.text
    assert client.get("/v1/me", headers=bearer(login(client, target))).status_code == 200
    again = client.post(
        "/v1/revocations", json=request_body(analyst, target.user_id), headers=analyst_headers
    )
    assert again.status_code == 201


@pytest.mark.parametrize(
    "case, status",
    [
        ("another_key", 403),
        ("another_moderator_id", 403),
        ("signed_other_verdict", 403),
        ("signed_for_other_moderator", 403),
        ("altered_reason", 403),
        ("registration_domain", 403),
        ("request_domain", 403),
    ],
)
def test_forged_decisions_are_rejected_without_change(
    client, database, pending, moderator, moderator_headers, case, status
):
    other = database.create_user("moderator")
    body = {
        "another_key": lambda: decision_body(pending, moderator, signer=SigningKey.generate()),
        "another_moderator_id": lambda: decision_body(pending, moderator)
        | {"moderator_id": str(other.user_id)},
        "signed_other_verdict": lambda: decision_body(
            pending, moderator, "rejected", signed_decision="approved"
        ),
        "signed_for_other_moderator": lambda: decision_body(
            pending, moderator, signed_moderator_id=other.user_id
        ),
        "altered_reason": lambda: decision_body(pending, moderator, reason="Something else"),
        "registration_domain": lambda: decision_body(
            pending, moderator, domain=REGISTRATION_DECISION_SIGNATURE_DOMAIN
        ),
        "request_domain": lambda: decision_body(
            pending, moderator, domain=REVOCATION_REQUEST_SIGNATURE_DOMAIN
        ),
    }[case]()
    response = _decide(client, moderator_headers, pending, body)
    assert response.status_code == status, response.text
    assert _state(database, pending["revocation_id"]) == (None, None)


@pytest.mark.parametrize("role", ["viewer", "analyst"])
def test_only_moderators_can_decide(client, database, pending, role):
    user = database.create_user(role)
    response = _decide(client, bearer(login(client, user)), pending, decision_body(pending, user))
    assert response.status_code == 403
    assert _state(database, pending["revocation_id"]) == (None, None)


def test_moderator_cannot_decide_own_revocation(client, database, analyst, analyst_headers, moderator, moderator_headers):
    stored = client.post(
        "/v1/revocations", json=request_body(analyst, moderator.user_id), headers=analyst_headers
    ).json()
    for decision in ("approved", "rejected"):
        response = _decide(client, moderator_headers, stored, decision_body(stored, moderator, decision))
        assert response.status_code == 403
    assert _state(database, stored["revocation_id"]) == (None, None)

    # Another Moderator can.
    other = database.create_user("moderator")
    response = _decide(client, bearer(login(client, other)), stored, decision_body(stored, other))
    assert response.status_code == 200


def test_decision_is_final(client, database, pending, moderator, moderator_headers):
    assert _decide(client, moderator_headers, pending, decision_body(pending, moderator, "rejected")).status_code == 200
    other = database.create_user("moderator")
    response = _decide(client, bearer(login(client, other)), pending, decision_body(pending, other))
    assert response.status_code == 409
    assert _state(database, pending["revocation_id"])[0] == "rejected"


def test_unknown_revocation_is_404(client, moderator, moderator_headers, pending):
    missing = {**pending, "revocation_id": str(uuid.uuid4())}
    response = _decide(client, moderator_headers, missing, decision_body(missing, moderator))
    assert response.status_code == 404


def test_request_by_since_revoked_analyst_cannot_be_decided(
    client, database, pending, analyst, moderator, moderator_headers
):
    database.revoke(analyst.user_id)
    response = _decide(client, moderator_headers, pending, decision_body(pending, moderator))
    assert response.status_code == 403
    assert _state(database, pending["revocation_id"]) == (None, None)


# ---------------------------------------------------------------------------
# Cross-implementation: the Rust client signs, the Python API verifies
# ---------------------------------------------------------------------------


def _ssh_user(database, tmp_path: Path, name: str, role: str) -> tuple[uuid.UUID, Path]:
    key_path = tmp_path / name
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key_path)], check=True)
    user_id = database.execute(
        "INSERT INTO catalogue.user_public (public_key, role) VALUES (%s, %s::catalogue.account_role)"
        " RETURNING user_id",
        (_openssh_public_key(key_path.with_suffix(".pub")), role),
    )[0][0]
    return user_id, key_path


def _cli(*args: str) -> dict:
    return json.loads(
        subprocess.run([str(SIGNER), *args], check=True, capture_output=True, text=True).stdout
    )


@pytest.mark.skipif(not SIGNER.exists(), reason="build with: cargo build -p relic-ingest")
def test_rust_client_revocation(client, database, target, tmp_path: Path):
    analyst_id, analyst_key = _ssh_user(database, tmp_path, "analyst_ed25519", "analyst")
    moderator_id, moderator_key = _ssh_user(database, tmp_path, "moderator_ed25519", "moderator")
    analyst_headers = bearer(_login_with_cli(client, analyst_id, analyst_key, tmp_path))
    moderator_headers = bearer(_login_with_cli(client, moderator_id, moderator_key, tmp_path))

    body = _cli(
        "request-revocation", "--analyst-id", str(analyst_id), "--target-type", "user",
        "--target-id", str(target.user_id), "--reason", "Schlüssel verloren — key lost",
        "--key", str(analyst_key),
    )
    created = client.post("/v1/revocations", json=body, headers=analyst_headers)
    assert created.status_code == 201, created.text
    revocation_id = created.json()["revocation_id"]

    request_path = tmp_path / "revocation.json"
    request_path.write_text(
        client.get(f"/v1/revocations/{revocation_id}", headers=moderator_headers).text
    )
    decision = _cli(
        "decide-revocation", "--request", str(request_path), "--moderator-id", str(moderator_id),
        "--decision", "approved", "--key", str(moderator_key),
    )
    decided = client.post(
        f"/v1/revocations/{revocation_id}/decision", json=decision, headers=moderator_headers
    )
    assert decided.status_code == 200, decided.text
    assert client.post("/v1/auth/login", json=login_body(client, target)).status_code == 403

    # The CLI refuses to sign a request that is no longer pending.
    request_path.write_text(
        client.get(f"/v1/revocations/{revocation_id}", headers=moderator_headers).text
    )
    refused = subprocess.run(
        [str(SIGNER), "decide-revocation", "--request", str(request_path),
         "--moderator-id", str(moderator_id), "--decision", "approved", "--key", str(moderator_key)],
        capture_output=True,
        text=True,
    )
    assert refused.returncode != 0 and "already approved" in refused.stderr
