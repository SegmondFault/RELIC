"""Two-Moderator approval for Moderator powers.

Approving a Moderator registration, and approving the revocation of a
Moderator account, need two different active Moderators. The first approval
is stored (202); the second decides. One rejection is final. The database
enforces the rule even if the API is bypassed.
"""

from __future__ import annotations

import uuid

import psycopg
import pytest
from nacl.signing import SigningKey
from psycopg import errors

from api.crypto import (
    REGISTRATION_DECISION_SIGNATURE_DOMAIN,
    REVOCATION_DECISION_SIGNATURE_DOMAIN,
    RevocationRequest,
    registration_decision_record,
    revocation_decision_record,
    verify,
)

from .conftest import User, decision_body, login, login_body, registration_body
from .test_revocations_api import decision_body as revocation_decision_body
from .test_revocations_api import request_body as revocation_request_body


def bearer(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


class Moderator:
    def __init__(self, client, database):
        self.user = database.create_user("moderator")
        self.headers = bearer(login(client, self.user))


@pytest.fixture
def moderators(client, database) -> list[Moderator]:
    return [Moderator(client, database) for _ in range(3)]


def _register(client, role: str) -> tuple[SigningKey, str]:
    key = SigningKey.generate()
    response = client.post("/v1/accounts", json=registration_body(client, key, role=role))
    assert response.status_code == 202, response.text
    return key, response.json()["registration_request_id"]


def _decide_registration(client, moderator: Moderator, request_id: str, decision: str = "approved"):
    request = client.get(f"/v1/registrations/{request_id}", headers=moderator.headers).json()
    return client.post(
        f"/v1/registrations/{request_id}/decision",
        json=decision_body(request, moderator.user, decision),
        headers=moderator.headers,
    )


def _login_status(client, key: SigningKey) -> int:
    applicant = User(uuid.uuid4(), key, None)
    return client.post("/v1/auth/login", json=login_body(client, applicant)).status_code


# ---------------------------------------------------------------------------
# Moderator registrations
# ---------------------------------------------------------------------------


def test_moderator_registration_needs_two_moderators(client, moderators):
    first, second, _ = moderators
    key, request_id = _register(client, "moderator")

    response = _decide_registration(client, first, request_id)
    assert response.status_code == 202, response.text
    body = response.json()
    assert body["status"] == "awaiting_second_approval"
    assert [a["moderator_id"] for a in body["approvals"]] == [str(first.user.user_id)]

    stored = client.get(f"/v1/registrations/{request_id}", headers=second.headers).json()
    assert (stored["status"], stored["approvals_required"]) == ("pending", 2)
    assert _login_status(client, key) == 403  # still pending: no account yet

    response = _decide_registration(client, second, request_id)
    assert response.status_code == 200, response.text
    assert response.json()["user_id"]
    assert _login_status(client, key) == 200

    # Both signatures are stored and re-verifiable over the ordinary decision message.
    stored = client.get(f"/v1/registrations/{request_id}", headers=second.headers).json()
    assert stored["moderator_id"] == str(second.user.user_id)
    for moderator_id, signature in [
        (first.user.user_id, stored["approvals"][0]["signature"]),
        (second.user.user_id, stored["decision_signature"]),
    ]:
        key_of = {first.user.user_id: first.user, second.user.user_id: second.user}[moderator_id].key
        record = registration_decision_record(
            uuid.UUID(request_id),
            public_key=bytes.fromhex(stored["public_key"]),
            requested_role="moderator",
            name=stored["name"],
            organisation=stored["organisation"],
            email=stored["email"],
            moderator_id=moderator_id,
            decision="approved",
        )
        assert verify(
            bytes(key_of.verify_key), REGISTRATION_DECISION_SIGNATURE_DOMAIN, record,
            bytes.fromhex(signature),
        )


def test_same_moderator_cannot_approve_twice(client, moderators):
    first = moderators[0]
    _, request_id = _register(client, "moderator")
    assert _decide_registration(client, first, request_id).status_code == 202
    response = _decide_registration(client, first, request_id)
    assert response.status_code == 409
    assert "another Moderator" in response.json()["detail"]
    stored = client.get(f"/v1/registrations/{request_id}", headers=first.headers).json()
    assert stored["status"] == "pending"


def test_one_rejection_is_final(client, moderators):
    first, second, third = moderators
    key, request_id = _register(client, "moderator")
    assert _decide_registration(client, first, request_id).status_code == 202
    assert _decide_registration(client, second, request_id, "rejected").status_code == 200
    assert _decide_registration(client, third, request_id).status_code == 409
    assert _login_status(client, key) == 403


def test_revoked_first_approver_does_not_count(client, database, moderators):
    first, second, third = moderators
    _, request_id = _register(client, "moderator")
    assert _decide_registration(client, first, request_id).status_code == 202
    database.revoke(first.user.user_id)
    # second becomes the first effective approval; third completes it.
    assert _decide_registration(client, second, request_id).status_code == 202
    assert _decide_registration(client, third, request_id).status_code == 200


def test_other_roles_need_one_moderator(client, moderators):
    for role in ("viewer", "analyst"):
        _, request_id = _register(client, role)
        stored = client.get(f"/v1/registrations/{request_id}", headers=moderators[0].headers).json()
        assert stored["approvals_required"] == 1
        assert _decide_registration(client, moderators[0], request_id).status_code == 200


def test_forged_first_approval_is_rejected_without_change(client, database, moderators):
    first = moderators[0]
    _, request_id = _register(client, "moderator")
    request = client.get(f"/v1/registrations/{request_id}", headers=first.headers).json()
    body = decision_body(request, first.user, signer=SigningKey.generate())
    response = client.post(
        f"/v1/registrations/{request_id}/decision", json=body, headers=first.headers
    )
    assert response.status_code == 403
    count = database.execute(
        "SELECT count(*) FROM catalogue.registration_approval WHERE registration_request_id = %s",
        (request_id,),
    )[0][0]
    assert count == 0


def test_database_refuses_single_moderator_approval(client, database, moderators):
    """Without a stored first approval, even calling decide_registration() as relic_app.

    This stops a buggy API or one dishonest Moderator. It cannot stop a
    compromised API, which could also store a forged first approval; the
    database does not verify signatures. relic-verify reports that
    (see test_forged_second_approval_is_reported_by_relic_verify).
    """
    first = moderators[0]
    _, request_id = _register(client, "moderator")
    with psycopg.connect(database.app_url) as conn, pytest.raises(
        errors.InsufficientPrivilege, match="another active Moderator"
    ):
        conn.execute(
            "SELECT catalogue.decide_registration(%s, %s, 'approved', %s)",
            (request_id, first.user.user_id, b"\x01" * 64),
        )


# ---------------------------------------------------------------------------
# Revoking a Moderator
# ---------------------------------------------------------------------------


@pytest.fixture
def moderator_revocation(client, database) -> tuple[dict, User]:
    analyst = database.create_user("analyst")
    target = database.create_user("moderator")
    response = client.post(
        "/v1/revocations",
        json=revocation_request_body(analyst, target.user_id, reason="Key compromised"),
        headers=bearer(login(client, analyst)),
    )
    assert response.status_code == 201, response.text
    return response.json(), target


def _decide_revocation(client, moderator: Moderator, stored: dict, decision: str = "approved"):
    return client.post(
        f"/v1/revocations/{stored['revocation_id']}/decision",
        json=revocation_decision_body(stored, moderator.user, decision),
        headers=moderator.headers,
    )


def test_revoking_a_moderator_needs_two_moderators(client, moderators, moderator_revocation):
    stored, target = moderator_revocation
    first, second, _ = moderators
    assert stored["approvals_required"] == 2

    response = _decide_revocation(client, first, stored)
    assert response.status_code == 202, response.text
    assert client.get("/v1/me", headers=bearer(login(client, target))).status_code == 200

    response = _decide_revocation(client, second, stored)
    assert response.status_code == 200, response.text
    assert client.post("/v1/auth/login", json=login_body(client, target)).status_code == 403

    stored = client.get(f"/v1/revocations/{stored['revocation_id']}", headers=second.headers).json()
    approval = stored["approvals"][0]
    record = revocation_decision_record(
        RevocationRequest(
            revocation_id=uuid.UUID(stored["revocation_id"]),
            analyst_id=uuid.UUID(stored["analyst_id"]),
            target_type="user",
            target_id=target.user_id,
            reason=stored["reason"],
        ),
        moderator_id=first.user.user_id,
        decision="approved",
    )
    assert approval["moderator_id"] == str(first.user.user_id)
    assert verify(
        bytes(first.user.key.verify_key),
        REVOCATION_DECISION_SIGNATURE_DOMAIN,
        record,
        bytes.fromhex(approval["signature"]),
    )


def test_one_moderator_can_reject_a_moderator_revocation(client, moderators, moderator_revocation):
    stored, target = moderator_revocation
    response = _decide_revocation(client, moderators[0], stored, "rejected")
    assert response.status_code == 200
    assert client.get("/v1/me", headers=bearer(login(client, target))).status_code == 200


def test_revoking_other_accounts_needs_one_moderator(client, database, moderators):
    analyst = database.create_user("analyst")
    target = database.create_user("analyst")
    stored = client.post(
        "/v1/revocations",
        json=revocation_request_body(analyst, target.user_id),
        headers=bearer(login(client, analyst)),
    ).json()
    assert stored["approvals_required"] == 1
    assert _decide_revocation(client, moderators[0], stored).status_code == 200


def test_database_refuses_single_moderator_revocation(database, moderators, moderator_revocation):
    """Without a stored first approval the API's login cannot revoke a Moderator; the operator can."""
    stored, _ = moderator_revocation
    update = (
        "UPDATE catalogue.revocation SET moderator_id = %s, decision = 'approved',"
        " decision_signature = %s WHERE revocation_id = %s"
    )
    params = (moderators[0].user.user_id, b"\x01" * 64, stored["revocation_id"])
    with psycopg.connect(database.app_url) as conn, pytest.raises(
        errors.InsufficientPrivilege, match="another active Moderator"
    ):
        conn.execute(update, params)
    database.execute(update, params)  # as relic_owner
    assert database.execute(
        "SELECT decision::text FROM catalogue.revocation WHERE revocation_id = %s",
        (stored["revocation_id"],),
    )[0][0] == "approved"


def test_approval_tables_are_append_only(database, client, moderators):
    _, request_id = _register(client, "moderator")
    assert _decide_registration(client, moderators[0], request_id).status_code == 202
    for statement in (
        "UPDATE catalogue.registration_approval SET approved_at = now()",
        "DELETE FROM catalogue.registration_approval",
    ):
        with pytest.raises(psycopg.Error, match="permanent records"):
            database.execute(statement)  # even the owner
