"""Moderator review and signed decisions on registration requests."""

from __future__ import annotations

import uuid

import pytest
from nacl.signing import SigningKey

from api.crypto import REGISTRATION_DECISION_SIGNATURE_DOMAIN, registration_decision_record, verify

from .conftest import User, decision_body, login, registration_body


def bearer(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def moderator(database) -> User:
    return database.create_user("moderator")


@pytest.fixture
def moderator_headers(client, moderator) -> dict:
    return bearer(login(client, moderator))


@pytest.fixture
def pending(client, moderator_headers):
    """A fresh pending request, as the Moderator sees it, plus the applicant's key."""
    key = SigningKey.generate()
    response = client.post("/v1/accounts", json=registration_body(client, key))
    assert response.status_code == 202, response.text
    request_id = response.json()["registration_request_id"]
    request = client.get(f"/v1/registrations/{request_id}", headers=moderator_headers)
    assert request.status_code == 200, request.text
    return request.json(), key


def _decide(client, headers, request, body):
    return client.post(
        f"/v1/registrations/{request['registration_request_id']}/decision",
        json=body,
        headers=headers,
    )


def _status(database, request_id) -> tuple:
    return database.execute(
        "SELECT decision::text, moderator_id, user_id FROM catalogue.registration_request"
        " WHERE registration_request_id = %s",
        (request_id,),
    )[0]


# ---------------------------------------------------------------------------
# Review
# ---------------------------------------------------------------------------


def test_moderator_sees_pending_request_with_contact_details(client, moderator_headers, pending):
    request, key = pending
    assert request["status"] == "pending"
    assert request["public_key"] == bytes(key.verify_key).hex()
    assert (request["name"], request["email"]) == ("Ada Lovelace", "ada@example.org")
    assert request["user_id"] is None and request["decision_signature"] is None

    listed = client.get("/v1/registrations", headers=moderator_headers).json()
    assert request["registration_request_id"] in {row["registration_request_id"] for row in listed}


@pytest.mark.parametrize("role", ["viewer", "analyst"])
def test_only_moderators_can_review_or_decide(client, database, pending, moderator, role):
    request, _ = pending
    headers = bearer(login(client, database.create_user(role)))
    assert client.get("/v1/registrations", headers=headers).status_code == 403
    assert client.get(
        f"/v1/registrations/{request['registration_request_id']}", headers=headers
    ).status_code == 403
    response = _decide(client, headers, request, decision_body(request, moderator))
    assert response.status_code == 403


def test_registration_routes_require_login(client, pending):
    request, _ = pending
    assert client.get("/v1/registrations").status_code == 401
    assert client.post(
        f"/v1/registrations/{request['registration_request_id']}/decision", json={}
    ).status_code == 401


def test_unknown_request_is_404(client, moderator, moderator_headers, pending):
    request, _ = pending
    unknown = {**request, "registration_request_id": str(uuid.uuid4())}
    assert client.get(
        f"/v1/registrations/{unknown['registration_request_id']}", headers=moderator_headers
    ).status_code == 404
    response = _decide(client, moderator_headers, unknown, decision_body(unknown, moderator))
    assert response.status_code == 404


# ---------------------------------------------------------------------------
# Decisions
# ---------------------------------------------------------------------------


def test_approval_creates_the_account_and_stores_a_verifiable_signature(
    client, database, moderator, moderator_headers, pending
):
    request, key = pending
    response = _decide(client, moderator_headers, request, decision_body(request, moderator))
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["decision"] == "approved"
    user_id = uuid.UUID(body["user_id"])

    token = login(client, User(user_id, key, "analyst"))
    assert client.get("/v1/me", headers=bearer(token)).json()["role"] == "analyst"

    # The stored row alone is enough to re-verify the decision later.
    stored = client.get(
        f"/v1/registrations/{request['registration_request_id']}", headers=moderator_headers
    ).json()
    assert stored["status"] == "approved"
    assert stored["moderator_id"] == str(moderator.user_id)
    assert stored["user_id"] == str(user_id)
    record = registration_decision_record(
        uuid.UUID(stored["registration_request_id"]),
        public_key=bytes.fromhex(stored["public_key"]),
        requested_role=stored["requested_role"],
        name=stored["name"],
        organisation=stored["organisation"],
        email=stored["email"],
        moderator_id=uuid.UUID(stored["moderator_id"]),
        decision=stored["status"],
    )
    assert verify(
        bytes(moderator.key.verify_key),
        REGISTRATION_DECISION_SIGNATURE_DOMAIN,
        record,
        bytes.fromhex(stored["decision_signature"]),
    )


def test_rejection_creates_no_account(client, database, moderator, moderator_headers, pending):
    request, key = pending
    response = _decide(
        client, moderator_headers, request, decision_body(request, moderator, "rejected")
    )
    assert response.status_code == 200, response.text
    assert response.json()["user_id"] is None
    assert _status(database, request["registration_request_id"])[0] == "rejected"
    assert not database.execute(
        "SELECT 1 FROM catalogue.user_public WHERE public_key = %s", (bytes(key.verify_key),)
    )
    # The key may apply again.
    again = client.post("/v1/accounts", json=registration_body(client, key))
    assert again.status_code == 202, again.text


def test_decision_is_final(client, database, moderator, moderator_headers, pending):
    request, _ = pending
    assert _decide(
        client, moderator_headers, request, decision_body(request, moderator)
    ).status_code == 200
    response = _decide(
        client, moderator_headers, request, decision_body(request, moderator, "rejected")
    )
    assert response.status_code == 409
    other = database.create_user("moderator")
    response = _decide(
        client, bearer(login(client, other)), request, decision_body(request, other, "rejected")
    )
    assert response.status_code == 409
    assert _status(database, request["registration_request_id"])[0] == "approved"


@pytest.mark.parametrize(
    "tamper",
    [
        pytest.param({"signer": SigningKey.generate()}, id="signed-with-another-key"),
        pytest.param({"signed_decision": "rejected"}, id="signed-reject-sent-approve"),
        pytest.param({"name": "Mallory"}, id="signed-different-name"),
        pytest.param({"requested_role": "moderator"}, id="signed-different-role"),
        pytest.param({"organisation": None}, id="signed-without-organisation"),
        pytest.param({"public_key": "11" * 32}, id="signed-different-key"),
        pytest.param({"registration_request_id": str(uuid.uuid4())}, id="signed-other-request"),
        pytest.param({"signed_moderator_id": uuid.uuid4()}, id="signed-as-other-moderator"),
    ],
)
def test_signature_must_cover_exactly_this_decision(
    client, database, moderator, moderator_headers, pending, tamper
):
    request, _ = pending
    response = _decide(
        client, moderator_headers, request, decision_body(request, moderator, **tamper)
    )
    assert response.status_code == 403
    assert response.json() == {"detail": "Decision signature rejected"}
    assert _status(database, request["registration_request_id"]) == (None, None, None)


def test_signature_from_another_moderator_is_not_accepted(
    client, database, moderator, moderator_headers, pending
):
    """A token for one Moderator cannot carry another Moderator's decision."""
    request, _ = pending
    other = database.create_user("moderator")
    response = _decide(client, moderator_headers, request, decision_body(request, other))
    assert response.status_code == 403
    assert "authenticated account" in response.json()["detail"]
    assert _status(database, request["registration_request_id"]) == (None, None, None)


def test_revoked_moderator_cannot_decide(client, database, moderator, moderator_headers, pending):
    request, _ = pending
    database.revoke(moderator.user_id)
    response = _decide(client, moderator_headers, request, decision_body(request, moderator))
    assert response.status_code == 401
    assert _status(database, request["registration_request_id"]) == (None, None, None)


@pytest.mark.parametrize(
    "body",
    [
        {"decision": "approved", "signature": "00" * 64},
        {"moderator_id": str(uuid.uuid4()), "decision": "maybe", "signature": "00" * 64},
        {"moderator_id": str(uuid.uuid4()), "decision": "approved", "signature": "00" * 63},
        {"moderator_id": str(uuid.uuid4()), "decision": "approved", "signature": "AA" * 64},
    ],
)
def test_malformed_decisions_are_rejected(client, moderator_headers, pending, body):
    request, _ = pending
    assert _decide(client, moderator_headers, request, body).status_code == 422


def test_zero_signature_is_rejected(client, database, moderator, moderator_headers, pending):
    """The old development placeholder must not pass."""
    request, _ = pending
    body = {"moderator_id": str(moderator.user_id), "decision": "approved", "signature": "00" * 64}
    assert _decide(client, moderator_headers, request, body).status_code == 403
    assert _status(database, request["registration_request_id"]) == (None, None, None)


def test_status_filter(client, moderator, moderator_headers, pending):
    request, _ = pending
    _decide(client, moderator_headers, request, decision_body(request, moderator, "rejected"))
    rejected = client.get("/v1/registrations?status=rejected", headers=moderator_headers).json()
    pending_rows = client.get("/v1/registrations", headers=moderator_headers).json()
    assert request["registration_request_id"] in {r["registration_request_id"] for r in rejected}
    assert request["registration_request_id"] not in {
        r["registration_request_id"] for r in pending_rows
    }
    assert client.get(
        "/v1/registrations?status=bogus", headers=moderator_headers
    ).status_code == 422
