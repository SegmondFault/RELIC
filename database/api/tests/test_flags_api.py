"""Signed flags (Viewers) and flag responses (Analysts).

Covers the negative acceptance tests required for every signed route: wrong
key, another User ID, altered content, another domain, wrong or revoked
identity, and no change to the table on failure. Plus the flag rules: one
flag per Viewer and target, nothing new on revoked targets or flags, and
flag responses as flag and revocation targets.
"""

from __future__ import annotations

import subprocess
import uuid
from pathlib import Path

import pytest
from nacl.signing import SigningKey

from api.crypto import (
    FLAG_RESPONSE_SIGNATURE_DOMAIN,
    FLAG_SIGNATURE_DOMAIN,
    REVOCATION_REQUEST_SIGNATURE_DOMAIN,
    Flag,
    flag_record,
    flag_response_record,
    verify,
)

from .conftest import User, login, sign
from .test_auth_api import SIGNER, _login_with_cli
from .test_revocations_api import _cli, _ssh_user
from .test_revocations_api import request_body as revocation_body


def bearer(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def flag_body(
    viewer: User,
    target_id: uuid.UUID,
    *,
    target_type: str = "source",
    note: str = "Licence looks wrong",
    flag_id: uuid.UUID | None = None,
    signer: SigningKey | None = None,
    domain: bytes = FLAG_SIGNATURE_DOMAIN,
    **signed_overrides,
) -> dict:
    """A flag as ``viewer`` would send it; ``signed_overrides`` change only what is signed."""
    fields = {
        "flag_id": flag_id or uuid.uuid4(),
        "viewer_id": viewer.user_id,
        "target_type": target_type,
        "target_id": target_id,
        "note": note,
    }
    record = flag_record(Flag(**{**fields, **signed_overrides}))
    body = {key: str(value) for key, value in fields.items()}
    body["signature"] = sign(signer or viewer.key, domain, record)
    return body


def response_body(
    stored: dict,
    analyst: User,
    *,
    note: str = "Checked, licence corrected",
    flag_response_id: uuid.UUID | None = None,
    signer: SigningKey | None = None,
    domain: bytes = FLAG_RESPONSE_SIGNATURE_DOMAIN,
    signed_note: str | None = None,
    signed_analyst_id: uuid.UUID | None = None,
    **signed_flag_overrides,
) -> dict:
    """Sign a response over ``stored`` as returned by GET /v1/flags/{id}."""
    flag = {**stored, **signed_flag_overrides}
    response_id = flag_response_id or uuid.uuid4()
    record = flag_response_record(
        Flag(
            flag_id=uuid.UUID(str(flag["flag_id"])),
            viewer_id=uuid.UUID(str(flag["viewer_id"])),
            target_type=flag["target_type"],
            target_id=uuid.UUID(str(flag["target_id"])),
            note=flag["note"],
        ),
        flag_response_id=response_id,
        analyst_id=signed_analyst_id or analyst.user_id,
        note=signed_note or note,
    )
    return {
        "flag_response_id": str(response_id),
        "analyst_id": str(analyst.user_id),
        "note": note,
        "signature": sign(signer or analyst.key, domain, record),
    }


@pytest.fixture
def viewer(database) -> User:
    return database.create_user("viewer")


@pytest.fixture
def viewer_headers(client, viewer) -> dict:
    return bearer(login(client, viewer))


@pytest.fixture
def analyst(database) -> User:
    return database.create_user("analyst")


@pytest.fixture
def analyst_headers(client, analyst) -> dict:
    return bearer(login(client, analyst))


@pytest.fixture
def source_id(database) -> uuid.UUID:
    """A fresh catalogue object to flag."""
    owner = database.create_user("analyst")
    source = uuid.uuid4()
    database.execute(
        "INSERT INTO catalogue.source (source_id, name, source_type, reference, snapshot_version,"
        " retrieved_at, is_ecological, submitted_by_analyst_id, signature)"
        " VALUES (%s, 'flag test', 'FIDBF', 'ref', 'v1', clock_timestamp(), true, %s, %s)",
        (source, owner.user_id, b"\x11" * 64),
    )
    return source


@pytest.fixture
def stored_flag(client, viewer, viewer_headers, source_id) -> dict:
    response = client.post("/v1/flags", json=flag_body(viewer, source_id), headers=viewer_headers)
    assert response.status_code == 201, response.text
    return response.json()


def _flags(database, target_id) -> int:
    return database.execute("SELECT count(*) FROM catalogue.flag WHERE target_id = %s", (target_id,))[0][0]


def _responses(database, flag_id) -> int:
    return database.execute(
        "SELECT count(*) FROM catalogue.flag_response WHERE flag_id = %s", (flag_id,)
    )[0][0]


def _respond(client, headers, stored, body):
    return client.post(f"/v1/flags/{stored['flag_id']}/responses", json=body, headers=headers)


# ---------------------------------------------------------------------------
# Flags
# ---------------------------------------------------------------------------


def test_viewer_flags_and_any_account_can_read(client, database, stored_flag, viewer, source_id):
    assert (stored_flag["viewer_id"], stored_flag["target_type"], stored_flag["target_id"]) == (
        str(viewer.user_id),
        "source",
        str(source_id),
    )
    assert stored_flag["revoked"] is False

    other = bearer(login(client, database.create_user("moderator")))
    assert client.get(f"/v1/flags/{stored_flag['flag_id']}", headers=other).json() == stored_flag
    listed = client.get(
        "/v1/flags", params={"target_type": "source", "target_id": str(source_id)}, headers=other
    ).json()
    assert listed == [stored_flag]


def test_stored_flag_signature_verifies_offline(stored_flag, viewer):
    record = flag_record(
        Flag(
            flag_id=uuid.UUID(stored_flag["flag_id"]),
            viewer_id=uuid.UUID(stored_flag["viewer_id"]),
            target_type=stored_flag["target_type"],
            target_id=uuid.UUID(stored_flag["target_id"]),
            note=stored_flag["note"],
        )
    )
    assert verify(
        bytes(viewer.key.verify_key),
        FLAG_SIGNATURE_DOMAIN,
        record,
        bytes.fromhex(stored_flag["signature"]),
    )


def test_identical_retry_returns_the_stored_flag(client, database, viewer, viewer_headers, source_id):
    body = flag_body(viewer, source_id)
    first = client.post("/v1/flags", json=body, headers=viewer_headers)
    again = client.post("/v1/flags", json=body, headers=viewer_headers)
    assert (first.status_code, again.status_code) == (201, 200)
    assert again.json() == first.json()
    assert _flags(database, source_id) == 1


def test_reused_flag_id_with_different_content_conflicts(
    client, database, viewer, viewer_headers, stored_flag
):
    other_target = database.create_user("viewer").user_id
    body = flag_body(
        viewer, other_target, target_type="user", flag_id=uuid.UUID(stored_flag["flag_id"])
    )
    response = client.post("/v1/flags", json=body, headers=viewer_headers)
    assert response.status_code == 409
    assert _flags(database, other_target) == 0


@pytest.mark.parametrize(
    "case",
    [
        "another_key",
        "another_users_id",
        "another_users_signed_flag",
        "altered_note",
        "altered_target",
        "revocation_domain",
        "response_domain",
    ],
)
def test_forged_flags_are_rejected_without_change(
    client, database, viewer, viewer_headers, source_id, case
):
    other = database.create_user("viewer")
    body = {
        "another_key": lambda: flag_body(viewer, source_id, signer=SigningKey.generate()),
        "another_users_id": lambda: {
            **flag_body(viewer, source_id, viewer_id=other.user_id),
            "viewer_id": str(other.user_id),
        },
        "another_users_signed_flag": lambda: flag_body(other, source_id),
        "altered_note": lambda: flag_body(viewer, source_id, note="Signed note")
        | {"note": "Sent note"},
        # Signed for another target, sent for this one.
        "altered_target": lambda: flag_body(viewer, uuid.uuid4()) | {"target_id": str(source_id)},
        "revocation_domain": lambda: flag_body(
            viewer, source_id, domain=REVOCATION_REQUEST_SIGNATURE_DOMAIN
        ),
        "response_domain": lambda: flag_body(
            viewer, source_id, domain=FLAG_RESPONSE_SIGNATURE_DOMAIN
        ),
    }[case]()
    response = client.post("/v1/flags", json=body, headers=viewer_headers)
    assert response.status_code == 403, response.text
    assert _flags(database, source_id) == 0


@pytest.mark.parametrize("role", ["analyst", "moderator"])
def test_only_viewers_can_flag(client, database, source_id, role):
    user = database.create_user(role)
    response = client.post(
        "/v1/flags", json=flag_body(user, source_id), headers=bearer(login(client, user))
    )
    assert response.status_code == 403
    assert _flags(database, source_id) == 0


def test_revoked_viewer_cannot_flag(client, database, viewer, viewer_headers, source_id):
    database.revoke(viewer.user_id)
    response = client.post("/v1/flags", json=flag_body(viewer, source_id), headers=viewer_headers)
    assert response.status_code == 401
    assert _flags(database, source_id) == 0


def test_unknown_target_is_rejected(client, viewer, viewer_headers):
    for target_type in ("user", "source", "flag", "flag_response"):
        response = client.post(
            "/v1/flags",
            json=flag_body(viewer, uuid.uuid4(), target_type=target_type),
            headers=viewer_headers,
        )
        assert response.status_code == 422, (target_type, response.text)


def test_one_flag_per_viewer_and_target(client, database, viewer, viewer_headers, stored_flag, source_id):
    response = client.post(
        "/v1/flags", json=flag_body(viewer, source_id, note="Again"), headers=viewer_headers
    )
    assert response.status_code == 409
    assert response.json()["detail"] == "You have already flagged this target"

    # Another Viewer can still flag it.
    other = database.create_user("viewer")
    response = client.post(
        "/v1/flags", json=flag_body(other, source_id), headers=bearer(login(client, other))
    )
    assert response.status_code == 201
    assert _flags(database, source_id) == 2


def test_accounts_flags_and_responses_can_be_flagged(
    client, database, viewer, viewer_headers, stored_flag, analyst, analyst_headers
):
    account = client.post(
        "/v1/flags",
        json=flag_body(viewer, analyst.user_id, target_type="user", note="Suspicious account"),
        headers=viewer_headers,
    )
    assert account.status_code == 201, account.text

    other = database.create_user("viewer")
    other_headers = bearer(login(client, other))
    on_flag = client.post(
        "/v1/flags",
        json=flag_body(other, uuid.UUID(stored_flag["flag_id"]), target_type="flag", note="Spam"),
        headers=other_headers,
    )
    assert on_flag.status_code == 201, on_flag.text

    answered = _respond(client, analyst_headers, stored_flag, response_body(stored_flag, analyst))
    assert answered.status_code == 201
    on_response = client.post(
        "/v1/flags",
        json=flag_body(
            other,
            uuid.UUID(answered.json()["flag_response_id"]),
            target_type="flag_response",
            note="Abusive response",
        ),
        headers=other_headers,
    )
    assert on_response.status_code == 201, on_response.text


def test_revoked_target_cannot_be_flagged(client, database, viewer, viewer_headers, source_id):
    database.revoke(source_id, "source")
    response = client.post("/v1/flags", json=flag_body(viewer, source_id), headers=viewer_headers)
    assert response.status_code == 409
    assert "is revoked" in response.json()["detail"]
    assert _flags(database, source_id) == 0


def test_created_at_comes_from_the_database(client, database, stored_flag):
    created = database.execute(
        "SELECT created_at <= clock_timestamp() AND created_at > clock_timestamp() - interval '1 minute'"
        " FROM catalogue.flag WHERE flag_id = %s",
        (stored_flag["flag_id"],),
    )[0][0]
    assert created is True


def test_database_requires_ed25519_signatures(database, viewer, source_id):
    with pytest.raises(Exception, match="flag_signature_ed25519"):
        database.execute(
            "INSERT INTO catalogue.flag (viewer_request_id, note, signature, target_type, target_id)"
            " VALUES (%s, 'x', %s, 'source', %s)",
            (viewer.user_id, b"\x01" * 63, source_id),
        )


@pytest.mark.parametrize(
    "field, value",
    [
        ("note", ""),
        ("note", " padded"),
        ("note", "two\nlines"),
        ("note", "x" * 2001),
        ("target_type", "integrity"),
        ("target_id", "not-a-uuid"),
        ("signature", "00" * 63),
        ("unexpected", "field"),
    ],
)
def test_malformed_flags_are_rejected(client, viewer, viewer_headers, source_id, field, value):
    body = flag_body(viewer, source_id)
    body[field] = value
    assert client.post("/v1/flags", json=body, headers=viewer_headers).status_code == 422


# ---------------------------------------------------------------------------
# Responses
# ---------------------------------------------------------------------------


def test_analysts_respond_and_any_account_can_read(
    client, database, stored_flag, analyst, analyst_headers, viewer_headers
):
    first = _respond(client, analyst_headers, stored_flag, response_body(stored_flag, analyst))
    assert first.status_code == 201, first.text
    second_analyst = database.create_user("analyst")
    second = _respond(
        client,
        bearer(login(client, second_analyst)),
        stored_flag,
        response_body(stored_flag, second_analyst, note="Agreed"),
    )
    assert second.status_code == 201, second.text

    stored = first.json()
    assert (stored["flag_id"], stored["analyst_id"], stored["revoked"]) == (
        stored_flag["flag_id"],
        str(analyst.user_id),
        False,
    )
    listed = client.get(
        "/v1/flag-responses", params={"flag_id": stored_flag["flag_id"]}, headers=viewer_headers
    ).json()
    assert sorted(row["flag_response_id"] for row in listed) == sorted(
        [stored["flag_response_id"], second.json()["flag_response_id"]]
    )
    one = client.get(f"/v1/flag-responses/{stored['flag_response_id']}", headers=viewer_headers)
    assert one.status_code == 200 and one.json() == stored
    assert client.get(f"/v1/flag-responses/{uuid.uuid4()}", headers=viewer_headers).status_code == 404

    # Re-verifiable from the flag and response rows alone.
    record = flag_response_record(
        Flag(
            flag_id=uuid.UUID(stored_flag["flag_id"]),
            viewer_id=uuid.UUID(stored_flag["viewer_id"]),
            target_type=stored_flag["target_type"],
            target_id=uuid.UUID(stored_flag["target_id"]),
            note=stored_flag["note"],
        ),
        flag_response_id=uuid.UUID(stored["flag_response_id"]),
        analyst_id=uuid.UUID(stored["analyst_id"]),
        note=stored["note"],
    )
    assert verify(
        bytes(analyst.key.verify_key),
        FLAG_RESPONSE_SIGNATURE_DOMAIN,
        record,
        bytes.fromhex(stored["signature"]),
    )


def test_identical_response_retry_returns_the_stored_response(
    client, database, stored_flag, analyst, analyst_headers
):
    body = response_body(stored_flag, analyst)
    first = _respond(client, analyst_headers, stored_flag, body)
    again = _respond(client, analyst_headers, stored_flag, body)
    assert (first.status_code, again.status_code) == (201, 200)
    assert again.json() == first.json()
    assert _responses(database, stored_flag["flag_id"]) == 1


def test_reused_response_id_with_different_content_conflicts(
    client, database, stored_flag, analyst, analyst_headers
):
    response_id = uuid.uuid4()
    first = response_body(stored_flag, analyst, flag_response_id=response_id)
    assert _respond(client, analyst_headers, stored_flag, first).status_code == 201
    changed = response_body(stored_flag, analyst, flag_response_id=response_id, note="Other")
    assert _respond(client, analyst_headers, stored_flag, changed).status_code == 409
    assert _responses(database, stored_flag["flag_id"]) == 1


@pytest.mark.parametrize(
    "case",
    [
        "another_key",
        "another_users_id",
        "signed_for_other_analyst",
        "altered_note",
        "signed_other_flag_note",
        "signed_other_target",
        "flag_domain",
    ],
)
def test_forged_responses_are_rejected_without_change(
    client, database, stored_flag, analyst, analyst_headers, case
):
    other = database.create_user("analyst")
    body = {
        "another_key": lambda: response_body(stored_flag, analyst, signer=SigningKey.generate()),
        "another_users_id": lambda: response_body(stored_flag, analyst, signed_analyst_id=other.user_id)
        | {"analyst_id": str(other.user_id)},
        "signed_for_other_analyst": lambda: response_body(
            stored_flag, analyst, signed_analyst_id=other.user_id
        ),
        "altered_note": lambda: response_body(stored_flag, analyst, signed_note="Signed note"),
        # The Analyst signed a different flag than the one stored.
        "signed_other_flag_note": lambda: response_body(stored_flag, analyst, note="Ok")
        | {"signature": response_body({**stored_flag, "note": "Edited"}, analyst)["signature"]},
        "signed_other_target": lambda: response_body(
            stored_flag, analyst, target_id=str(uuid.uuid4())
        ),
        "flag_domain": lambda: response_body(stored_flag, analyst, domain=FLAG_SIGNATURE_DOMAIN),
    }[case]()
    response = _respond(client, analyst_headers, stored_flag, body)
    assert response.status_code == 403, response.text
    assert _responses(database, stored_flag["flag_id"]) == 0


@pytest.mark.parametrize("role", ["viewer", "moderator"])
def test_only_analysts_can_respond(client, database, stored_flag, role):
    user = database.create_user(role)
    response = _respond(
        client, bearer(login(client, user)), stored_flag, response_body(stored_flag, user)
    )
    assert response.status_code == 403
    assert _responses(database, stored_flag["flag_id"]) == 0


def test_revoked_analyst_cannot_respond(client, database, stored_flag, analyst, analyst_headers):
    database.revoke(analyst.user_id)
    response = _respond(client, analyst_headers, stored_flag, response_body(stored_flag, analyst))
    assert response.status_code == 401
    assert _responses(database, stored_flag["flag_id"]) == 0


def test_unknown_flag_is_404(client, stored_flag, analyst, analyst_headers):
    missing = {**stored_flag, "flag_id": str(uuid.uuid4())}
    response = _respond(client, analyst_headers, missing, response_body(missing, analyst))
    assert response.status_code == 404


def test_revoked_flag_takes_no_responses(client, database, stored_flag, analyst, analyst_headers):
    database.revoke(uuid.UUID(stored_flag["flag_id"]), "flag")
    response = _respond(client, analyst_headers, stored_flag, response_body(stored_flag, analyst))
    assert response.status_code == 409
    assert "is revoked" in response.json()["detail"]
    assert _responses(database, stored_flag["flag_id"]) == 0


def test_responses_can_be_revoked_through_the_api(
    client, database, stored_flag, analyst, analyst_headers
):
    answered = _respond(client, analyst_headers, stored_flag, response_body(stored_flag, analyst))
    response_id = uuid.UUID(answered.json()["flag_response_id"])

    other = database.create_user("analyst")
    requested = client.post(
        "/v1/revocations",
        json=revocation_body(other, response_id, target_type="flag_response", reason="Abusive"),
        headers=bearer(login(client, other)),
    )
    assert requested.status_code == 201, requested.text
    assert requested.json()["target_type"] == "flag_response"

    moderator = database.create_user("moderator")
    database.execute(
        "UPDATE catalogue.revocation SET moderator_id = %s, decision = 'approved',"
        " decided_at = clock_timestamp(), decision_signature = %s WHERE revocation_id = %s",
        (moderator.user_id, b"\x02" * 64, requested.json()["revocation_id"]),
    )
    read = client.get(f"/v1/flag-responses/{response_id}", headers=analyst_headers).json()
    assert read["revoked"] is True


# ---------------------------------------------------------------------------
# Cross-implementation: the Rust client signs, the Python API verifies
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not SIGNER.exists(), reason="build with: cargo build -p relic-ingest")
def test_rust_client_flag_and_response(client, database, source_id, tmp_path: Path):
    viewer_id, viewer_key = _ssh_user(database, tmp_path, "viewer_ed25519", "viewer")
    analyst_id, analyst_key = _ssh_user(database, tmp_path, "analyst_ed25519", "analyst")
    viewer_headers = bearer(_login_with_cli(client, viewer_id, viewer_key, tmp_path))
    analyst_headers = bearer(_login_with_cli(client, analyst_id, analyst_key, tmp_path))

    body = _cli(
        "flag", "--viewer-id", str(viewer_id), "--target-type", "source",
        "--target-id", str(source_id), "--note", "Falsche Lizenz — wrong licence",
        "--key", str(viewer_key),
    )
    created = client.post("/v1/flags", json=body, headers=viewer_headers)
    assert created.status_code == 201, created.text
    flag_id = created.json()["flag_id"]

    flag_path = tmp_path / "flag.json"
    flag_path.write_text(client.get(f"/v1/flags/{flag_id}", headers=analyst_headers).text)
    answer = _cli(
        "respond-flag", "--flag", str(flag_path), "--analyst-id", str(analyst_id),
        "--note", "Geprüft — checked", "--key", str(analyst_key),
    )
    answered = client.post(f"/v1/flags/{flag_id}/responses", json=answer, headers=analyst_headers)
    assert answered.status_code == 201, answered.text

    # The CLI refuses to answer a revoked flag.
    database.revoke(uuid.UUID(flag_id), "flag")
    flag_path.write_text(client.get(f"/v1/flags/{flag_id}", headers=analyst_headers).text)
    refused = subprocess.run(
        [str(SIGNER), "respond-flag", "--flag", str(flag_path), "--analyst-id", str(analyst_id),
         "--note", "Again", "--key", str(analyst_key)],
        capture_output=True,
        text=True,
    )
    assert refused.returncode != 0 and "flag is revoked" in refused.stderr
