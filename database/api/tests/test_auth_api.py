"""Login, registration, /me and /users against a disposable database."""

from __future__ import annotations

import json
import subprocess
import time
import uuid
from pathlib import Path

import jwt
import pytest
from fastapi.testclient import TestClient
from nacl.signing import SigningKey

from api.main import create_app

from .conftest import (
    JWT_SECRET,
    REPO,
    decide,
    key_login_body,
    login,
    login_body,
    make_settings,
    registration_body,
)


def bearer(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------------------
# Login
# ---------------------------------------------------------------------------


def test_login_and_me(client, database):
    analyst = database.create_user("analyst")
    token = login(client, analyst)

    response = client.get("/v1/me", headers=bearer(token))
    assert response.status_code == 200
    body = response.json()
    assert body["user_id"] == str(analyst.user_id)
    assert body["role"] == "analyst"
    assert body["owner_type"] == "human"
    assert body["public_key"] == analyst.public_key_hex
    assert body["revoked"] is False


def test_login_challenge_is_single_use(client, database):
    analyst = database.create_user("analyst")
    body = login_body(client, analyst)
    assert client.post("/v1/auth/login", json=body).status_code == 200
    assert client.post("/v1/auth/login", json=body).status_code == 401


def test_login_with_another_key_fails(client, database):
    analyst = database.create_user("analyst")
    body = login_body(client, analyst, signer=SigningKey.generate())
    assert client.post("/v1/auth/login", json=body).status_code == 401


def test_login_signature_cannot_be_moved_to_another_key(client, database):
    victim = database.create_user("moderator")
    attacker = database.create_user("viewer")
    body = login_body(client, attacker)
    body["public_key"] = victim.public_key_hex
    assert client.post("/v1/auth/login", json=body).status_code == 401


def test_login_identifies_the_account_by_key(client, database):
    analyst = database.create_user("analyst")
    database.create_user("moderator")
    token = login(client, analyst)
    me = client.get("/v1/me", headers=bearer(token)).json()
    assert me["user_id"] == str(analyst.user_id)
    assert me["role"] == "analyst"


def test_failed_login_burns_the_challenge(client, database):
    analyst = database.create_user("analyst")
    good = login_body(client, analyst)
    bad = dict(good, signature="00" * 64)
    assert client.post("/v1/auth/login", json=bad).status_code == 401
    assert client.post("/v1/auth/login", json=good).status_code == 401


def test_unknown_key_cannot_log_in_even_with_a_valid_signature(client):
    response = client.post("/v1/auth/login", json=key_login_body(client, SigningKey.generate()))
    assert response.status_code == 401


def test_failures_without_the_private_key_are_indistinguishable(client, database):
    """Unknown key, registered key, pending registration: same answer without a valid signature."""
    registered = database.create_user("analyst")
    applicant = SigningKey.generate()
    assert client.post("/v1/accounts", json=registration_body(client, applicant)).status_code == 202

    responses = [
        client.post(
            "/v1/auth/login", json=key_login_body(client, key, signer=SigningKey.generate())
        )
        for key in (SigningKey.generate(), registered.key, applicant)
    ]
    assert {response.status_code for response in responses} == {401}
    assert len({response.text for response in responses}) == 1


def test_system_account_cannot_log_in(client, database):
    system = database.create_user(None, owner_type="system")
    assert client.post("/v1/auth/login", json=login_body(client, system)).status_code == 401


def test_revocation_blocks_login_and_live_tokens(client, database):
    analyst = database.create_user("analyst")
    token = login(client, analyst)
    assert client.get("/v1/me", headers=bearer(token)).status_code == 200

    database.revoke(analyst.user_id)

    assert client.get("/v1/me", headers=bearer(token)).status_code == 401
    response = client.post("/v1/auth/login", json=login_body(client, analyst))
    assert response.status_code == 403
    assert response.json()["detail"] == "Account has been revoked"

    # Without the key the revocation is not disclosed.
    forged = client.post("/v1/auth/login", json=login_body(client, analyst, signer=SigningKey.generate()))
    assert forged.status_code == 401


def test_expired_challenge_is_rejected(database):
    settings = make_settings(database.app_url, challenge_ttl_seconds=1)
    analyst = database.create_user("analyst")
    with TestClient(create_app(settings)) as client:
        body = login_body(client, analyst)
        time.sleep(1.2)
        assert client.post("/v1/auth/login", json=body).status_code == 401


def test_challenge_request_validation(client):
    assert client.post("/v1/auth/challenge", json={"purpose": "login"}).status_code == 201
    # Challenges name no account.
    for purpose in ("login", "registration"):
        assert (
            client.post(
                "/v1/auth/challenge", json={"purpose": purpose, "user_id": str(uuid.uuid4())}
            ).status_code
            == 422
        )
    assert client.post("/v1/auth/challenge", json={"purpose": "admin"}).status_code == 422


def test_login_rate_limit(database):
    settings = make_settings(database.app_url, auth_rate_limit_per_minute=3)
    with TestClient(create_app(settings)) as client:
        codes = [
            client.post("/v1/auth/challenge", json={"purpose": "registration"}).status_code
            for _ in range(4)
        ]
    assert codes == [201, 201, 201, 429]


# ---------------------------------------------------------------------------
# Tokens
# ---------------------------------------------------------------------------


def _claims(user_id: uuid.UUID, **overrides) -> dict:
    now = int(time.time())
    claims = {
        "iss": "https://relic.test",
        "aud": "https://relic.test",
        "sub": str(user_id),
        "iat": now,
        "nbf": now,
        "exp": now + 300,
        "jti": uuid.uuid4().hex,
    }
    claims.update(overrides)
    return claims


@pytest.mark.parametrize(
    "make_token",
    [
        pytest.param(lambda uid: jwt.encode(_claims(uid), "wrong-" * 10, algorithm="HS256"), id="wrong-secret"),
        pytest.param(lambda uid: jwt.encode(_claims(uid, exp=int(time.time()) - 1), JWT_SECRET, algorithm="HS256"), id="expired"),
        pytest.param(lambda uid: jwt.encode(_claims(uid, aud="https://other.example"), JWT_SECRET, algorithm="HS256"), id="wrong-audience"),
        pytest.param(lambda uid: jwt.encode(_claims(uid, iss="https://other.example"), JWT_SECRET, algorithm="HS256"), id="wrong-issuer"),
        pytest.param(lambda uid: jwt.encode({k: v for k, v in _claims(uid).items() if k != "jti"}, JWT_SECRET, algorithm="HS256"), id="missing-claim"),
        pytest.param(lambda uid: jwt.encode(_claims(uid), None, algorithm="none"), id="alg-none"),
        pytest.param(lambda uid: "x" * 5000, id="oversized"),
    ],
)
def test_forged_tokens_are_rejected(client, database, make_token):
    analyst = database.create_user("analyst")
    response = client.get("/v1/me", headers=bearer(make_token(analyst.user_id)))
    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"


def test_missing_token_is_rejected(client):
    assert client.get("/v1/me").status_code == 401
    assert client.get("/v1/users").status_code == 401


def test_unimplemented_routes_still_require_authentication(client):
    assert client.get("/v1/fidbf").status_code == 401
    assert client.post("/v1/flags").status_code == 401
    assert client.post("/v1/revocations").status_code == 401


# ---------------------------------------------------------------------------
# Users
# ---------------------------------------------------------------------------


def test_users_list_and_detail_expose_only_public_identity(client, database):
    viewer = database.create_user("viewer")
    token = login(client, viewer)

    response = client.get("/v1/users", params={"limit": 500}, headers=bearer(token))
    assert response.status_code == 200
    users = {user["user_id"]: user for user in response.json()}
    assert str(viewer.user_id) in users
    assert set(users[str(viewer.user_id)]) == {
        "user_id", "role", "owner_type", "public_key", "created_at", "revoked",
    }

    detail = client.get(f"/v1/users/{viewer.user_id}", headers=bearer(token))
    assert detail.status_code == 200
    assert detail.json()["public_key"] == viewer.public_key_hex

    assert client.get(f"/v1/users/{uuid.uuid4()}", headers=bearer(token)).status_code == 404
    assert client.get("/v1/users/not-a-uuid", headers=bearer(token)).status_code == 422
    assert client.get("/v1/users", params={"limit": 501}, headers=bearer(token)).status_code == 422


def test_users_show_revocation(client, database):
    reader = database.create_user("viewer")
    revoked = database.create_user("analyst")
    database.revoke(revoked.user_id)
    token = login(client, reader)
    body = client.get(f"/v1/users/{revoked.user_id}", headers=bearer(token)).json()
    assert body["revoked"] is True


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------


def _pending(database, request_id: str) -> tuple:
    return database.execute(
        "SELECT requested_role::text, name, organisation, email, decision"
        " FROM catalogue.registration_request WHERE registration_request_id = %s",
        (request_id,),
    )[0]


def test_registration_creates_a_pending_request_not_an_account(client, database):
    key = SigningKey.generate()
    response = client.post("/v1/accounts", json=registration_body(client, key))
    assert response.status_code == 202, response.text
    body = response.json()
    assert body["status"] == "pending"
    assert _pending(database, body["registration_request_id"]) == (
        "analyst", "Ada Lovelace", "Analytical Engines", "ada@example.org", None,
    )
    assert not database.execute(
        "SELECT 1 FROM catalogue.user_public WHERE public_key = %s", (bytes(key.verify_key),)
    )


def test_registration_without_organisation(client, database):
    body = registration_body(client, SigningKey.generate(), organisation=None, role="viewer")
    response = client.post("/v1/accounts", json=body)
    assert response.status_code == 202, response.text


def test_approved_registration_can_log_in_with_requested_role(client, database):
    key = SigningKey.generate()
    request_id = client.post(
        "/v1/accounts", json=registration_body(client, key, role="viewer")
    ).json()["registration_request_id"]
    user_id = decide(client, database, request_id)["user_id"]

    # The applicant needs only their key: /v1/me tells them their User ID.
    response = client.post("/v1/auth/login", json=key_login_body(client, key))
    assert response.status_code == 200, response.text
    me = client.get("/v1/me", headers=bearer(response.json()["access_token"])).json()
    assert me["role"] == "viewer"
    assert me["user_id"] == user_id


def test_pending_registration_is_reported_only_to_the_key_holder(client):
    key = SigningKey.generate()
    assert client.post("/v1/accounts", json=registration_body(client, key)).status_code == 202

    response = client.post("/v1/auth/login", json=key_login_body(client, key))
    assert response.status_code == 403
    assert response.json()["detail"] == "Registration is pending approval"


def test_rejected_registration_is_reported_only_to_the_key_holder(client, database):
    key = SigningKey.generate()
    request_id = client.post("/v1/accounts", json=registration_body(client, key)).json()[
        "registration_request_id"
    ]
    decide(client, database, request_id, "rejected")

    response = client.post("/v1/auth/login", json=key_login_body(client, key))
    assert response.status_code == 403
    assert response.json()["detail"] == "Registration was rejected"

    forged = key_login_body(client, key, signer=SigningKey.generate())
    assert client.post("/v1/auth/login", json=forged).status_code == 401


@pytest.mark.parametrize(
    "field, value",
    [
        ("name", "Mallory"),
        ("email", "mallory@example.org"),
        ("requested_role", "moderator"),
        ("organisation", None),
    ],
)
def test_tampered_registration_is_rejected(client, field, value):
    body = registration_body(client, SigningKey.generate())
    body[field] = value
    assert client.post("/v1/accounts", json=body).status_code == 401


def test_registration_requires_possession_of_the_key(client):
    claimed = SigningKey.generate()
    body = registration_body(client, SigningKey.generate())
    body["public_key"] = bytes(claimed.verify_key).hex()
    assert client.post("/v1/accounts", json=body).status_code == 401


def test_registration_challenge_is_single_use(client):
    body = registration_body(client, SigningKey.generate())
    assert client.post("/v1/accounts", json=body).status_code == 202
    assert client.post("/v1/accounts", json=body).status_code == 401


def test_login_challenge_cannot_be_used_for_registration(client, database):
    analyst = database.create_user("analyst")
    login_challenge = client.post("/v1/auth/challenge", json={"purpose": "login"}).json()
    body = registration_body(client, SigningKey.generate())
    body["challenge_id"] = login_challenge["challenge_id"]
    assert client.post("/v1/accounts", json=body).status_code == 401


def test_duplicate_keys_are_conflicts(client, database):
    key = SigningKey.generate()
    assert client.post("/v1/accounts", json=registration_body(client, key)).status_code == 202
    assert client.post("/v1/accounts", json=registration_body(client, key)).status_code == 409

    existing = database.create_user("analyst")
    body = registration_body(client, existing.key)
    assert client.post("/v1/accounts", json=body).status_code == 409


@pytest.mark.parametrize(
    "field, value",
    [
        ("name", " Ada"),
        ("name", "Ada\nLovelace"),
        ("name", "x" * 201),
        ("email", "not-an-email"),
        ("requested_role", "admin"),
        ("public_key", "AB" * 32),
        ("signature", "00" * 63),
        ("unexpected", "field"),
    ],
)
def test_malformed_registration_is_rejected_before_any_work(client, field, value):
    body = registration_body(client, SigningKey.generate())
    body[field] = value
    assert client.post("/v1/accounts", json=body).status_code == 422


# ---------------------------------------------------------------------------
# Cross-implementation: the Rust client signs, the Python API verifies
# ---------------------------------------------------------------------------

SIGNER = REPO / "target/debug/relic-sign-challenge"


@pytest.mark.skipif(not SIGNER.exists(), reason="build with: cargo build -p relic-ingest")
def test_rust_client_registration_and_login(client, database, tmp_path: Path):
    key_path = tmp_path / "id_ed25519"
    subprocess.run(
        ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key_path)], check=True
    )
    challenge_path = tmp_path / "challenge.json"

    def signed(command: list[str], purpose_body: dict) -> dict:
        challenge = client.post("/v1/auth/challenge", json=purpose_body).json()
        challenge_path.write_text(json.dumps(challenge))
        output = subprocess.run(
            [str(SIGNER), *command, "--challenge", str(challenge_path), "--key", str(key_path)],
            check=True,
            capture_output=True,
            text=True,
        ).stdout
        return json.loads(output)

    registration = signed(
        ["register", "--role", "analyst", "--name", "Grace Hopper", "--email", "grace@example.org",
         "--organisation", "Ünïcode Navy"],
        {"purpose": "registration"},
    )
    response = client.post("/v1/accounts", json=registration)
    assert response.status_code == 202, response.text

    # The Moderator reviews the request and signs the decision with their own
    # OpenSSH key through the same CLI.
    moderator_key_path = tmp_path / "moderator_ed25519"
    subprocess.run(
        ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(moderator_key_path)], check=True
    )
    moderator_public = _openssh_public_key(moderator_key_path.with_suffix(".pub"))
    moderator_id = database.execute(
        "INSERT INTO catalogue.user_public (public_key, role) VALUES (%s, 'moderator')"
        " RETURNING user_id",
        (moderator_public,),
    )[0][0]

    moderator_token = _login_with_cli(client, moderator_id, moderator_key_path, tmp_path)
    headers = bearer(moderator_token)
    request_id = response.json()["registration_request_id"]
    request_path = tmp_path / "request.json"
    request_path.write_text(client.get(f"/v1/registrations/{request_id}", headers=headers).text)
    decision = json.loads(
        subprocess.run(
            [str(SIGNER), "decide-registration", "--request", str(request_path),
             "--moderator-id", str(moderator_id), "--decision", "approved",
             "--key", str(moderator_key_path)],
            check=True,
            capture_output=True,
            text=True,
        ).stdout
    )
    decided = client.post(
        f"/v1/registrations/{request_id}/decision", json=decision, headers=headers
    )
    assert decided.status_code == 200, decided.text
    user_id = decided.json()["user_id"]

    login_request = signed(["login"], {"purpose": "login"})
    token = client.post("/v1/auth/login", json=login_request)
    assert token.status_code == 200, token.text
    me = client.get("/v1/me", headers=bearer(token.json()["access_token"])).json()
    assert me["role"] == "analyst"
    assert me["user_id"] == str(user_id)


def _openssh_public_key(path: Path) -> bytes:
    import base64

    blob = base64.b64decode(path.read_text().split()[1])
    return blob[-32:]


def _login_with_cli(client, user_id, key_path: Path, tmp_path: Path) -> str:
    challenge = client.post("/v1/auth/challenge", json={"purpose": "login"}).json()
    challenge_path = tmp_path / f"login-{user_id}.json"
    challenge_path.write_text(json.dumps(challenge))
    body = json.loads(
        subprocess.run(
            [str(SIGNER), "login", "--challenge", str(challenge_path), "--key", str(key_path)],
            check=True,
            capture_output=True,
            text=True,
        ).stdout
    )
    response = client.post("/v1/auth/login", json=body)
    assert response.status_code == 200, response.text
    return response.json()["access_token"]
