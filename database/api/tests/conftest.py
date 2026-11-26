"""Shared fixtures.

Database tests need a disposable PostgreSQL server reachable through a
superuser URI without a database name, for example::

    docker run -d --name relic-test-pg -e POSTGRES_PASSWORD=postgres \\
        -p 127.0.0.1:55432:5432 postgres:17-alpine
    RELIC_TEST_SUPERUSER_URL=postgresql://postgres:postgres@127.0.0.1:55432 pytest

The session rebuilds the ``relic`` database from scratch with
``database/tests/setup-disposable-db.sh``. Without the variable, database
tests are skipped and only the offline tests run.
"""

from __future__ import annotations

import os
import subprocess
import uuid
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

import psycopg
import pytest
from fastapi.testclient import TestClient
from nacl.signing import SigningKey

from api.config import Settings
from api.crypto import (
    LOGIN_SIGNATURE_DOMAIN,
    REGISTRATION_DECISION_SIGNATURE_DOMAIN,
    REGISTRATION_SIGNATURE_DOMAIN,
    Challenge,
    login_record,
    registration_decision_record,
    registration_record,
    signing_message,
)
from api.main import create_app

REPO = Path(__file__).resolve().parents[3]
SUPERUSER_URL = os.environ.get("RELIC_TEST_SUPERUSER_URL")
JWT_SECRET = "test-secret-" + "x" * 40


def make_settings(database_url: str, **overrides) -> Settings:
    values = dict(
        host="relic.test",
        database_url=database_url,
        jwt_secret=JWT_SECRET,
        global_rate_limit_per_minute=100_000,
        auth_rate_limit_per_minute=100_000,
        registration_rate_limit_per_hour=100_000,
        proof_rate_limit_per_minute=100_000,
    )
    values.update(overrides)
    return Settings(_env_file=None, **values)


@dataclass
class Database:
    super_url: str
    app_url: str
    worker_url: str
    auditor_url: str

    def execute(self, query: str, params: tuple = ()) -> list[tuple]:
        with psycopg.connect(self.super_url, autocommit=True) as conn:
            conn.execute("SET ROLE relic_owner")
            cur = conn.execute(query, params)
            return cur.fetchall() if cur.description else []

    def create_user(self, role: str | None, owner_type: str = "human") -> "User":
        key = SigningKey.generate()
        user_id = uuid.uuid4()
        self.execute(
            "INSERT INTO catalogue.user_public (user_id, public_key, role, owner_type)"
            " VALUES (%s, %s, %s::catalogue.account_role, %s::catalogue.account_owner_type)",
            (user_id, bytes(key.verify_key), role, owner_type),
        )
        return User(user_id, key, role)

    def revoke(self, target_id: uuid.UUID, target_type: str = "user") -> None:
        # Accounts are revoked at a Moderator's request, entries at an Analyst's.
        requester = self.create_user("moderator" if target_type == "user" else "analyst")
        moderator = self.create_user("moderator")
        revocation_id = self.execute(
            "INSERT INTO catalogue.revocation"
            " (requester_id, target_type, target_id, reason, request_signature)"
            " VALUES (%s, %s::catalogue.corpus_target_type, %s, 'test', %s) RETURNING revocation_id",
            (requester.user_id, target_type, target_id, b"\x01" * 64),
        )[0][0]
        self.execute(
            "UPDATE catalogue.revocation SET moderator_id = %s, decision = 'approved',"
            " decided_at = clock_timestamp(), decision_signature = %s"
            " WHERE revocation_id = %s",
            (moderator.user_id, b"\x02" * 64, revocation_id),
        )


@dataclass
class User:
    user_id: uuid.UUID
    key: SigningKey
    role: str | None

    @property
    def public_key_hex(self) -> str:
        return bytes(self.key.verify_key).hex()


def challenge_from(body: dict) -> Challenge:
    return Challenge(
        challenge_id=uuid.UUID(body["challenge_id"]),
        nonce=bytes.fromhex(body["nonce"]),
        audience=body["audience"],
        expires_at_unix_micros=body["expires_at_unix_micros"],
    )


def sign(key: SigningKey, domain: bytes, record: bytes) -> str:
    import hashlib

    digest = hashlib.sha256(record).digest()
    return key.sign(signing_message(domain, digest)).signature.hex()


def key_login_body(
    client: TestClient, key: SigningKey, *, signer: SigningKey | None = None
) -> dict:
    """A login request naming ``key``, signed by ``signer`` (default: ``key``)."""
    response = client.post("/v1/auth/challenge", json={"purpose": "login"})
    assert response.status_code == 201, response.text
    challenge = challenge_from(response.json())
    public_key = bytes(key.verify_key)
    return {
        "challenge_id": str(challenge.challenge_id),
        "public_key": public_key.hex(),
        "signature": sign(
            signer or key, LOGIN_SIGNATURE_DOMAIN, login_record(challenge, public_key)
        ),
    }


def login_body(client: TestClient, user: User, *, signer: SigningKey | None = None) -> dict:
    return key_login_body(client, user.key, signer=signer)


def login(client: TestClient, user: User) -> str:
    response = client.post("/v1/auth/login", json=login_body(client, user))
    assert response.status_code == 200, response.text
    return response.json()["access_token"]


def registration_body(
    client: TestClient,
    key: SigningKey,
    *,
    role: str = "analyst",
    name: str = "Ada Lovelace",
    organisation: str | None = "Analytical Engines",
    email: str = "ada@example.org",
) -> dict:
    response = client.post("/v1/auth/challenge", json={"purpose": "registration"})
    assert response.status_code == 201, response.text
    challenge = challenge_from(response.json())
    public_key = bytes(key.verify_key)
    record = registration_record(
        challenge,
        public_key=public_key,
        requested_role=role,
        name=name,
        organisation=organisation,
        email=email,
    )
    return {
        "challenge_id": str(challenge.challenge_id),
        "public_key": public_key.hex(),
        "requested_role": role,
        "name": name,
        "organisation": organisation,
        "email": email,
        "signature": sign(key, REGISTRATION_SIGNATURE_DOMAIN, record),
    }


def decision_body(
    request: dict,
    moderator: User,
    decision: str = "approved",
    *,
    signer: SigningKey | None = None,
    signed_decision: str | None = None,
    signed_moderator_id: uuid.UUID | None = None,
    **overrides,
) -> dict:
    """Sign a decision over ``request`` as returned by GET /v1/registrations/{id}."""
    details = {**request, **overrides}
    record = registration_decision_record(
        uuid.UUID(details["registration_request_id"]),
        public_key=bytes.fromhex(details["public_key"]),
        requested_role=details["requested_role"],
        name=details["name"],
        organisation=details["organisation"],
        email=details["email"],
        moderator_id=signed_moderator_id or moderator.user_id,
        decision=signed_decision or decision,
    )
    return {
        "moderator_id": str(moderator.user_id),
        "decision": decision,
        "signature": sign(signer or moderator.key, REGISTRATION_DECISION_SIGNATURE_DOMAIN, record),
    }


def decide(
    client: TestClient, database: "Database", request_id: str, decision: str = "approved"
) -> dict:
    """Have a fresh Moderator sign and submit a decision through the API."""
    moderator = database.create_user("moderator")
    headers = {"Authorization": f"Bearer {login(client, moderator)}"}
    request = client.get(f"/v1/registrations/{request_id}", headers=headers).json()
    response = client.post(
        f"/v1/registrations/{request_id}/decision",
        json=decision_body(request, moderator, decision),
        headers=headers,
    )
    assert response.status_code == 200, response.text
    return response.json()


@pytest.fixture(scope="session")
def database() -> Database:
    if not SUPERUSER_URL:
        pytest.skip("set RELIC_TEST_SUPERUSER_URL to run database tests")
    subprocess.run(
        [str(REPO / "database/tests/setup-disposable-db.sh"), SUPERUSER_URL],
        check=True,
        capture_output=True,
    )
    parts = urlsplit(SUPERUSER_URL)
    return Database(
        super_url=f"{SUPERUSER_URL}/relic",
        app_url=f"postgresql://relic_app:relic-test-only@{parts.hostname}:{parts.port}/relic",
        worker_url=f"postgresql://relic_worker:relic-test-only@{parts.hostname}:{parts.port}/relic",
        auditor_url=f"postgresql://relic_auditor:relic-test-only@{parts.hostname}:{parts.port}/relic",
    )


@pytest.fixture
def client(database: Database, object_dirs: "ObjectDirs"):
    settings = make_settings(
        database.app_url, staging_dir=object_dirs.staging, fidbf_root=object_dirs.store
    )
    with TestClient(create_app(settings)) as test_client:
        yield test_client


@dataclass
class ObjectDirs:
    """The API's staging directory and the FIDBF object store, for this session."""

    staging: Path
    store: Path


@pytest.fixture(scope="session")
def object_dirs(tmp_path_factory) -> ObjectDirs:
    root = tmp_path_factory.mktemp("objects")
    dirs = ObjectDirs(staging=root / "staging", store=root / "store")
    dirs.staging.mkdir()
    dirs.store.mkdir()
    return dirs


@pytest.fixture
def offline_client():
    """An app whose database is unreachable: for transport-level tests."""
    settings = make_settings("postgresql://relic_app@127.0.0.1:1/relic")
    with TestClient(create_app(settings)) as test_client:
        yield test_client
