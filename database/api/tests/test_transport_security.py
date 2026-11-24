"""Transport-level protections that do not need a database."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from api.config import Settings
from api.main import create_app
from fastapi.testclient import TestClient

from .conftest import make_settings


def test_docs_and_schema_are_disabled(offline_client):
    for path in ("/docs", "/redoc", "/openapi.json"):
        assert offline_client.get(path).status_code == 404


def test_docs_only_in_dev_mode():
    settings = make_settings("postgresql://relic_app@127.0.0.1:1/relic", insecure_dev_mode=True)
    with TestClient(create_app(settings)) as client:
        assert client.get("/openapi.json").status_code == 200


def test_security_headers_present(offline_client):
    response = offline_client.get("/healthz")
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert "default-src 'none'" in response.headers["content-security-policy"]
    assert "server" not in response.headers


def test_declared_oversized_body_is_rejected(offline_client):
    response = offline_client.post(
        "/v1/accounts",
        content=b"x" * (65 * 1024),
        headers={"content-type": "application/json"},
    )
    assert response.status_code == 413
    assert response.headers["x-content-type-options"] == "nosniff"


def test_streamed_oversized_body_is_rejected(offline_client):
    def chunks():
        for _ in range(100):
            yield b"x" * 1024

    response = offline_client.post(
        "/v1/accounts", content=chunks(), headers={"content-type": "application/json"}
    )
    assert response.status_code == 413


def test_unreachable_database_is_503_not_a_crash():
    settings = make_settings("postgresql://relic_app@127.0.0.1:1/relic")
    with TestClient(create_app(settings)) as client:
        client.app.state.pool.timeout = 0.5
        response = client.post("/v1/auth/challenge", json={"purpose": "registration"})
    assert response.status_code == 503
    assert response.json() == {"detail": "Database unavailable"}


@pytest.mark.parametrize(
    "database_url, overrides, message",
    [
        ("postgresql://relic_app@127.0.0.1/relic", {"jwt_secret": "short"}, "at least 32"),
        ("postgresql://relic_app@127.0.0.1/relic", {"host": "https://relic.test"}, "bare host"),
        ("postgresql://u@db.example.org/relic", {}, "without TLS"),
        ("postgresql://u@db.example.org/relic?sslmode=prefer", {}, "without TLS"),
    ],
)
def test_unsafe_configuration_is_refused(database_url, overrides, message):
    with pytest.raises(ValidationError, match=message):
        make_settings(database_url, **overrides)


def test_remote_database_with_tls_is_accepted():
    settings = make_settings("postgresql://u@db.example.org/relic?sslmode=verify-full")
    assert isinstance(settings, Settings)
    assert settings.audience == "https://relic.test"
