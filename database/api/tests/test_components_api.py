"""Signed software components, releases, binary-component assertions and
behavioural compositions (Analysts).

Covers the negative acceptance tests required for every signed route (wrong
key, another User ID, altered content, another domain, wrong role, no change
on failure), identical retries, revoked targets, and the database rule that
a composition's members are written with it and never later.
"""

from __future__ import annotations

import json
import subprocess
import uuid
from pathlib import Path

import psycopg
import pytest
from nacl.signing import SigningKey

from api.crypto import (
    BEHAVIOURAL_COMPOSITION_SIGNATURE_DOMAIN,
    BINARY_COMPONENT_ASSERTION_SIGNATURE_DOMAIN,
    CLASSIFICATION_SIGNATURE_DOMAIN,
    SOFTWARE_COMPONENT_SIGNATURE_DOMAIN,
    SOFTWARE_RELEASE_SIGNATURE_DOMAIN,
    BehaviouralComposition,
    BinaryComponentAssertion,
    CompositionMember,
    SoftwareComponent,
    SoftwareRelease,
    behavioural_composition_record,
    binary_component_assertion_record,
    software_component_record,
    software_release_record,
    verify,
)

from .conftest import REPO, User, login, sign
from .test_auth_api import SIGNER, _login_with_cli
from .test_claims_api import Objects, analyst, analyst_headers, bearer, classification_body, objects
from .test_revocations_api import _ssh_user

__all__ = ["analyst", "analyst_headers", "objects"]  # fixtures re-used from test_claims_api

VERIFY = REPO / "target/debug/relic-verify"


def _wire(fields: dict) -> dict:
    return {key: (str(value) if isinstance(value, uuid.UUID) else value) for key, value in fields.items()}


def component_body(
    analyst: User,
    *,
    name: str = "OpenSSL",
    component_kind: str = "library",
    namespace: str | None = "openssl.org",
    purl: str | None = "pkg:generic/openssl",
    component_id: uuid.UUID | None = None,
    signer: SigningKey | None = None,
    domain: bytes = SOFTWARE_COMPONENT_SIGNATURE_DOMAIN,
    **signed_overrides,
) -> dict:
    """``signed_overrides`` change only what is signed, not what is sent."""
    fields = {
        "component_id": component_id or uuid.uuid4(),
        "analyst_id": analyst.user_id,
        "name": name,
        "component_kind": component_kind,
        "namespace": namespace,
        "purl": purl,
    }
    record = software_component_record(SoftwareComponent(**{**fields, **signed_overrides}))
    return _wire(fields) | {"signature": sign(signer or analyst.key, domain, record)}


def release_body(
    analyst: User,
    component_id: uuid.UUID,
    *,
    version: str | None = "3.0.13",
    source_id: uuid.UUID | None = None,
    software_release_id: uuid.UUID | None = None,
    signer: SigningKey | None = None,
    domain: bytes = SOFTWARE_RELEASE_SIGNATURE_DOMAIN,
    **signed_overrides,
) -> dict:
    fields = {
        "software_release_id": software_release_id or uuid.uuid4(),
        "analyst_id": analyst.user_id,
        "component_id": component_id,
        "version": version,
        "source_id": source_id,
    }
    record = software_release_record(SoftwareRelease(**{**fields, **signed_overrides}))
    return _wire(fields) | {"signature": sign(signer or analyst.key, domain, record)}


def assertion_body(
    analyst: User,
    binary_id: uuid.UUID,
    software_release_id: uuid.UUID,
    *,
    relationship: str = "statically_contains",
    basis: str = "detected",
    confidence: str | None = "0.7500",
    evidence_provenance_id: uuid.UUID | None = None,
    binary_component_assertion_id: uuid.UUID | None = None,
    signer: SigningKey | None = None,
    domain: bytes = BINARY_COMPONENT_ASSERTION_SIGNATURE_DOMAIN,
    **signed_overrides,
) -> dict:
    fields = {
        "binary_component_assertion_id": binary_component_assertion_id or uuid.uuid4(),
        "analyst_id": analyst.user_id,
        "binary_id": binary_id,
        "software_release_id": software_release_id,
        "relationship": relationship,
        "basis": basis,
        "confidence": confidence,
        "evidence_provenance_id": evidence_provenance_id,
    }
    record = binary_component_assertion_record(
        BinaryComponentAssertion(**{**fields, **signed_overrides})
    )
    return _wire(fields) | {"signature": sign(signer or analyst.key, domain, record)}


def default_members(objects: Objects) -> list[dict]:
    return [
        {"target_type": "binary", "target_id": objects.binary_id, "member_role": "loader",
         "sequence_number": 0},
        {"target_type": "function", "target_id": objects.function_id, "member_role": "payload",
         "sequence_number": 1},
    ]


def composition_body(
    analyst: User,
    members: list[dict],
    *,
    name: str = "Staged loader",
    description: str | None = "Loader decrypts and runs a payload",
    evidence_provenance_id: uuid.UUID | None = None,
    behavioural_composition_id: uuid.UUID | None = None,
    signed_members: list[dict] | None = None,
    signer: SigningKey | None = None,
    domain: bytes = BEHAVIOURAL_COMPOSITION_SIGNATURE_DOMAIN,
    **signed_overrides,
) -> dict:
    fields = {
        "behavioural_composition_id": behavioural_composition_id or uuid.uuid4(),
        "analyst_id": analyst.user_id,
        "name": name,
        "description": description,
        "evidence_provenance_id": evidence_provenance_id,
    }
    signed = {**fields, **signed_overrides}
    signed["members"] = tuple(CompositionMember(**m) for m in (signed_members or members))
    record = behavioural_composition_record(BehaviouralComposition(**signed))
    return _wire(fields) | {
        "members": [_wire(m) for m in members],
        "signature": sign(signer or analyst.key, domain, record),
    }


def _count(database, table: str, key: str, value) -> int:
    return database.execute(f"SELECT count(*) FROM catalogue.{table} WHERE {key} = %s", (value,))[0][0]


def _post(client, path: str, body: dict, headers: dict):
    return client.post(f"/v1/{path}", json=body, headers=headers)


@pytest.fixture
def release(client, analyst, analyst_headers, objects) -> tuple[uuid.UUID, uuid.UUID]:
    """(component_id, software_release_id), created through the API."""
    component = _post(client, "software-components", component_body(analyst), analyst_headers)
    assert component.status_code == 201, component.text
    component_id = uuid.UUID(component.json()["component_id"])
    body = release_body(analyst, component_id, source_id=objects.source_id)
    created = _post(client, "software-releases", body, analyst_headers)
    assert created.status_code == 201, created.text
    return component_id, uuid.UUID(created.json()["software_release_id"])


# ---------------------------------------------------------------------------
# The whole chain, read back and re-verified by another account
# ---------------------------------------------------------------------------


def test_analyst_builds_the_component_model_and_any_account_can_read(
    client, database, analyst, analyst_headers, objects, release
):
    component_id, release_id = release
    assertion = _post(
        client, "binary-component-assertions",
        assertion_body(analyst, objects.binary_id, release_id), analyst_headers,
    )
    assert assertion.status_code == 201, assertion.text
    # Members sent in the reverse of the order they were signed in.
    members = default_members(objects)
    composition = _post(
        client, "behavioural-compositions",
        composition_body(analyst, members[::-1], signed_members=members), analyst_headers,
    )
    assert composition.status_code == 201, composition.text
    assert composition.json()["member_count"] == 2

    viewer = bearer(login(client, database.create_user("viewer")))
    key = bytes(analyst.key.verify_key)

    c = client.get(f"/v1/software-components/{component_id}", headers=viewer).json()
    assert c["purl"] == "pkg:generic/openssl" and c["revoked"] is False
    assert verify(key, SOFTWARE_COMPONENT_SIGNATURE_DOMAIN, software_component_record(
        SoftwareComponent(
            component_id=uuid.UUID(c["component_id"]),
            analyst_id=uuid.UUID(c["created_by_analyst_id"]), name=c["name"],
            component_kind=c["component_kind"], namespace=c["namespace"], purl=c["purl"],
        )), bytes.fromhex(c["signature"]))

    r = client.get(f"/v1/software-releases/{release_id}", headers=viewer).json()
    assert (r["component_id"], r["source_id"]) == (str(component_id), str(objects.source_id))
    assert verify(key, SOFTWARE_RELEASE_SIGNATURE_DOMAIN, software_release_record(
        SoftwareRelease(
            software_release_id=uuid.UUID(r["software_release_id"]),
            analyst_id=uuid.UUID(r["created_by_analyst_id"]),
            component_id=uuid.UUID(r["component_id"]), version=r["version"],
            source_id=uuid.UUID(r["source_id"]),
        )), bytes.fromhex(r["signature"]))

    a = client.get(
        f"/v1/binary-component-assertions/{assertion.json()['binary_component_assertion_id']}",
        headers=viewer,
    ).json()
    assert a == assertion.json() and a["confidence"] == "0.7500"

    d = client.get(
        f"/v1/behavioural-compositions/{composition.json()['behavioural_composition_id']}",
        headers=viewer,
    ).json()
    assert d == composition.json()
    assert [m["sequence_number"] for m in d["members"]] == [0, 1]
    assert verify(key, BEHAVIOURAL_COMPOSITION_SIGNATURE_DOMAIN, behavioural_composition_record(
        BehaviouralComposition(
            behavioural_composition_id=uuid.UUID(d["behavioural_composition_id"]),
            analyst_id=uuid.UUID(d["submitted_by_analyst_id"]), name=d["name"],
            description=d["description"], evidence_provenance_id=None,
            members=tuple(
                CompositionMember(m["target_type"], uuid.UUID(m["target_id"]), m["member_role"],
                                  m["sequence_number"])
                for m in d["members"]
            ),
        )), bytes.fromhex(d["signature"]))

    # Lists and their filters.
    assert [x["software_release_id"] for x in client.get(
        f"/v1/software-releases?component_id={component_id}", headers=viewer).json()
    ] == [str(release_id)]
    assert [x["component_id"] for x in client.get(
        "/v1/software-components?purl=pkg:generic/openssl", headers=viewer).json()
    ] == [str(component_id)]
    assert len(client.get(
        f"/v1/binary-component-assertions?binary_id={objects.binary_id}", headers=viewer).json()
    ) == 1
    containing = client.get(
        f"/v1/behavioural-compositions?member_type=function&member_id={objects.function_id}",
        headers=viewer,
    ).json()
    assert [x["behavioural_composition_id"] for x in containing] == [d["behavioural_composition_id"]]
    assert "members" not in containing[0]
    assert client.get(
        f"/v1/behavioural-compositions?member_id={objects.function_id}", headers=viewer
    ).status_code == 422

    # The composition can be classified; its members are not.
    classified = _post(
        client, "classifications",
        classification_body(analyst, uuid.UUID(d["behavioural_composition_id"]),
                            target_type="behavioural_composition"),
        analyst_headers,
    )
    assert classified.status_code == 201, classified.text


# ---------------------------------------------------------------------------
# Retries, forgeries and roles, for every route
# ---------------------------------------------------------------------------

KINDS = ["component", "release", "assertion", "composition"]
ROUTES = {
    "component": ("software-components", "software_component", "component_id"),
    "release": ("software-releases", "software_release", "software_release_id"),
    "assertion": (
        "binary-component-assertions", "binary_component_assertion",
        "binary_component_assertion_id",
    ),
    "composition": (
        "behavioural-compositions", "behavioural_composition", "behavioural_composition_id",
    ),
}


def _builder(kind: str, objects: Objects, release):
    """body(analyst, **kwargs) for one kind, with valid targets filled in."""
    component_id, release_id = release
    return {
        "component": lambda user, **kw: component_body(user, **kw),
        "release": lambda user, **kw: release_body(user, component_id, **kw),
        "assertion": lambda user, **kw: assertion_body(user, objects.binary_id, release_id, **kw),
        "composition": lambda user, **kw: composition_body(user, default_members(objects), **kw),
    }[kind]


# One signed field per kind, with its default value and another value.
DEFAULTS = {
    "component": {"name": "OpenSSL"},
    "release": {"version": "3.0.13"},
    "assertion": {"relationship": "statically_contains"},
    "composition": {"name": "Staged loader"},
}
ALTERED = {
    "component": {"name": "LibreSSL"},
    "release": {"version": "1.1.1"},
    "assertion": {"relationship": "dynamically_links"},
    "composition": {"name": "Benign chain"},
}


@pytest.mark.parametrize("kind", KINDS)
def test_retry_returns_the_row_and_reuse_conflicts(
    client, database, analyst, analyst_headers, objects, release, kind
):
    path, table, id_field = ROUTES[kind]
    build = _builder(kind, objects, release)
    body = build(analyst)
    first = _post(client, path, body, analyst_headers)
    again = _post(client, path, body, analyst_headers)
    assert (first.status_code, again.status_code) == (201, 200), first.text
    assert again.json() == first.json()
    field, value = next(iter(ALTERED[kind].items()))
    other = build(analyst, **{id_field: uuid.UUID(body[id_field]), field: value})
    conflict = _post(client, path, other, analyst_headers)
    assert conflict.status_code == 409 and "already used" in conflict.json()["detail"]
    assert _count(database, table, id_field, body[id_field]) == 1


def test_composition_retry_with_members_in_another_order_is_identical(
    client, analyst, analyst_headers, objects
):
    members = default_members(objects)
    body = composition_body(analyst, members)
    assert _post(client, "behavioural-compositions", body, analyst_headers).status_code == 201
    reordered = body | {"members": body["members"][::-1]}
    assert _post(client, "behavioural-compositions", reordered, analyst_headers).status_code == 200


@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize(
    "case", ["another_key", "another_users_id", "another_users_signed", "altered", "other_domain"]
)
def test_forgeries_are_rejected(
    client, database, analyst, analyst_headers, objects, release, kind, case
):
    path, table, id_field = ROUTES[kind]
    build = _builder(kind, objects, release)
    other = database.create_user("analyst")
    body = {
        "another_key": lambda: build(analyst, signer=SigningKey.generate()),
        "another_users_id": lambda: build(analyst, analyst_id=other.user_id)
        | {"analyst_id": str(other.user_id)},
        "another_users_signed": lambda: build(other),
        # Signed with another value, sent with the default one.
        "altered": lambda: build(analyst, **ALTERED[kind]) | DEFAULTS[kind],
        "other_domain": lambda: build(analyst, domain=CLASSIFICATION_SIGNATURE_DOMAIN),
    }[case]()
    response = _post(client, path, body, analyst_headers)
    assert response.status_code == 403, response.text
    assert _count(database, table, id_field, body[id_field]) == 0


def test_composition_signed_with_other_members_is_rejected(
    client, database, analyst, analyst_headers, objects
):
    members = default_members(objects)
    body = composition_body(analyst, members, signed_members=members[:1])
    assert _post(client, "behavioural-compositions", body, analyst_headers).status_code == 403
    assert _count(database, "composition_member", "target_id", objects.function_id) == 0


@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize("role", ["viewer", "moderator"])
def test_only_analysts_write(client, database, objects, release, kind, role):
    user = database.create_user(role)
    path, _, _ = ROUTES[kind]
    body = _builder(kind, objects, release)(user)
    assert _post(client, path, body, bearer(login(client, user))).status_code == 403


# ---------------------------------------------------------------------------
# Validation, unknown and revoked targets
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "overrides",
    [
        {"purl": "openssl"},
        {"purl": "pkg:generic/has space"},
        {"name": " padded"},
        {"name": ""},
        {"component_kind": "x" * 65},
        {"namespace": ""},
    ],
)
def test_invalid_components(client, analyst, analyst_headers, overrides):
    body = component_body(analyst, **overrides)
    assert _post(client, "software-components", body, analyst_headers).status_code == 422


@pytest.mark.parametrize(
    "members",
    [
        [],
        [{"target_type": "source", "member_role": "x"}],
        [{"target_type": "binary", "member_role": "x", "sequence_number": -1}],
        [{"target_type": "binary", "member_role": "loader"}] * 2,
    ],
    ids=["none", "not_binary_or_function", "negative_sequence", "duplicate"],
)
def test_invalid_compositions(client, analyst, analyst_headers, objects, members):
    members = [
        {"target_id": objects.binary_id, "sequence_number": None} | m for m in members
    ]
    body = composition_body(analyst, members, signed_members=default_members(objects))
    assert _post(client, "behavioural-compositions", body, analyst_headers).status_code == 422


def test_too_many_members(client, analyst, analyst_headers, objects):
    members = [
        {"target_type": "binary", "target_id": objects.binary_id, "member_role": "r",
         "sequence_number": n}
        for n in range(501)
    ]
    body = composition_body(analyst, members, signed_members=default_members(objects))
    assert _post(client, "behavioural-compositions", body, analyst_headers).status_code in (413, 422)


def test_unknown_targets(client, database, analyst, analyst_headers, objects, release):
    _, release_id = release
    cases = [
        ("software-releases", release_body(analyst, uuid.uuid4())),
        ("binary-component-assertions", assertion_body(analyst, uuid.uuid4(), release_id)),
        ("binary-component-assertions", assertion_body(analyst, objects.binary_id, uuid.uuid4())),
        ("behavioural-compositions", composition_body(analyst, [
            {"target_type": "function", "target_id": uuid.uuid4(), "member_role": "x",
             "sequence_number": None},
        ])),
        ("binary-component-assertions", assertion_body(
            analyst, objects.binary_id, release_id, evidence_provenance_id=uuid.uuid4())),
    ]
    for path, body in cases:
        response = _post(client, path, body, analyst_headers)
        assert response.status_code == 422, (path, response.text)
    assert _count(database, "behavioural_composition", "submitted_by_analyst_id",
                  analyst.user_id) == 0


def test_nothing_new_on_revoked_rows(client, database, analyst, analyst_headers, objects, release):
    component_id, release_id = release

    def refused(path, body):
        response = _post(client, path, body, analyst_headers)
        assert response.status_code == 409 and "revoked" in response.json()["detail"], response.text

    database.revoke(component_id, "software_component")
    refused("software-releases", release_body(analyst, component_id))
    # Revoking the component also blocks assertions on its existing releases.
    refused("binary-component-assertions", assertion_body(analyst, objects.binary_id, release_id))

    database.revoke(objects.function_id, "function")
    refused("behavioural-compositions", composition_body(analyst, default_members(objects)))
    assert _count(database, "composition_member", "target_id", objects.binary_id) == 0

    read = client.get(f"/v1/software-components/{component_id}", headers=analyst_headers).json()
    assert read["revoked"] is True


def test_rows_are_immutable(client, database, analyst, analyst_headers, objects, release):
    component_id, _ = release
    with pytest.raises(psycopg.Error, match="immutable"):
        database.execute(
            "UPDATE catalogue.software_component SET name = 'x' WHERE component_id = %s",
            (component_id,),
        )


# ---------------------------------------------------------------------------
# The database keeps a composition's membership as signed
# ---------------------------------------------------------------------------


def _signed_composition(client, analyst, analyst_headers, objects) -> uuid.UUID:
    body = composition_body(analyst, default_members(objects))
    assert _post(client, "behavioural-compositions", body, analyst_headers).status_code == 201
    return uuid.UUID(body["behavioural_composition_id"])


def test_api_login_cannot_add_a_member_later(client, database, analyst, analyst_headers, objects):
    """What a compromised API could try: append to a committed composition."""
    composition_id = _signed_composition(client, analyst, analyst_headers, objects)
    with psycopg.connect(database.app_url, autocommit=True) as conn:
        with pytest.raises(psycopg.errors.IntegrityConstraintViolation, match="all 2 members"):
            conn.execute(
                "INSERT INTO catalogue.composition_member"
                " (behavioural_composition_id, target_type, target_id, member_role)"
                " VALUES (%s, 'binary', %s, 'extra')",
                (composition_id, objects.binary_id),
            )
    assert _count(database, "composition_member", "behavioural_composition_id", composition_id) == 2


def test_composition_without_all_its_members_cannot_commit(database, analyst, objects):
    composition_id = uuid.uuid4()
    with psycopg.connect(database.app_url) as conn:
        conn.execute(
            "INSERT INTO catalogue.behavioural_composition (behavioural_composition_id, name,"
            " member_count, submitted_by_analyst_id, signature) VALUES (%s, 'short', 2, %s, %s)",
            (composition_id, analyst.user_id, b"\x01" * 64),
        )
        conn.execute(
            "INSERT INTO catalogue.composition_member"
            " (behavioural_composition_id, target_type, target_id, member_role)"
            " VALUES (%s, 'binary', %s, 'only')",
            (composition_id, objects.binary_id),
        )
        with pytest.raises(psycopg.errors.IntegrityConstraintViolation, match="1 of its 2"):
            conn.commit()
    assert _count(database, "behavioural_composition", "behavioural_composition_id",
                  composition_id) == 0


# ---------------------------------------------------------------------------
# Rust client (relic-sign-challenge) and relic-verify
# ---------------------------------------------------------------------------


def _cli(*args: str) -> dict:
    result = subprocess.run([str(SIGNER), *args], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


@pytest.mark.skipif(not (SIGNER.exists() and VERIFY.exists()),
                    reason="build with: cargo build -p relic-ingest -p relic-verify")
def test_rust_client_builds_the_model_and_relic_verify_agrees(
    client, database, objects, tmp_path: Path
):
    analyst_id, key = _ssh_user(database, tmp_path, "analyst_ed25519", "analyst")
    headers = bearer(_login_with_cli(client, analyst_id, key, tmp_path))
    common = ("--analyst-id", str(analyst_id), "--key", str(key))

    def post(path: str, body: dict) -> dict:
        response = client.post(f"/v1/{path}", json=body, headers=headers)
        assert response.status_code == 201, response.text
        return response.json()

    component = post("software-components", _cli(
        "create-component", *common, "--name", "zlib", "--kind", "library",
        "--purl", "pkg:generic/zlib",
    ))
    release = post("software-releases", _cli(
        "create-release", *common, "--component-id", component["component_id"],
        "--version", "1.3.1", "--source-id", str(objects.source_id),
    ))
    assertion = post("binary-component-assertions", _cli(
        "assert-component", *common, "--binary-id", str(objects.binary_id),
        "--software-release-id", release["software_release_id"],
        "--relationship", "statically_contains", "--basis", "detected", "--confidence", "0.9000",
    ))
    members = tmp_path / "members.json"
    members.write_text(json.dumps([
        {"target_type": "function", "target_id": str(objects.function_id),
         "member_role": "inflate", "sequence_number": 1},
        {"target_type": "binary", "target_id": str(objects.binary_id), "member_role": "host"},
    ]))
    composition = post("behavioural-compositions", _cli(
        "compose", *common, "--name", "Embedded zlib", "--members", str(members),
    ))
    assert composition["member_count"] == 2

    duplicate = tmp_path / "duplicate.json"
    duplicate.write_text(json.dumps([{"target_type": "binary", "target_id": str(objects.binary_id),
                                      "member_role": "x"}] * 2))
    refused = subprocess.run(
        [str(SIGNER), "compose", *common, "--name", "x", "--members", str(duplicate)],
        capture_output=True, text=True,
    )
    assert refused.returncode != 0 and "distinct" in refused.stderr

    report = json.loads(subprocess.run(
        [str(VERIFY), "--database-url", database.auditor_url, "--json"],
        capture_output=True, text=True,
    ).stdout)
    failing = {f["id"] for f in report["failures"]}
    for row_id in (component["component_id"], release["software_release_id"],
                   assertion["binary_component_assertion_id"],
                   composition["behavioural_composition_id"]):
        assert row_id not in failing

    # A Moderator decides a revocation of the component, shown its details.
    other_id, other_key = _ssh_user(database, tmp_path, "other_ed25519", "analyst")
    moderator_id, moderator_key = _ssh_user(database, tmp_path, "moderator_ed25519", "moderator")
    request = _cli(
        "request-revocation", "--analyst-id", str(other_id), "--target-type", "software_component",
        "--target-id", component["component_id"], "--reason", "Duplicate", "--key", str(other_key),
    )
    other_headers = bearer(_login_with_cli(client, other_id, other_key, tmp_path))
    assert client.post("/v1/revocations", json=request, headers=other_headers).status_code == 201
    moderator_headers = bearer(_login_with_cli(client, moderator_id, moderator_key, tmp_path))

    def saved(name: str, path: str) -> str:
        file = tmp_path / name
        file.write_text(client.get(path, headers=moderator_headers).text)
        return str(file)

    revocation = saved("revocation.json", f"/v1/revocations/{request['revocation_id']}")
    requester = saved("requester.json", f"/v1/users/{other_id}")
    target = saved("target.json", f"/v1/software-components/{component['component_id']}")
    decide = ("decide-revocation", "--request", revocation, "--requester", requester,
              "--moderator-id", str(moderator_id), "--decision", "approved",
              "--key", str(moderator_key))
    missing = subprocess.run([str(SIGNER), *decide], capture_output=True, text=True)
    assert missing.returncode != 0 and "--target" in missing.stderr
    result = subprocess.run([str(SIGNER), *decide, "--target", target],
                            capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert '"purl": "pkg:generic/zlib"' in result.stderr
    decided = client.post(
        f"/v1/revocations/{request['revocation_id']}/decision",
        json=json.loads(result.stdout), headers=moderator_headers,
    )
    assert decided.status_code == 200, decided.text
    read = client.get(f"/v1/software-components/{component['component_id']}", headers=headers)
    assert read.json()["revoked"] is True


# ---------------------------------------------------------------------------
# What depends on a revoked row, revoked evidence, ordered positions
# ---------------------------------------------------------------------------


def test_ancestor_revoked_marks_rows_built_on_a_revoked_row(
    client, database, analyst, analyst_headers, objects, release
):
    component_id, release_id = release
    assertion = _post(
        client, "binary-component-assertions",
        assertion_body(analyst, objects.binary_id, release_id), analyst_headers,
    ).json()
    composition = _post(
        client, "behavioural-compositions",
        composition_body(analyst, default_members(objects)), analyst_headers,
    ).json()
    assert (assertion["ancestor_revoked"], composition["ancestor_revoked"]) == (False, False)

    def read(path: str, key: str) -> dict:
        return client.get(f"/v1/{path}/{key}", headers=analyst_headers).json()

    database.revoke(component_id, "software_component")
    for path, key in (("software-releases", release_id),
                      ("binary-component-assertions",
                       assertion["binary_component_assertion_id"])):
        row = read(path, key)
        assert (row["revoked"], row["ancestor_revoked"]) == (False, True), path
    listed = client.get(
        f"/v1/binary-component-assertions?binary_id={objects.binary_id}", headers=analyst_headers
    ).json()
    assert [row["ancestor_revoked"] for row in listed] == [True]

    database.revoke(objects.function_id, "function")
    row = read("behavioural-compositions", composition["behavioural_composition_id"])
    assert (row["revoked"], row["ancestor_revoked"]) == (False, True)


def _provenance(database, objects: Objects) -> uuid.UUID:
    provenance_id = uuid.uuid4()
    owner = database.create_user("analyst")
    database.execute(
        "INSERT INTO catalogue.provenance (provenance_id, binary_id, schema_name, schema_version,"
        " object_data, sha256, md5, submitted_by_user_id, signature, source_id)"
        " VALUES (%s, %s, 'ocsf', '1.3.0', '{\"class_uid\": 1}', %s, %s, %s, %s, %s)",
        (provenance_id, objects.binary_id, uuid.uuid4().hex * 2, uuid.uuid4().hex,
         owner.user_id, b"\x11" * 64, objects.source_id),
    )
    return provenance_id


def test_revoked_evidence_is_refused(client, database, analyst, analyst_headers, objects, release):
    from .test_claims_api import license_body

    _, release_id = release
    evidence = _provenance(database, objects)
    accepted = _post(
        client, "binary-component-assertions",
        assertion_body(analyst, objects.binary_id, release_id, evidence_provenance_id=evidence),
        analyst_headers,
    ).json()
    assert accepted["ancestor_revoked"] is False

    database.revoke(evidence, "provenance")
    for path, body in (
        ("license-assertions",
         license_body(analyst, objects.binary_id, evidence_provenance_id=evidence)),
        ("binary-component-assertions",
         assertion_body(analyst, objects.binary_id, release_id, evidence_provenance_id=evidence)),
        ("behavioural-compositions",
         composition_body(analyst, default_members(objects), evidence_provenance_id=evidence)),
    ):
        response = _post(client, path, body, analyst_headers)
        assert response.status_code == 409, (path, response.text)
        assert "Evidence provenance" in response.json()["detail"], path
    stored = client.get(
        f"/v1/binary-component-assertions/{accepted['binary_component_assertion_id']}",
        headers=analyst_headers,
    ).json()
    assert stored["ancestor_revoked"] is True


def test_each_position_is_used_once(client, database, analyst, analyst_headers, objects):
    members = default_members(objects)
    members[1]["sequence_number"] = members[0]["sequence_number"]
    body = composition_body(analyst, members)
    response = _post(client, "behavioural-compositions", body, analyst_headers)
    assert response.status_code == 422 and "sequence_number" in response.text

    # The database enforces it too, whatever the API checks.
    composition_id = uuid.uuid4()
    with psycopg.connect(database.app_url) as conn:
        conn.execute(
            "INSERT INTO catalogue.behavioural_composition (behavioural_composition_id, name,"
            " member_count, submitted_by_analyst_id, signature) VALUES (%s, 'x', 2, %s, %s)",
            (composition_id, analyst.user_id, b"\x01" * 64),
        )
        insert = ("INSERT INTO catalogue.composition_member (behavioural_composition_id,"
                  " target_type, target_id, member_role, sequence_number)"
                  " VALUES (%s, %s, %s, %s, 0)")
        conn.execute(insert, (composition_id, "binary", objects.binary_id, "a"))
        with pytest.raises(psycopg.errors.UniqueViolation, match="composition_member_sequence_idx"):
            conn.execute(insert, (composition_id, "function", objects.function_id, "b"))
        conn.rollback()


def test_member_filter_pages_in_order(client, database, analyst, analyst_headers, objects):
    """One member in several compositions, under several roles in one of them."""
    members = default_members(objects)
    twice = members + [{"target_type": "binary", "target_id": objects.binary_id,
                        "member_role": "dropper", "sequence_number": None}]
    created = sorted(
        _post(client, "behavioural-compositions", composition_body(analyst, m),
              analyst_headers).json()["behavioural_composition_id"]
        for m in (members, twice, members[:1])
    )
    url = f"/v1/behavioural-compositions?member_type=binary&member_id={objects.binary_id}"
    first = client.get(url + "&limit=2", headers=analyst_headers).json()
    rest = client.get(url + f"&limit=2&after={first[-1]['behavioural_composition_id']}",
                      headers=analyst_headers).json()
    assert [r["behavioural_composition_id"] for r in first + rest] == created
