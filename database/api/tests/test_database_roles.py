"""Database logins and what each may do.

relic_app is the API: it verifies user signatures and stores user-signed
rows, and never holds a system key. relic_worker is the integrity, MMR and
FIDBF-admission workers: the only login that appends system-signed evidence.
These tests pin both privilege sets, so widening either is a deliberate change.
"""

from __future__ import annotations

import psycopg
import pytest
from psycopg import errors

APPEND_ONLY_EVIDENCE = {"integrity", "mmr_checkpoint"}
NOT_CATALOGUE_DATA = {
    "user_private", "registration_request", "auth_challenge",
    "registration_approval", "revocation_approval",
}
WORKER_INSERTS = {
    "source", "batch", "binary_record", "fidbf", "function_record", "integrity", "mmr_checkpoint",
}


def _tables(database) -> set[str]:
    return {
        row[0]
        for row in database.execute(
            "SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace"
            " WHERE n.nspname = 'catalogue' AND c.relkind = 'r'"
        )
    }


def _granted(database, role: str, privilege: str) -> set[str]:
    return {
        row[0]
        for row in database.execute(
            "SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace"
            " WHERE n.nspname = 'catalogue' AND c.relkind = 'r'"
            "   AND has_table_privilege(%s, c.oid, %s)",
            (role, privilege),
        )
    }


API_INSERTS = {
    "auth_challenge", "registration_request", "registration_approval", "revocation",
    "revocation_approval", "flag", "flag_response",
}


def test_api_login_privileges(database):
    tables = _tables(database)
    assert _granted(database, "relic_app", "SELECT") == tables - {"user_private"}
    # Only what its routes write: accounts only via decide_registration(),
    # system evidence only via workers, corpus objects only once a route exists.
    assert _granted(database, "relic_app", "INSERT") == API_INSERTS
    assert _granted(database, "relic_app", "UPDATE") == {"auth_challenge", "revocation"}
    assert _granted(database, "relic_app", "DELETE") == set()


def test_worker_login_privileges(database):
    tables = _tables(database)
    assert _granted(database, "relic_worker", "SELECT") == tables - NOT_CATALOGUE_DATA
    assert _granted(database, "relic_worker", "INSERT") == WORKER_INSERTS
    assert _granted(database, "relic_worker", "UPDATE") == set()
    assert _granted(database, "relic_worker", "DELETE") == set()


def test_new_tables_are_not_writable_by_the_api(database):
    database.execute("CREATE TABLE catalogue.default_privilege_probe (x int)")
    try:
        writable = database.execute(
            "SELECT has_table_privilege('relic_app', 'catalogue.default_privilege_probe', 'INSERT'),"
            "       has_table_privilege('relic_app', 'catalogue.default_privilege_probe', 'UPDATE'),"
            "       has_table_privilege('relic_app', 'catalogue.default_privilege_probe', 'SELECT')"
        )[0]
    finally:
        database.execute("DROP TABLE catalogue.default_privilege_probe")
    assert writable == (False, False, True)


def test_auditor_login_only_reads(database):
    tables = _tables(database)
    assert _granted(database, "relic_auditor", "SELECT") == tables - {"user_private"}
    for privilege in ("INSERT", "UPDATE", "DELETE"):
        assert _granted(database, "relic_auditor", privilege) == set(), privilege
    with psycopg.connect(database.auditor_url) as conn:
        assert conn.execute("SHOW default_transaction_read_only").fetchone()[0] == "on"


def test_no_login_is_an_operator(database):
    for role in ("relic_app", "relic_worker", "relic_auditor"):
        member, superuser, createrole, bypassrls = database.execute(
            "SELECT pg_has_role(%s, 'relic_owner', 'USAGE'), rolsuper, rolcreaterole, rolbypassrls"
            " FROM pg_roles WHERE rolname = %s",
            (role, role),
        )[0]
        assert (member, superuser, createrole, bypassrls) == (False, False, False, False), role


@pytest.mark.parametrize("table", sorted(APPEND_ONLY_EVIDENCE))
def test_api_cannot_append_system_evidence(database, table):
    with psycopg.connect(database.app_url) as conn, pytest.raises(errors.InsufficientPrivilege):
        conn.execute(f"INSERT INTO catalogue.{table} DEFAULT VALUES")


def test_api_cannot_read_contact_details(database):
    with psycopg.connect(database.app_url) as conn, pytest.raises(errors.InsufficientPrivilege):
        conn.execute("SELECT email FROM catalogue.user_private")


def test_every_stored_signature_must_be_ed25519(database):
    """Each *signature bytea column has a CHECK on its own table requiring 64 bytes."""
    rows = database.execute(
        "SELECT col.table_name, col.column_name,"
        "       array_remove(array_agg(pg_get_constraintdef(con.oid)), NULL)"
        "  FROM information_schema.columns col"
        "  LEFT JOIN pg_constraint con"
        "    ON con.contype = 'c'"
        "   AND con.conrelid = format('catalogue.%%I', col.table_name)::regclass"
        " WHERE col.table_schema = 'catalogue' AND col.data_type = 'bytea'"
        "   AND col.column_name LIKE '%%signature'"
        " GROUP BY col.table_name, col.column_name"
    )
    assert len(rows) >= 15
    missing = [
        f"{table}.{column}"
        for table, column, checks in rows
        if not any(f"octet_length({column}) = 64" in check for check in checks)
    ]
    assert missing == []
