"""Canonical authentication messages and Ed25519 verification.

This is a deliberate, minimal port of ``crates/relic-crypto`` (``encode_fields``,
``signing_message`` and ``auth``). The Rust crate remains the source of truth:
``tests/test_crypto_vectors.py`` pins this module to the vectors the Rust test
suite generates, so any divergence fails CI on both sides.

Verification uses libsodium (PyNaCl), which, like ed25519-dalek's
``verify_strict``, rejects non-canonical signatures and small-order keys.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Sequence
from uuid import UUID

from nacl.exceptions import CryptoError
from nacl.signing import VerifyKey

LOGIN_RECORD_DOMAIN = b"RELIC:login-challenge:v1"
LOGIN_SIGNATURE_DOMAIN = b"RELIC:login-signature:v1"
REGISTRATION_RECORD_DOMAIN = b"RELIC:registration-request:v1"
REGISTRATION_SIGNATURE_DOMAIN = b"RELIC:registration-proof-signature:v1"
REGISTRATION_DECISION_RECORD_DOMAIN = b"RELIC:registration-decision:v1"
REGISTRATION_DECISION_SIGNATURE_DOMAIN = b"RELIC:registration-decision-signature:v1"
REVOCATION_REQUEST_RECORD_DOMAIN = b"RELIC:revocation-request:v1"
REVOCATION_REQUEST_SIGNATURE_DOMAIN = b"RELIC:revocation-request-signature:v1"
REVOCATION_DECISION_RECORD_DOMAIN = b"RELIC:revocation-decision:v1"
REVOCATION_DECISION_SIGNATURE_DOMAIN = b"RELIC:revocation-decision-signature:v1"
FLAG_RECORD_DOMAIN = b"RELIC:flag:v1"
FLAG_SIGNATURE_DOMAIN = b"RELIC:flag-signature:v1"
FLAG_RESPONSE_RECORD_DOMAIN = b"RELIC:flag-response:v1"
FLAG_RESPONSE_SIGNATURE_DOMAIN = b"RELIC:flag-response-signature:v1"

PUBLIC_KEY_BYTES = 32
SIGNATURE_BYTES = 64
NONCE_BYTES = 32


def _framed(value: bytes) -> bytes:
    return len(value).to_bytes(8, "big") + value


def encode_fields(domain: bytes, fields: Sequence[bytes]) -> bytes:
    """``u64_be(len) || bytes`` for the domain and then every field."""
    return _framed(domain) + b"".join(_framed(field) for field in fields)


def encode_optional(value: str | None) -> bytes:
    return b"\x00" if value is None else b"\x01" + value.encode("utf-8")


def signing_message(domain: bytes, digest: bytes) -> bytes:
    return _framed(domain) + digest


@dataclass(frozen=True)
class Challenge:
    challenge_id: UUID
    nonce: bytes
    audience: str
    expires_at_unix_micros: int

    def _fields(self) -> list[bytes]:
        return [
            self.challenge_id.bytes,
            self.nonce,
            self.audience.encode("utf-8"),
            self.expires_at_unix_micros.to_bytes(8, "big", signed=True),
        ]


def login_record(challenge: Challenge, public_key: bytes) -> bytes:
    return encode_fields(LOGIN_RECORD_DOMAIN, [*challenge._fields(), public_key])


def registration_record(
    challenge: Challenge,
    *,
    public_key: bytes,
    requested_role: str,
    name: str,
    organisation: str | None,
    email: str,
) -> bytes:
    return encode_fields(
        REGISTRATION_RECORD_DOMAIN,
        [
            *challenge._fields(),
            public_key,
            requested_role.encode("utf-8"),
            name.encode("utf-8"),
            encode_optional(organisation),
            email.encode("utf-8"),
        ],
    )


def registration_decision_record(
    registration_request_id: UUID,
    *,
    public_key: bytes,
    requested_role: str,
    name: str,
    organisation: str | None,
    email: str,
    moderator_id: UUID,
    decision: str,
) -> bytes:
    """What a Moderator signs: the request, every reviewed detail, who decided and how."""
    if decision not in ("approved", "rejected"):
        raise ValueError("decision must be 'approved' or 'rejected'")
    return encode_fields(
        REGISTRATION_DECISION_RECORD_DOMAIN,
        [
            registration_request_id.bytes,
            public_key,
            requested_role.encode("utf-8"),
            name.encode("utf-8"),
            encode_optional(organisation),
            email.encode("utf-8"),
            moderator_id.bytes,
            decision.encode("utf-8"),
        ],
    )


@dataclass(frozen=True)
class RevocationRequest:
    """An Analyst's request to revoke one catalogue object or account."""

    revocation_id: UUID
    analyst_id: UUID
    target_type: str
    target_id: UUID
    reason: str

    def _fields(self) -> list[bytes]:
        return [
            self.revocation_id.bytes,
            self.analyst_id.bytes,
            self.target_type.encode("utf-8"),
            self.target_id.bytes,
            self.reason.encode("utf-8"),
        ]


def revocation_request_record(request: RevocationRequest) -> bytes:
    return encode_fields(REVOCATION_REQUEST_RECORD_DOMAIN, request._fields())


def revocation_decision_record(
    request: RevocationRequest, *, moderator_id: UUID, decision: str
) -> bytes:
    """What a Moderator signs: the stored request, who decided and how."""
    if decision not in ("approved", "rejected"):
        raise ValueError("decision must be 'approved' or 'rejected'")
    return encode_fields(
        REVOCATION_DECISION_RECORD_DOMAIN,
        [*request._fields(), moderator_id.bytes, decision.encode("utf-8")],
    )


@dataclass(frozen=True)
class Flag:
    """A Viewer's flag on one catalogue object, account, flag or flag response."""

    flag_id: UUID
    viewer_id: UUID
    target_type: str
    target_id: UUID
    note: str

    def _fields(self) -> list[bytes]:
        return [
            self.flag_id.bytes,
            self.viewer_id.bytes,
            self.target_type.encode("utf-8"),
            self.target_id.bytes,
            self.note.encode("utf-8"),
        ]


def flag_record(flag: Flag) -> bytes:
    return encode_fields(FLAG_RECORD_DOMAIN, flag._fields())


def flag_response_record(
    flag: Flag, *, flag_response_id: UUID, analyst_id: UUID, note: str
) -> bytes:
    """What an Analyst signs: their response ID, the flag as stored, who responds and the note."""
    return encode_fields(
        FLAG_RESPONSE_RECORD_DOMAIN,
        [
            flag_response_id.bytes,
            *flag._fields(),
            analyst_id.bytes,
            note.encode("utf-8"),
        ],
    )


def verify(public_key: bytes, signature_domain: bytes, record: bytes, signature: bytes) -> bool:
    """Strictly verify a domain-separated signature over ``SHA-256(record)``."""
    if len(public_key) != PUBLIC_KEY_BYTES or len(signature) != SIGNATURE_BYTES:
        return False
    digest = hashlib.sha256(record).digest()
    try:
        VerifyKey(public_key).verify(signing_message(signature_domain, digest), signature)
    except (CryptoError, ValueError, TypeError):
        return False
    return True
