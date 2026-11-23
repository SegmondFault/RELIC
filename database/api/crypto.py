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
LICENSE_ASSERTION_RECORD_DOMAIN = b"RELIC:license-assertion:v1"
LICENSE_ASSERTION_SIGNATURE_DOMAIN = b"RELIC:license-assertion-signature:v1"
CLASSIFICATION_RECORD_DOMAIN = b"RELIC:classification:v1"
CLASSIFICATION_SIGNATURE_DOMAIN = b"RELIC:classification-signature:v1"
SOFTWARE_COMPONENT_RECORD_DOMAIN = b"RELIC:software-component:v1"
SOFTWARE_COMPONENT_SIGNATURE_DOMAIN = b"RELIC:software-component-signature:v1"
SOFTWARE_RELEASE_RECORD_DOMAIN = b"RELIC:software-release:v1"
SOFTWARE_RELEASE_SIGNATURE_DOMAIN = b"RELIC:software-release-signature:v1"
BINARY_COMPONENT_ASSERTION_RECORD_DOMAIN = b"RELIC:binary-component-assertion:v1"
BINARY_COMPONENT_ASSERTION_SIGNATURE_DOMAIN = b"RELIC:binary-component-assertion-signature:v1"
BEHAVIOURAL_COMPOSITION_RECORD_DOMAIN = b"RELIC:behavioural-composition:v1"
BEHAVIOURAL_COMPOSITION_SIGNATURE_DOMAIN = b"RELIC:behavioural-composition-signature:v1"
COMPOSITION_MEMBER_DOMAIN = b"RELIC:composition-member:v1"

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


def encode_optional_bytes(value: bytes | None) -> bytes:
    return b"\x00" if value is None else b"\x01" + value


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


@dataclass(frozen=True)
class LicenseAssertion:
    """An Analyst's SPDX licence claim on one source or binary."""

    license_assertion_id: UUID
    analyst_id: UUID
    target_type: str
    target_id: UUID
    spdx_expression: str
    basis: str
    confidence: str | None
    evidence_provenance_id: UUID | None


def license_assertion_record(assertion: LicenseAssertion) -> bytes:
    return encode_fields(
        LICENSE_ASSERTION_RECORD_DOMAIN,
        [
            assertion.license_assertion_id.bytes,
            assertion.analyst_id.bytes,
            assertion.target_type.encode("utf-8"),
            assertion.target_id.bytes,
            assertion.spdx_expression.encode("utf-8"),
            assertion.basis.encode("utf-8"),
            encode_optional(assertion.confidence),
            encode_optional_bytes(
                assertion.evidence_provenance_id.bytes if assertion.evidence_provenance_id else None
            ),
        ],
    )


@dataclass(frozen=True)
class Classification:
    """An Analyst's label on one binary, function or behavioural composition."""

    classification_id: UUID
    analyst_id: UUID
    target_type: str
    target_id: UUID
    label: str
    confidence: str | None
    misp_universe: str | None
    misp_uuid: UUID | None
    evidence_json: str | None


def classification_record(classification: Classification) -> bytes:
    return encode_fields(
        CLASSIFICATION_RECORD_DOMAIN,
        [
            classification.classification_id.bytes,
            classification.analyst_id.bytes,
            classification.target_type.encode("utf-8"),
            classification.target_id.bytes,
            classification.label.encode("utf-8"),
            encode_optional(classification.confidence),
            encode_optional(classification.misp_universe),
            encode_optional_bytes(classification.misp_uuid.bytes if classification.misp_uuid else None),
            encode_optional(classification.evidence_json),
        ],
    )



def _optional_id(value: UUID | None) -> bytes:
    return encode_optional_bytes(value.bytes if value else None)


@dataclass(frozen=True)
class SoftwareComponent:
    """An Analyst's normalised software identity (not a claim about any binary)."""

    component_id: UUID
    analyst_id: UUID
    name: str
    component_kind: str
    namespace: str | None
    purl: str | None


def software_component_record(component: SoftwareComponent) -> bytes:
    return encode_fields(
        SOFTWARE_COMPONENT_RECORD_DOMAIN,
        [
            component.component_id.bytes,
            component.analyst_id.bytes,
            component.name.encode("utf-8"),
            component.component_kind.encode("utf-8"),
            encode_optional(component.namespace),
            encode_optional(component.purl),
        ],
    )


@dataclass(frozen=True)
class SoftwareRelease:
    """A release of a software component; version and source may be unknown."""

    software_release_id: UUID
    analyst_id: UUID
    component_id: UUID
    version: str | None
    source_id: UUID | None


def software_release_record(release: SoftwareRelease) -> bytes:
    return encode_fields(
        SOFTWARE_RELEASE_RECORD_DOMAIN,
        [
            release.software_release_id.bytes,
            release.analyst_id.bytes,
            release.component_id.bytes,
            encode_optional(release.version),
            _optional_id(release.source_id),
        ],
    )


@dataclass(frozen=True)
class BinaryComponentAssertion:
    """An Analyst's claim that a binary relates to a software release."""

    binary_component_assertion_id: UUID
    analyst_id: UUID
    binary_id: UUID
    software_release_id: UUID
    relationship: str
    basis: str
    confidence: str | None
    evidence_provenance_id: UUID | None


def binary_component_assertion_record(assertion: BinaryComponentAssertion) -> bytes:
    return encode_fields(
        BINARY_COMPONENT_ASSERTION_RECORD_DOMAIN,
        [
            assertion.binary_component_assertion_id.bytes,
            assertion.analyst_id.bytes,
            assertion.binary_id.bytes,
            assertion.software_release_id.bytes,
            assertion.relationship.encode("utf-8"),
            assertion.basis.encode("utf-8"),
            encode_optional(assertion.confidence),
            _optional_id(assertion.evidence_provenance_id),
        ],
    )


@dataclass(frozen=True)
class CompositionMember:
    """One exact binary or function in a behavioural composition."""

    target_type: str
    target_id: UUID
    member_role: str
    sequence_number: int | None


def composition_member_record(member: CompositionMember) -> bytes:
    sequence = None if member.sequence_number is None else member.sequence_number.to_bytes(4, "big")
    return encode_fields(
        COMPOSITION_MEMBER_DOMAIN,
        [
            member.target_type.encode("utf-8"),
            member.target_id.bytes,
            member.member_role.encode("utf-8"),
            encode_optional_bytes(sequence),
        ],
    )


@dataclass(frozen=True)
class BehaviouralComposition:
    """A set or sequence of binaries and functions; the signature covers every member."""

    behavioural_composition_id: UUID
    analyst_id: UUID
    name: str
    description: str | None
    evidence_provenance_id: UUID | None
    members: tuple[CompositionMember, ...]


def behavioural_composition_record(composition: BehaviouralComposition) -> bytes:
    """Members are sorted by their encoded bytes, so their order does not matter."""
    members = sorted(composition_member_record(member) for member in composition.members)
    return encode_fields(
        BEHAVIOURAL_COMPOSITION_RECORD_DOMAIN,
        [
            composition.behavioural_composition_id.bytes,
            composition.analyst_id.bytes,
            composition.name.encode("utf-8"),
            encode_optional(composition.description),
            _optional_id(composition.evidence_provenance_id),
            b"".join(_framed(member) for member in members),
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
