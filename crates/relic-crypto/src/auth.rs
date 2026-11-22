//! Canonical account messages: login, registration proof-of-possession,
//! registration decisions, revocation requests and decisions, and flags and
//! flag responses.
//!
//! Login and registration proofs are signed over a single-use server
//! challenge. Decisions, revocation requests, flags and flag responses are
//! single-use because the identifier they sign is unique and stored. The API
//! (Python) re-implements these exact encodings and is pinned to the test
//! vectors in `tests/vectors/auth-v1.json`; changing any field, order,
//! encoding or domain requires a new version and new vectors.

use crate::{Digest32, encode_fields, sha256};

/// Record domain for a login proof.
pub const LOGIN_RECORD_DOMAIN: &[u8] = b"RELIC:login-challenge:v1";
/// Signature domain for a login proof.
pub const LOGIN_SIGNATURE_DOMAIN: &[u8] = b"RELIC:login-signature:v1";
/// Record domain for a registration proof-of-possession.
pub const REGISTRATION_RECORD_DOMAIN: &[u8] = b"RELIC:registration-request:v1";
/// Signature domain for a registration proof-of-possession.
pub const REGISTRATION_SIGNATURE_DOMAIN: &[u8] = b"RELIC:registration-proof-signature:v1";
/// Record domain for a Moderator's decision on a registration request.
pub const REGISTRATION_DECISION_RECORD_DOMAIN: &[u8] = b"RELIC:registration-decision:v1";
/// Signature domain for a Moderator's decision on a registration request.
pub const REGISTRATION_DECISION_SIGNATURE_DOMAIN: &[u8] =
    b"RELIC:registration-decision-signature:v1";

/// Record domain for an Analyst's revocation request.
pub const REVOCATION_REQUEST_RECORD_DOMAIN: &[u8] = b"RELIC:revocation-request:v1";
/// Signature domain for an Analyst's revocation request.
pub const REVOCATION_REQUEST_SIGNATURE_DOMAIN: &[u8] = b"RELIC:revocation-request-signature:v1";
/// Record domain for a Moderator's decision on a revocation request.
pub const REVOCATION_DECISION_RECORD_DOMAIN: &[u8] = b"RELIC:revocation-decision:v1";
/// Signature domain for a Moderator's decision on a revocation request.
pub const REVOCATION_DECISION_SIGNATURE_DOMAIN: &[u8] = b"RELIC:revocation-decision-signature:v1";

/// Record domain for a Viewer's flag on a catalogue object, account or flag.
pub const FLAG_RECORD_DOMAIN: &[u8] = b"RELIC:flag:v1";
/// Signature domain for a Viewer's flag.
pub const FLAG_SIGNATURE_DOMAIN: &[u8] = b"RELIC:flag-signature:v1";
/// Record domain for an Analyst's response to a flag.
pub const FLAG_RESPONSE_RECORD_DOMAIN: &[u8] = b"RELIC:flag-response:v1";
/// Signature domain for an Analyst's response to a flag.
pub const FLAG_RESPONSE_SIGNATURE_DOMAIN: &[u8] = b"RELIC:flag-response-signature:v1";

/// A Moderator's verdict on a pending registration or revocation request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Decision {
    Approved,
    Rejected,
}

/// Verdict on a registration request.
pub type RegistrationDecision = Decision;
/// Verdict on a revocation request.
pub type RevocationDecision = Decision;

impl Decision {
    /// The canonical (and database enum) spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Approved => "approved",
            Self::Rejected => "rejected",
        }
    }
}

/// A server-issued, single-use challenge exactly as returned by the API.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthChallenge {
    /// Challenge UUID bytes (RFC 4122 byte order).
    pub challenge_id: [u8; 16],
    /// 32 random bytes chosen by the server.
    pub nonce: [u8; 32],
    /// Origin of the RELIC deployment, e.g. `https://relic.example.org`.
    pub audience: String,
    /// Expiry in Unix microseconds, as issued by the server.
    pub expires_at_unix_micros: i64,
}

/// Account details bound into a registration proof.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegistrationDetails<'a> {
    /// The applicant's own Ed25519 public key.
    pub public_key: &'a [u8; 32],
    /// `viewer`, `analyst` or `moderator`.
    pub requested_role: &'a str,
    pub name: &'a str,
    pub organisation: Option<&'a str>,
    pub email: &'a str,
}

/// Encode an optional UTF-8 field as `0x00` (absent) or `0x01 || bytes`.
#[must_use]
pub fn encode_optional(value: Option<&str>) -> Vec<u8> {
    value.map_or_else(
        || vec![0],
        |value| {
            let mut encoded = Vec::with_capacity(value.len() + 1);
            encoded.push(1);
            encoded.extend_from_slice(value.as_bytes());
            encoded
        },
    )
}

/// Canonical login record bytes.
///
/// The client names itself by its Ed25519 public key; public keys are unique
/// across all accounts, so the server resolves the account after verifying
/// the signature with exactly this key.
#[must_use]
pub fn login_record(challenge: &AuthChallenge, public_key: &[u8; 32]) -> Vec<u8> {
    encode_fields(
        LOGIN_RECORD_DOMAIN,
        &[
            &challenge.challenge_id,
            &challenge.nonce,
            challenge.audience.as_bytes(),
            &challenge.expires_at_unix_micros.to_be_bytes(),
            public_key,
        ],
    )
}

/// Digest signed under [`LOGIN_SIGNATURE_DOMAIN`].
#[must_use]
pub fn login_digest(challenge: &AuthChallenge, public_key: &[u8; 32]) -> Digest32 {
    sha256(&login_record(challenge, public_key))
}

/// Canonical registration record bytes.
#[must_use]
pub fn registration_record(
    challenge: &AuthChallenge,
    details: &RegistrationDetails<'_>,
) -> Vec<u8> {
    let organisation = encode_optional(details.organisation);
    encode_fields(
        REGISTRATION_RECORD_DOMAIN,
        &[
            &challenge.challenge_id,
            &challenge.nonce,
            challenge.audience.as_bytes(),
            &challenge.expires_at_unix_micros.to_be_bytes(),
            details.public_key,
            details.requested_role.as_bytes(),
            details.name.as_bytes(),
            &organisation,
            details.email.as_bytes(),
        ],
    )
}

/// Digest signed under [`REGISTRATION_SIGNATURE_DOMAIN`].
#[must_use]
pub fn registration_digest(
    challenge: &AuthChallenge,
    details: &RegistrationDetails<'_>,
) -> Digest32 {
    sha256(&registration_record(challenge, details))
}

/// Canonical bytes of a Moderator's registration decision.
///
/// Binds the request identifier, every detail the Moderator reviewed, the
/// deciding Moderator and the verdict, so the stored signature can be checked
/// later from the `registration_request` row alone.
#[must_use]
pub fn registration_decision_record(
    registration_request_id: &[u8; 16],
    details: &RegistrationDetails<'_>,
    moderator_id: &[u8; 16],
    decision: RegistrationDecision,
) -> Vec<u8> {
    let organisation = encode_optional(details.organisation);
    encode_fields(
        REGISTRATION_DECISION_RECORD_DOMAIN,
        &[
            registration_request_id,
            details.public_key,
            details.requested_role.as_bytes(),
            details.name.as_bytes(),
            &organisation,
            details.email.as_bytes(),
            moderator_id,
            decision.as_str().as_bytes(),
        ],
    )
}

/// Digest signed under [`REGISTRATION_DECISION_SIGNATURE_DOMAIN`].
#[must_use]
pub fn registration_decision_digest(
    registration_request_id: &[u8; 16],
    details: &RegistrationDetails<'_>,
    moderator_id: &[u8; 16],
    decision: RegistrationDecision,
) -> Digest32 {
    sha256(&registration_decision_record(
        registration_request_id,
        details,
        moderator_id,
        decision,
    ))
}

/// An Analyst's request to revoke one catalogue object or account.
///
/// The Analyst chooses `revocation_id` (a fresh UUID). It is the primary key
/// of the stored row, so a signed request can be admitted at most once.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RevocationRequest<'a> {
    pub revocation_id: &'a [u8; 16],
    /// The requesting Analyst's User ID.
    pub analyst_id: &'a [u8; 16],
    /// A `corpus_target_type` value, e.g. `user` or `fidbf`.
    pub target_type: &'a str,
    pub target_id: &'a [u8; 16],
    pub reason: &'a str,
}

fn revocation_request_fields<'a>(request: &RevocationRequest<'a>) -> [&'a [u8]; 5] {
    [
        request.revocation_id,
        request.analyst_id,
        request.target_type.as_bytes(),
        request.target_id,
        request.reason.as_bytes(),
    ]
}

/// Canonical bytes of an Analyst's revocation request.
#[must_use]
pub fn revocation_request_record(request: &RevocationRequest<'_>) -> Vec<u8> {
    encode_fields(
        REVOCATION_REQUEST_RECORD_DOMAIN,
        &revocation_request_fields(request),
    )
}

/// Digest signed under [`REVOCATION_REQUEST_SIGNATURE_DOMAIN`].
#[must_use]
pub fn revocation_request_digest(request: &RevocationRequest<'_>) -> Digest32 {
    sha256(&revocation_request_record(request))
}

/// Canonical bytes of a Moderator's revocation decision.
///
/// Binds every field of the request as stored, the deciding Moderator and
/// the verdict, so the stored signature can be checked later from the
/// `revocation` row alone.
#[must_use]
pub fn revocation_decision_record(
    request: &RevocationRequest<'_>,
    moderator_id: &[u8; 16],
    decision: RevocationDecision,
) -> Vec<u8> {
    let [revocation_id, analyst_id, target_type, target_id, reason] =
        revocation_request_fields(request);
    encode_fields(
        REVOCATION_DECISION_RECORD_DOMAIN,
        &[
            revocation_id,
            analyst_id,
            target_type,
            target_id,
            reason,
            moderator_id,
            decision.as_str().as_bytes(),
        ],
    )
}

/// Digest signed under [`REVOCATION_DECISION_SIGNATURE_DOMAIN`].
#[must_use]
pub fn revocation_decision_digest(
    request: &RevocationRequest<'_>,
    moderator_id: &[u8; 16],
    decision: RevocationDecision,
) -> Digest32 {
    sha256(&revocation_decision_record(request, moderator_id, decision))
}

/// A Viewer's flag on one catalogue object, account, flag or flag response.
///
/// The Viewer chooses `flag_id` (a fresh UUID). It is the primary key of the
/// stored row, so a signed flag can be admitted at most once.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Flag<'a> {
    pub flag_id: &'a [u8; 16],
    /// The flagging Viewer's User ID.
    pub viewer_id: &'a [u8; 16],
    /// A `corpus_target_type` value, e.g. `binary` or `user`.
    pub target_type: &'a str,
    pub target_id: &'a [u8; 16],
    pub note: &'a str,
}

fn flag_fields<'a>(flag: &Flag<'a>) -> [&'a [u8]; 5] {
    [
        flag.flag_id,
        flag.viewer_id,
        flag.target_type.as_bytes(),
        flag.target_id,
        flag.note.as_bytes(),
    ]
}

/// Canonical bytes of a Viewer's flag.
#[must_use]
pub fn flag_record(flag: &Flag<'_>) -> Vec<u8> {
    encode_fields(FLAG_RECORD_DOMAIN, &flag_fields(flag))
}

/// Digest signed under [`FLAG_SIGNATURE_DOMAIN`].
#[must_use]
pub fn flag_digest(flag: &Flag<'_>) -> Digest32 {
    sha256(&flag_record(flag))
}

/// Canonical bytes of an Analyst's response to a flag.
///
/// Binds the Analyst's chosen `flag_response_id`, every field of the flag as
/// stored, the responding Analyst and their note, so the response attests
/// exactly what was answered and can be checked from the two rows alone.
#[must_use]
pub fn flag_response_record(
    flag: &Flag<'_>,
    flag_response_id: &[u8; 16],
    analyst_id: &[u8; 16],
    note: &str,
) -> Vec<u8> {
    let [flag_id, viewer_id, target_type, target_id, flag_note] = flag_fields(flag);
    encode_fields(
        FLAG_RESPONSE_RECORD_DOMAIN,
        &[
            flag_response_id,
            flag_id,
            viewer_id,
            target_type,
            target_id,
            flag_note,
            analyst_id,
            note.as_bytes(),
        ],
    )
}

/// Digest signed under [`FLAG_RESPONSE_SIGNATURE_DOMAIN`].
#[must_use]
pub fn flag_response_digest(
    flag: &Flag<'_>,
    flag_response_id: &[u8; 16],
    analyst_id: &[u8; 16],
    note: &str,
) -> Digest32 {
    sha256(&flag_response_record(
        flag,
        flag_response_id,
        analyst_id,
        note,
    ))
}
