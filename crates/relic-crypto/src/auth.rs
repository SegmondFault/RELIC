//! Canonical authentication messages: login and registration proof-of-possession.
//!
//! Both messages are signed over a single-use server challenge. The API
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

/// A Moderator's verdict on a pending registration request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegistrationDecision {
    Approved,
    Rejected,
}

impl RegistrationDecision {
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
#[must_use]
pub fn login_record(challenge: &AuthChallenge, user_id: &[u8; 16]) -> Vec<u8> {
    encode_fields(
        LOGIN_RECORD_DOMAIN,
        &[
            &challenge.challenge_id,
            &challenge.nonce,
            challenge.audience.as_bytes(),
            &challenge.expires_at_unix_micros.to_be_bytes(),
            user_id,
        ],
    )
}

/// Digest signed under [`LOGIN_SIGNATURE_DOMAIN`].
#[must_use]
pub fn login_digest(challenge: &AuthChallenge, user_id: &[u8; 16]) -> Digest32 {
    sha256(&login_record(challenge, user_id))
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
