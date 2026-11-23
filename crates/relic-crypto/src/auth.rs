//! Canonical signed user messages: login, registration proof-of-possession,
//! registration decisions, revocation requests and decisions, flags and flag
//! responses, licence assertions, classifications, software components and
//! releases, binary-component assertions and behavioural compositions.
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

/// Record domain for an Analyst's licence assertion.
pub const LICENSE_ASSERTION_RECORD_DOMAIN: &[u8] = b"RELIC:license-assertion:v1";
/// Signature domain for an Analyst's licence assertion.
pub const LICENSE_ASSERTION_SIGNATURE_DOMAIN: &[u8] = b"RELIC:license-assertion-signature:v1";
/// Record domain for an Analyst's classification.
pub const CLASSIFICATION_RECORD_DOMAIN: &[u8] = b"RELIC:classification:v1";
/// Signature domain for an Analyst's classification.
pub const CLASSIFICATION_SIGNATURE_DOMAIN: &[u8] = b"RELIC:classification-signature:v1";
/// Record domain for a software component identity.
pub const SOFTWARE_COMPONENT_RECORD_DOMAIN: &[u8] = b"RELIC:software-component:v1";
/// Signature domain for a software component identity.
pub const SOFTWARE_COMPONENT_SIGNATURE_DOMAIN: &[u8] = b"RELIC:software-component-signature:v1";
/// Record domain for a software release identity.
pub const SOFTWARE_RELEASE_RECORD_DOMAIN: &[u8] = b"RELIC:software-release:v1";
/// Signature domain for a software release identity.
pub const SOFTWARE_RELEASE_SIGNATURE_DOMAIN: &[u8] = b"RELIC:software-release-signature:v1";
/// Record domain for a binary-component assertion.
pub const BINARY_COMPONENT_ASSERTION_RECORD_DOMAIN: &[u8] = b"RELIC:binary-component-assertion:v1";
/// Signature domain for a binary-component assertion.
pub const BINARY_COMPONENT_ASSERTION_SIGNATURE_DOMAIN: &[u8] =
    b"RELIC:binary-component-assertion-signature:v1";
/// Record domain for a behavioural composition, members included.
pub const BEHAVIOURAL_COMPOSITION_RECORD_DOMAIN: &[u8] = b"RELIC:behavioural-composition:v1";
/// Signature domain for a behavioural composition.
pub const BEHAVIOURAL_COMPOSITION_SIGNATURE_DOMAIN: &[u8] =
    b"RELIC:behavioural-composition-signature:v1";
/// Domain of one member's encoding inside a composition record (never signed alone).
pub const COMPOSITION_MEMBER_DOMAIN: &[u8] = b"RELIC:composition-member:v1";

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

/// Encode optional bytes (e.g. a UUID) as `0x00` (absent) or `0x01 || bytes`.
#[must_use]
pub fn encode_optional_bytes(value: Option<&[u8]>) -> Vec<u8> {
    value.map_or_else(|| vec![0], |value| [&[1][..], value].concat())
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

/// An Analyst's claim that one source or binary carries an SPDX licence.
///
/// The Analyst chooses `license_assertion_id` (a fresh UUID); it is the
/// stored row's primary key, so a signed assertion is admitted at most once.
/// Assertions are immutable: a correction is a new assertion plus a
/// revocation of the old one.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LicenseAssertion<'a> {
    pub license_assertion_id: &'a [u8; 16],
    pub analyst_id: &'a [u8; 16],
    /// `source` or `binary`.
    pub target_type: &'a str,
    pub target_id: &'a [u8; 16],
    /// An SPDX license expression, exactly as submitted.
    pub spdx_expression: &'a str,
    /// `declared`, `detected`, `inferred` or `analyst_assessed`.
    pub basis: &'a str,
    /// Exactly four decimals between `0.0000` and `1.0000`, as stored.
    pub confidence: Option<&'a str>,
    pub evidence_provenance_id: Option<&'a [u8; 16]>,
}

/// Canonical bytes of a licence assertion.
#[must_use]
pub fn license_assertion_record(assertion: &LicenseAssertion<'_>) -> Vec<u8> {
    encode_fields(
        LICENSE_ASSERTION_RECORD_DOMAIN,
        &[
            assertion.license_assertion_id,
            assertion.analyst_id,
            assertion.target_type.as_bytes(),
            assertion.target_id,
            assertion.spdx_expression.as_bytes(),
            assertion.basis.as_bytes(),
            &encode_optional(assertion.confidence),
            &encode_optional_bytes(assertion.evidence_provenance_id.map(|id| &id[..])),
        ],
    )
}

/// Digest signed under [`LICENSE_ASSERTION_SIGNATURE_DOMAIN`].
#[must_use]
pub fn license_assertion_digest(assertion: &LicenseAssertion<'_>) -> Digest32 {
    sha256(&license_assertion_record(assertion))
}

/// An Analyst's label on one binary, function or behavioural composition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Classification<'a> {
    pub classification_id: &'a [u8; 16],
    pub analyst_id: &'a [u8; 16],
    /// `binary`, `function` or `behavioural_composition`.
    pub target_type: &'a str,
    pub target_id: &'a [u8; 16],
    pub label: &'a str,
    /// Exactly four decimals between `0.0000` and `1.0000`, as stored.
    pub confidence: Option<&'a str>,
    pub misp_universe: Option<&'a str>,
    pub misp_uuid: Option<&'a [u8; 16]>,
    /// The evidence JSON text exactly as submitted (and stored verbatim).
    pub evidence_json: Option<&'a str>,
}

/// Canonical bytes of a classification.
#[must_use]
pub fn classification_record(classification: &Classification<'_>) -> Vec<u8> {
    encode_fields(
        CLASSIFICATION_RECORD_DOMAIN,
        &[
            classification.classification_id,
            classification.analyst_id,
            classification.target_type.as_bytes(),
            classification.target_id,
            classification.label.as_bytes(),
            &encode_optional(classification.confidence),
            &encode_optional(classification.misp_universe),
            &encode_optional_bytes(classification.misp_uuid.map(|id| &id[..])),
            &encode_optional(classification.evidence_json),
        ],
    )
}

/// Digest signed under [`CLASSIFICATION_SIGNATURE_DOMAIN`].
#[must_use]
pub fn classification_digest(classification: &Classification<'_>) -> Digest32 {
    sha256(&classification_record(classification))
}

/// An Analyst's normalised software identity (a library, application, runtime...).
///
/// It is not itself a claim that any binary contains the component.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SoftwareComponent<'a> {
    pub component_id: &'a [u8; 16],
    pub analyst_id: &'a [u8; 16],
    pub name: &'a str,
    pub component_kind: &'a str,
    pub namespace: Option<&'a str>,
    /// A package URL, exactly as submitted.
    pub purl: Option<&'a str>,
}

/// Canonical bytes of a software component.
#[must_use]
pub fn software_component_record(component: &SoftwareComponent<'_>) -> Vec<u8> {
    encode_fields(
        SOFTWARE_COMPONENT_RECORD_DOMAIN,
        &[
            component.component_id,
            component.analyst_id,
            component.name.as_bytes(),
            component.component_kind.as_bytes(),
            &encode_optional(component.namespace),
            &encode_optional(component.purl),
        ],
    )
}

/// Digest signed under [`SOFTWARE_COMPONENT_SIGNATURE_DOMAIN`].
#[must_use]
pub fn software_component_digest(component: &SoftwareComponent<'_>) -> Digest32 {
    sha256(&software_component_record(component))
}

/// A release (version) of a software component; version and source may be unknown.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SoftwareRelease<'a> {
    pub software_release_id: &'a [u8; 16],
    pub analyst_id: &'a [u8; 16],
    pub component_id: &'a [u8; 16],
    pub version: Option<&'a str>,
    pub source_id: Option<&'a [u8; 16]>,
}

/// Canonical bytes of a software release.
#[must_use]
pub fn software_release_record(release: &SoftwareRelease<'_>) -> Vec<u8> {
    encode_fields(
        SOFTWARE_RELEASE_RECORD_DOMAIN,
        &[
            release.software_release_id,
            release.analyst_id,
            release.component_id,
            &encode_optional(release.version),
            &encode_optional_bytes(release.source_id.map(|id| &id[..])),
        ],
    )
}

/// Digest signed under [`SOFTWARE_RELEASE_SIGNATURE_DOMAIN`].
#[must_use]
pub fn software_release_digest(release: &SoftwareRelease<'_>) -> Digest32 {
    sha256(&software_release_record(release))
}

/// An Analyst's claim that a binary relates to a software release.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BinaryComponentAssertion<'a> {
    pub binary_component_assertion_id: &'a [u8; 16],
    pub analyst_id: &'a [u8; 16],
    pub binary_id: &'a [u8; 16],
    pub software_release_id: &'a [u8; 16],
    /// `build_of`, `statically_contains`, `dynamically_links`, `derived_from` or `other`.
    pub relationship: &'a str,
    /// `declared`, `detected`, `inferred` or `analyst_assessed`.
    pub basis: &'a str,
    /// Exactly four decimals between `0.0000` and `1.0000`, as stored.
    pub confidence: Option<&'a str>,
    pub evidence_provenance_id: Option<&'a [u8; 16]>,
}

/// Canonical bytes of a binary-component assertion.
#[must_use]
pub fn binary_component_assertion_record(assertion: &BinaryComponentAssertion<'_>) -> Vec<u8> {
    encode_fields(
        BINARY_COMPONENT_ASSERTION_RECORD_DOMAIN,
        &[
            assertion.binary_component_assertion_id,
            assertion.analyst_id,
            assertion.binary_id,
            assertion.software_release_id,
            assertion.relationship.as_bytes(),
            assertion.basis.as_bytes(),
            &encode_optional(assertion.confidence),
            &encode_optional_bytes(assertion.evidence_provenance_id.map(|id| &id[..])),
        ],
    )
}

/// Digest signed under [`BINARY_COMPONENT_ASSERTION_SIGNATURE_DOMAIN`].
#[must_use]
pub fn binary_component_assertion_digest(assertion: &BinaryComponentAssertion<'_>) -> Digest32 {
    sha256(&binary_component_assertion_record(assertion))
}

/// One member of a behavioural composition: an exact binary or function.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompositionMember<'a> {
    /// `binary` or `function`.
    pub target_type: &'a str,
    pub target_id: &'a [u8; 16],
    pub member_role: &'a str,
    /// Position in the sequence, or `None` when no order is asserted.
    pub sequence_number: Option<u32>,
}

/// Canonical bytes of one member (a part of the composition record).
#[must_use]
pub fn composition_member_record(member: &CompositionMember<'_>) -> Vec<u8> {
    let sequence = member.sequence_number.map(u32::to_be_bytes);
    encode_fields(
        COMPOSITION_MEMBER_DOMAIN,
        &[
            member.target_type.as_bytes(),
            member.target_id,
            member.member_role.as_bytes(),
            &encode_optional_bytes(sequence.as_ref().map(|bytes| &bytes[..])),
        ],
    )
}

/// An Analyst-defined set or sequence of binaries and functions whose combined
/// behaviour can be classified. The signature covers every member, so the
/// membership cannot change after signing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BehaviouralComposition<'a> {
    pub behavioural_composition_id: &'a [u8; 16],
    pub analyst_id: &'a [u8; 16],
    pub name: &'a str,
    pub description: Option<&'a str>,
    pub evidence_provenance_id: Option<&'a [u8; 16]>,
    /// In any order: the record sorts them.
    pub members: &'a [CompositionMember<'a>],
}

/// Canonical bytes of a behavioural composition.
///
/// The members field is each member's [`composition_member_record`], sorted
/// bytewise and each prefixed with its length as a big-endian `u64`, so the
/// record does not depend on the order in which members were listed.
///
/// # Panics
///
/// Only if a member's length does not fit in a `u64`, which cannot happen.
#[must_use]
pub fn behavioural_composition_record(composition: &BehaviouralComposition<'_>) -> Vec<u8> {
    let mut members: Vec<Vec<u8>> = composition
        .members
        .iter()
        .map(composition_member_record)
        .collect();
    members.sort();
    let mut encoded_members = Vec::new();
    for member in &members {
        let length = u64::try_from(member.len()).expect("member length exceeds u64");
        encoded_members.extend_from_slice(&length.to_be_bytes());
        encoded_members.extend_from_slice(member);
    }
    encode_fields(
        BEHAVIOURAL_COMPOSITION_RECORD_DOMAIN,
        &[
            composition.behavioural_composition_id,
            composition.analyst_id,
            composition.name.as_bytes(),
            &encode_optional(composition.description),
            &encode_optional_bytes(composition.evidence_provenance_id.map(|id| &id[..])),
            &encoded_members,
        ],
    )
}

/// Digest signed under [`BEHAVIOURAL_COMPOSITION_SIGNATURE_DOMAIN`].
#[must_use]
pub fn behavioural_composition_digest(composition: &BehaviouralComposition<'_>) -> Digest32 {
    sha256(&behavioural_composition_record(composition))
}
