//! Client-side check of the API's inclusion proof, the checkpoint it names
//! and, optionally, the integrity entry it is about.
//!
//! The server's word is never taken for what matters:
//!
//! * the checkpoint's signature is verified with a public key the caller
//!   supplies (pinned out of band), and the caller may also pin the system
//!   account and the exact checkpoint commitment;
//! * the proof must lead from the leaf to one of the peaks that signature
//!   covers; and
//! * the leaf is only as good as where it came from. Given the integrity entry
//!   (`GET /v1/integrity/{id}`), the chain hash is recomputed from the entry's
//!   own fields, so a verified proof is about that source and record hash.
//!   Without it, the leaf is merely what the server reported ([`LeafOrigin`]).
//!
//! Nothing here reads a database.

use chrono::DateTime;
use relic_crypto::Digest32;
use serde::Deserialize;
use thiserror::Error;
use uuid::Uuid;

use crate::{
    IntegrityEnvelope, Peak, SignedCheckpoint,
    proof::{InclusionProof, ProofError},
};

/// The checkpoint format whose hashing this crate implements.
const SUPPORTED_CHECKPOINT_FORMAT: u32 = 1;

/// The integrity-entry format whose chain hash [`IntegrityEnvelope`] computes.
const SUPPORTED_ENTRY_FORMAT: u32 = 1;

/// `GET /v1/integrity/{id}/proof`. Unknown envelope fields are ignored; the
/// proof itself is strictly parsed.
#[derive(Debug, Deserialize)]
struct ApiProof {
    integrity_id: i64,
    chain_hash: String,
    mmr_checkpoint_id: i64,
    leaf_count: u64,
    commitment: String,
    proof: InclusionProof,
}

/// `GET /v1/mmr-checkpoints/{id}`. Every field that the signature covers is
/// required; extra fields are ignored because the signature does not cover
/// them.
#[derive(Debug, Deserialize)]
struct ApiCheckpoint {
    mmr_checkpoint_id: i64,
    last_integrity_id: i64,
    leaf_count: u64,
    peaks: Vec<ApiPeak>,
    commitment: String,
    format_version: u32,
    created_at: String,
    system_uid: String,
    system_signature: String,
}

#[derive(Debug, Deserialize)]
struct ApiPeak {
    start_index: u64,
    height: u32,
    hash: String,
}

/// `GET /v1/integrity/{id}`. Every field the chain hash covers is required;
/// the entry's own system signature and any other field are ignored, because
/// the recomputed chain hash is authenticated by the checkpoint instead.
#[derive(Debug, Deserialize)]
struct ApiEntry {
    integrity_id: i64,
    source_id: String,
    source_type: String,
    record_hash: String,
    prev_hash: Option<String>,
    chain_hash: String,
    format_version: u32,
    created_at: String,
    system_uid: String,
}

/// What the caller pins or expects besides the public key. Every field is
/// optional; each one that is set must match, or the proof is rejected.
#[derive(Clone, Copy, Debug, Default)]
pub struct Expectations<'a> {
    /// The system account the checkpoint must name: a pin is the account's
    /// user id together with its public key.
    pub system_uid: Option<Uuid>,
    /// The exact checkpoint to accept, by commitment: for example one recorded
    /// while the key that signed it was still trusted.
    pub commitment: Option<Digest32>,
    /// A chain hash the caller computed itself.
    pub chain_hash: Option<Digest32>,
    /// The `GET /v1/integrity/{id}` response. Its chain hash is recomputed
    /// from its fields and must be the leaf the proof is about.
    pub entry_json: Option<&'a str>,
    /// The source the entry must be about. Needs `entry_json`.
    pub source_id: Option<Uuid>,
    /// The record hash the entry must commit to. Needs `entry_json`.
    pub record_hash: Option<Digest32>,
}

/// Where the proven leaf (the entry's chain hash) came from.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LeafOrigin {
    /// Recomputed from the fields of the integrity entry the caller supplied.
    RecomputedFromEntry,
    /// Equal to a chain hash the caller computed and supplied.
    Expected,
    /// Only reported by the server. The proof then shows that the server's
    /// claim is consistent with its signed checkpoint, not which record the
    /// leaf is.
    ServerReported,
}

/// The integrity entry whose chain hash was recomputed and proven.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedEntry {
    /// Source the entry admits.
    pub source_id: Uuid,
    /// Source type it was admitted as.
    pub source_type: String,
    /// Hash of the admitted record.
    pub record_hash: Digest32,
    /// When it was admitted, in Unix microseconds.
    pub created_at_unix_micros: i64,
    /// Integrity system account the entry names. Its own signature on the
    /// entry is not checked here; the checkpoint's signature covers the leaf.
    pub system_uid: Uuid,
}

/// What a successful verification established.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Verified {
    /// Integrity row id, as reported by the server. Neither the proof nor the
    /// checkpoint covers it: the proof is about the leaf at `leaf_index`.
    pub integrity_id: i64,
    /// Zero-based position of the leaf on the integrity chain.
    pub leaf_index: u64,
    /// The leaf that was proven: the entry's `chain_hash`.
    pub chain_hash: Digest32,
    /// Where that chain hash came from.
    pub leaf_origin: LeafOrigin,
    /// The entry, when it was supplied and its chain hash recomputed.
    pub entry: Option<VerifiedEntry>,
    /// Checkpoint id, as numbered by the server (not covered by the signature).
    pub mmr_checkpoint_id: i64,
    /// Rows covered by the checkpoint.
    pub leaf_count: u64,
    /// The checkpoint's signed commitment.
    pub commitment: Digest32,
    /// When the checkpoint was signed, in Unix microseconds.
    pub checkpoint_created_at_unix_micros: i64,
    /// System account whose signature was verified.
    pub system_uid: Uuid,
}

/// Why a proof was not accepted.
#[derive(Debug, Error)]
pub enum ClientError {
    /// An input is not the JSON the API produces.
    #[error("{what} is not valid: {reason}")]
    Malformed {
        /// Which input.
        what: &'static str,
        /// Parser message.
        reason: String,
    },
    /// Two inputs describe different things.
    #[error("the {0} disagree")]
    Mismatch(&'static str),
    /// The checkpoint uses a format this verifier cannot check.
    #[error("unsupported checkpoint format {0}")]
    UnsupportedFormat(u32),
    /// The integrity entry uses a format whose chain hash is unknown here.
    #[error("unsupported integrity entry format {0}")]
    UnsupportedEntryFormat(u32),
    /// The entry's fields do not hash to the chain hash it states.
    #[error("the entry's fields hash to {recomputed}, not to its chain hash {stated}")]
    EntryHashMismatch {
        /// Chain hash recomputed from the fields.
        recomputed: Digest32,
        /// Chain hash the entry states.
        stated: Digest32,
    },
    /// The proof is about another leaf than the entry supplied.
    #[error("the proof is for chain hash {proven}, but the entry hashes to {entry}")]
    EntryNotProven {
        /// The entry's recomputed chain hash.
        entry: Digest32,
        /// The chain hash the proof is about.
        proven: Digest32,
    },
    /// The leaf is not the one the caller expected.
    #[error("the proof is for chain hash {proven}, not the expected {expected}")]
    UnexpectedLeaf {
        /// What the caller expected.
        expected: Digest32,
        /// What the proof carries.
        proven: Digest32,
    },
    /// A value the caller pinned or expected differs.
    #[error("{what} is {actual}, not the expected {expected}")]
    Unexpected {
        /// Which value.
        what: &'static str,
        /// What the caller expected.
        expected: String,
        /// What the inputs say.
        actual: String,
    },
    /// An expectation about the entry was given without the entry.
    #[error("checking the {0} needs the integrity entry")]
    EntryRequired(&'static str),
    /// The cryptographic check failed.
    #[error("proof rejected: {0}")]
    Rejected(#[from] ProofError),
}

fn malformed(what: &'static str, reason: &str) -> ClientError {
    ClientError::Malformed {
        what,
        reason: reason.to_owned(),
    }
}

fn digest(what: &'static str, text: &str) -> Result<Digest32, ClientError> {
    text.parse()
        .map_err(|_| malformed(what, "not a 64-character hexadecimal digest"))
}

fn uuid(what: &'static str, text: &str) -> Result<Uuid, ClientError> {
    Uuid::parse_str(text).map_err(|error| malformed(what, &error.to_string()))
}

fn unix_micros(what: &'static str, text: &str) -> Result<i64, ClientError> {
    DateTime::parse_from_rfc3339(text)
        .map(|instant| instant.timestamp_micros())
        .map_err(|error| malformed(what, &error.to_string()))
}

/// Split a 128-character hex string into the 64 bytes it encodes.
fn signature(text: &str) -> Result<[u8; 64], ClientError> {
    let (high, low) = text
        .split_at_checked(64)
        .filter(|(_, low)| low.len() == 64)
        .ok_or_else(|| malformed("the checkpoint signature", "expected 128 hex characters"))?;
    let mut bytes = [0_u8; 64];
    bytes[..32].copy_from_slice(digest("the checkpoint signature", high)?.as_bytes());
    bytes[32..].copy_from_slice(digest("the checkpoint signature", low)?.as_bytes());
    Ok(bytes)
}

fn signed_checkpoint(checkpoint: &ApiCheckpoint) -> Result<SignedCheckpoint, ClientError> {
    let peaks = checkpoint
        .peaks
        .iter()
        .map(|peak| {
            Ok(Peak {
                start_index: peak.start_index,
                height: peak.height,
                hash: digest("a checkpoint peak", &peak.hash)?,
            })
        })
        .collect::<Result<Vec<_>, ClientError>>()?;
    Ok(SignedCheckpoint {
        format_version: checkpoint.format_version,
        last_integrity_id: checkpoint.last_integrity_id.to_string(),
        leaf_count: checkpoint.leaf_count,
        peaks,
        commitment: digest("the checkpoint commitment", &checkpoint.commitment)?,
        system_uid: uuid("the checkpoint system_uid", &checkpoint.system_uid)?.to_string(),
        created_at_unix_micros: unix_micros("the checkpoint timestamp", &checkpoint.created_at)?,
        system_signature: signature(&checkpoint.system_signature)?,
    })
}

/// Recompute the entry's chain hash from its fields and check it is the
/// proven leaf and what the caller expects.
fn verify_entry(
    entry_json: &str,
    response: &ApiProof,
    proven: &Digest32,
    expected: &Expectations<'_>,
) -> Result<VerifiedEntry, ClientError> {
    let entry: ApiEntry = serde_json::from_str(entry_json)
        .map_err(|error| malformed("the integrity entry", &error.to_string()))?;
    if entry.format_version != SUPPORTED_ENTRY_FORMAT {
        return Err(ClientError::UnsupportedEntryFormat(entry.format_version));
    }
    if entry.integrity_id != response.integrity_id {
        return Err(ClientError::Mismatch(
            "integrity ids of the entry and the proof",
        ));
    }
    let source_id = uuid("the entry source_id", &entry.source_id)?;
    let system_uid = uuid("the entry system_uid", &entry.system_uid)?;
    let record_hash = digest("the entry record_hash", &entry.record_hash)?;
    let created_at_unix_micros = unix_micros("the entry timestamp", &entry.created_at)?;
    let envelope = IntegrityEnvelope {
        // The writers sign the canonical (lowercase, hyphenated) forms.
        source_id: source_id.to_string(),
        source_type: entry.source_type.clone(),
        record_hash,
        prev_hash: entry
            .prev_hash
            .as_deref()
            .map(|text| digest("the entry prev_hash", text))
            .transpose()?,
        format_version: entry.format_version,
        created_at_unix_micros,
        system_uid: system_uid.to_string(),
    };
    let recomputed = envelope.chain_hash();
    let stated = digest("the entry chain_hash", &entry.chain_hash)?;
    if recomputed != stated {
        return Err(ClientError::EntryHashMismatch { recomputed, stated });
    }
    if recomputed != *proven {
        return Err(ClientError::EntryNotProven {
            entry: recomputed,
            proven: *proven,
        });
    }
    if let Some(wanted) = expected.source_id
        && wanted != source_id
    {
        return Err(ClientError::Unexpected {
            what: "the entry's source",
            expected: wanted.to_string(),
            actual: source_id.to_string(),
        });
    }
    if let Some(wanted) = expected.record_hash
        && wanted != record_hash
    {
        return Err(ClientError::Unexpected {
            what: "the entry's record hash",
            expected: wanted.to_string(),
            actual: record_hash.to_string(),
        });
    }
    Ok(VerifiedEntry {
        source_id,
        source_type: entry.source_type,
        record_hash,
        created_at_unix_micros,
        system_uid,
    })
}

/// Verify the API's proof against the API's checkpoint.
///
/// `public_key` is the system account's Ed25519 key, obtained independently of
/// the proof. Supply the entry (`expected.entry_json`) to tie the proof to the
/// entry's source and record hash; otherwise the result's
/// [`leaf_origin`](Verified::leaf_origin) says the leaf was only reported by
/// the server.
///
/// # Errors
///
/// Returns an error describing the first check that fails.
pub fn verify_api_proof(
    proof_json: &str,
    checkpoint_json: &str,
    public_key: &[u8; 32],
    expected: &Expectations<'_>,
) -> Result<Verified, ClientError> {
    if expected.entry_json.is_none() {
        if expected.source_id.is_some() {
            return Err(ClientError::EntryRequired("source"));
        }
        if expected.record_hash.is_some() {
            return Err(ClientError::EntryRequired("record hash"));
        }
    }
    let response: ApiProof = serde_json::from_str(proof_json)
        .map_err(|error| malformed("the proof", &error.to_string()))?;
    let checkpoint: ApiCheckpoint = serde_json::from_str(checkpoint_json)
        .map_err(|error| malformed("the checkpoint", &error.to_string()))?;

    if response.mmr_checkpoint_id != checkpoint.mmr_checkpoint_id {
        return Err(ClientError::Mismatch(
            "checkpoint ids of the proof and the checkpoint",
        ));
    }
    if response.leaf_count != checkpoint.leaf_count
        || response.proof.leaf_count != checkpoint.leaf_count
    {
        return Err(ClientError::Mismatch(
            "leaf counts of the proof and the checkpoint",
        ));
    }
    if digest("the proof commitment", &response.commitment)?
        != digest("the checkpoint commitment", &checkpoint.commitment)?
    {
        return Err(ClientError::Mismatch(
            "commitments of the proof and the checkpoint",
        ));
    }
    if checkpoint.format_version != SUPPORTED_CHECKPOINT_FORMAT {
        return Err(ClientError::UnsupportedFormat(checkpoint.format_version));
    }

    let signed = signed_checkpoint(&checkpoint)?;
    let system_uid = uuid("the checkpoint system_uid", &checkpoint.system_uid)?;
    if let Some(pinned) = expected.system_uid
        && pinned != system_uid
    {
        return Err(ClientError::Unexpected {
            what: "the checkpoint's system account",
            expected: pinned.to_string(),
            actual: system_uid.to_string(),
        });
    }
    if let Some(pinned) = expected.commitment
        && pinned != signed.commitment
    {
        return Err(ClientError::Unexpected {
            what: "the checkpoint commitment",
            expected: pinned.to_string(),
            actual: signed.commitment.to_string(),
        });
    }

    let chain_hash = digest("the proof chain_hash", &response.chain_hash)?;
    let entry = expected
        .entry_json
        .map(|json| verify_entry(json, &response, &chain_hash, expected))
        .transpose()?;
    if let Some(wanted) = expected.chain_hash
        && wanted != chain_hash
    {
        return Err(ClientError::UnexpectedLeaf {
            expected: wanted,
            proven: chain_hash,
        });
    }

    response
        .proof
        .verify_against_checkpoint(&chain_hash, &signed, public_key)?;

    let leaf_origin = if entry.is_some() {
        LeafOrigin::RecomputedFromEntry
    } else if expected.chain_hash.is_some() {
        LeafOrigin::Expected
    } else {
        LeafOrigin::ServerReported
    };
    Ok(Verified {
        integrity_id: response.integrity_id,
        leaf_index: response.proof.leaf_index,
        chain_hash,
        leaf_origin,
        entry,
        mmr_checkpoint_id: checkpoint.mmr_checkpoint_id,
        leaf_count: signed.leaf_count,
        commitment: signed.commitment,
        checkpoint_created_at_unix_micros: signed.created_at_unix_micros,
        system_uid,
    })
}
