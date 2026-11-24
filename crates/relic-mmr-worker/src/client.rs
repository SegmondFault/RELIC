//! Client-side check of the API's inclusion proof and checkpoint.
//!
//! The server's word is never taken: the checkpoint's signature is verified
//! with a public key the caller supplies (ideally pinned out of band), and the
//! proof must lead from the leaf to one of the peaks that signature covers.
//! Nothing here reads a database.

use chrono::DateTime;
use relic_crypto::Digest32;
use serde::Deserialize;
use thiserror::Error;
use uuid::Uuid;

use crate::{
    Peak, SignedCheckpoint,
    proof::{InclusionProof, ProofError},
};

/// The checkpoint format whose hashing this crate implements.
const SUPPORTED_CHECKPOINT_FORMAT: u32 = 1;

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

/// What a successful verification established.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Verified {
    /// Integrity row the proof is about.
    pub integrity_id: i64,
    /// Zero-based position of that row on the integrity chain.
    pub leaf_index: u64,
    /// The row's `chain_hash`, the leaf that was proven.
    pub chain_hash: Digest32,
    /// Checkpoint that covers it.
    pub mmr_checkpoint_id: i64,
    /// Rows covered by that checkpoint.
    pub leaf_count: u64,
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
    /// The proof and the checkpoint describe different things.
    #[error("the proof and the checkpoint disagree on their {0}")]
    Mismatch(&'static str),
    /// The checkpoint uses a format this verifier cannot check.
    #[error("unsupported checkpoint format {0}")]
    UnsupportedFormat(u32),
    /// The leaf is not the one the caller expected.
    #[error("the proof is for chain hash {proven}, not the expected {expected}")]
    UnexpectedLeaf {
        /// What the caller expected.
        expected: Digest32,
        /// What the proof carries.
        proven: Digest32,
    },
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
    let created_at = DateTime::parse_from_rfc3339(&checkpoint.created_at)
        .map_err(|error| malformed("the checkpoint timestamp", &error.to_string()))?;
    let system_uid = Uuid::parse_str(&checkpoint.system_uid)
        .map_err(|error| malformed("the checkpoint system_uid", &error.to_string()))?;
    Ok(SignedCheckpoint {
        format_version: checkpoint.format_version,
        last_integrity_id: checkpoint.last_integrity_id.to_string(),
        leaf_count: checkpoint.leaf_count,
        peaks,
        commitment: digest("the checkpoint commitment", &checkpoint.commitment)?,
        system_uid: system_uid.to_string(),
        created_at_unix_micros: created_at.timestamp_micros(),
        system_signature: signature(&checkpoint.system_signature)?,
    })
}

/// Verify the API's proof against the API's checkpoint.
///
/// `public_key` is the system account's Ed25519 key, obtained independently of
/// the proof. When `expected_chain_hash` is given, the proof must be about that
/// leaf: a client that recomputed an entry's chain hash itself should pass it,
/// otherwise the proof only shows that the server's own claim is consistent
/// with its signed checkpoint.
///
/// # Errors
///
/// Returns an error describing the first check that fails.
pub fn verify_api_proof(
    proof_json: &str,
    checkpoint_json: &str,
    public_key: &[u8; 32],
    expected_chain_hash: Option<&Digest32>,
) -> Result<Verified, ClientError> {
    let response: ApiProof = serde_json::from_str(proof_json)
        .map_err(|error| malformed("the proof", &error.to_string()))?;
    let checkpoint: ApiCheckpoint = serde_json::from_str(checkpoint_json)
        .map_err(|error| malformed("the checkpoint", &error.to_string()))?;

    if response.mmr_checkpoint_id != checkpoint.mmr_checkpoint_id {
        return Err(ClientError::Mismatch("checkpoint id"));
    }
    if response.leaf_count != checkpoint.leaf_count
        || response.proof.leaf_count != checkpoint.leaf_count
    {
        return Err(ClientError::Mismatch("leaf count"));
    }
    if digest("the proof commitment", &response.commitment)?
        != digest("the checkpoint commitment", &checkpoint.commitment)?
    {
        return Err(ClientError::Mismatch("commitment"));
    }
    if checkpoint.format_version != SUPPORTED_CHECKPOINT_FORMAT {
        return Err(ClientError::UnsupportedFormat(checkpoint.format_version));
    }

    let chain_hash = digest("the proof chain_hash", &response.chain_hash)?;
    if let Some(expected) = expected_chain_hash
        && *expected != chain_hash
    {
        return Err(ClientError::UnexpectedLeaf {
            expected: *expected,
            proven: chain_hash,
        });
    }

    let signed = signed_checkpoint(&checkpoint)?;
    response
        .proof
        .verify_against_checkpoint(&chain_hash, &signed, public_key)?;

    Ok(Verified {
        integrity_id: response.integrity_id,
        leaf_index: response.proof.leaf_index,
        chain_hash,
        mmr_checkpoint_id: checkpoint.mmr_checkpoint_id,
        leaf_count: checkpoint.leaf_count,
        system_uid: Uuid::parse_str(&signed.system_uid)
            .map_err(|error| malformed("the checkpoint system_uid", &error.to_string()))?,
    })
}
