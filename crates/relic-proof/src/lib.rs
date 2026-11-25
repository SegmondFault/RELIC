//! What it takes to check RELIC's integrity evidence offline, without a
//! database: the integrity-chain hash of one entry ([`integrity`]), the
//! Merkle Mountain Range frontier and signed checkpoints over that chain
//! (this module), inclusion proofs ([`proof`]) and the API's JSON form of a
//! proof and its checkpoint ([`client`], used by `relic-verify-proof`).
//!
//! The database workers (`relic-integrity-worker`, `relic-mmr-worker`) build
//! on the same definitions, so the chain, the checkpoints and their proofs can
//! never disagree about how anything is hashed.

pub mod client;
pub mod integrity;
pub mod proof;

pub use integrity::IntegrityEnvelope;

use relic_crypto::{Digest32, SystemSigner, hash_fields, verify_digest_signature};

const LEAF_DOMAIN: &[u8] = b"RELIC:mmr-leaf:v1";
const NODE_DOMAIN: &[u8] = b"RELIC:mmr-node:v1";
const COMMITMENT_DOMAIN: &[u8] = b"RELIC:mmr-commitment:v1";
const CHECKPOINT_DOMAIN: &[u8] = b"RELIC:mmr-checkpoint:v1";
const SIGNATURE_DOMAIN: &[u8] = b"RELIC:mmr-system-signature:v1";

/// Hash of the leaf at `leaf_index` carrying `chain_hash`.
///
/// The single definition shared by [`MmrFrontier::append`] and the proofs, so
/// the tree and its proofs can never disagree about how a leaf is hashed.
pub(crate) fn leaf_hash(leaf_index: u64, chain_hash: &Digest32) -> Digest32 {
    hash_fields(
        LEAF_DOMAIN,
        &[&leaf_index.to_be_bytes(), chain_hash.as_bytes()],
    )
}

/// Hash of the complete subtree of `height` starting at `start_index`.
pub(crate) fn node_hash(
    start_index: u64,
    height: u32,
    left: &Digest32,
    right: &Digest32,
) -> Digest32 {
    hash_fields(
        NODE_DOMAIN,
        &[
            &start_index.to_be_bytes(),
            &height.to_be_bytes(),
            left.as_bytes(),
            right.as_bytes(),
        ],
    )
}

/// One complete tree on the left-to-right MMR frontier.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Peak {
    /// Zero-based index of the peak's first covered integrity row.
    pub start_index: u64,
    /// Tree height (`0` is one leaf).
    pub height: u32,
    /// Root hash of this complete subtree.
    pub hash: Digest32,
}

/// Minimal incremental MMR state. It is reconstructible from integrity rows.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct MmrFrontier {
    leaf_count: u64,
    peaks: Vec<Peak>,
}

impl MmrFrontier {
    /// Create an empty frontier.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            leaf_count: 0,
            peaks: Vec::new(),
        }
    }

    /// Number of integrity rows covered by the frontier.
    #[must_use]
    pub const fn leaf_count(&self) -> u64 {
        self.leaf_count
    }

    /// Ordered current peaks, from left to right.
    #[must_use]
    pub fn peaks(&self) -> &[Peak] {
        &self.peaks
    }

    /// Append the next integrity chain hash and merge equal-height peaks.
    ///
    /// # Errors
    ///
    /// Returns an error if the leaf count cannot be represented as `u64`, or
    /// if the in-memory frontier violates its internal invariant.
    pub fn append(&mut self, chain_hash: Digest32) -> Result<(), AppendError> {
        let next_leaf_count = self
            .leaf_count
            .checked_add(1)
            .ok_or(AppendError::LeafCountOverflow)?;
        let leaf_index = self.leaf_count;
        let mut right = Peak {
            start_index: leaf_index,
            height: 0,
            hash: leaf_hash(leaf_index, &chain_hash),
        };

        while self
            .peaks
            .last()
            .is_some_and(|left| left.height == right.height)
        {
            let left = self.peaks.pop().ok_or(AppendError::InvalidFrontier)?;
            let parent_height = left.height + 1;
            right = Peak {
                start_index: left.start_index,
                height: parent_height,
                hash: node_hash(left.start_index, parent_height, &left.hash, &right.hash),
            };
        }

        self.peaks.push(right);
        self.leaf_count = next_leaf_count;
        Ok(())
    }

    /// Commit to the covered extent and exact ordered frontier.
    #[must_use]
    pub fn commitment(&self) -> Digest32 {
        let mut encoded_peaks = Vec::with_capacity(self.peaks.len() * 44);
        for peak in &self.peaks {
            encoded_peaks.extend_from_slice(&peak.start_index.to_be_bytes());
            encoded_peaks.extend_from_slice(&peak.height.to_be_bytes());
            encoded_peaks.extend_from_slice(peak.hash.as_bytes());
        }
        hash_fields(
            COMMITMENT_DOMAIN,
            &[&self.leaf_count.to_be_bytes(), &encoded_peaks],
        )
    }
}

/// Complete signed checkpoint payload ready for database insertion.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedCheckpoint {
    /// MMR format specification identifier.
    pub format_version: u32,
    /// Database identifier of the newest covered integrity row.
    pub last_integrity_id: String,
    /// Number of covered integrity rows.
    pub leaf_count: u64,
    /// Ordered inspectable frontier.
    pub peaks: Vec<Peak>,
    /// Commitment to the covered extent and frontier.
    pub commitment: Digest32,
    /// MMR system account identity.
    pub system_uid: String,
    /// Worker-selected UTC timestamp in Unix microseconds.
    pub created_at_unix_micros: i64,
    /// Ed25519 signature over the complete checkpoint payload hash.
    pub system_signature: [u8; 64],
}

impl SignedCheckpoint {
    /// Strictly verify the checkpoint fields, commitment and signature.
    ///
    /// # Errors
    ///
    /// Returns an error if the stored frontier does not produce the stored
    /// commitment, or if the system signature is invalid.
    pub fn verify(&self, verifying_key: &[u8; 32]) -> Result<(), VerificationError> {
        let frontier = MmrFrontier {
            leaf_count: self.leaf_count,
            peaks: self.peaks.clone(),
        };
        if frontier.commitment() != self.commitment {
            return Err(VerificationError::CommitmentMismatch);
        }
        verify_digest_signature(
            verifying_key,
            SIGNATURE_DOMAIN,
            &checkpoint_hash(self),
            &self.system_signature,
        )
        .map_err(|_| VerificationError::InvalidSignature)
    }
}

/// Sign a checkpoint for a non-empty, independently reconstructed frontier.
///
/// # Errors
///
/// Returns an error when asked to checkpoint an empty frontier, which has no
/// `last_integrity_id` to identify.
pub fn sign_checkpoint(
    frontier: &MmrFrontier,
    format_version: u32,
    last_integrity_id: String,
    system_uid: String,
    created_at_unix_micros: i64,
    signer: &SystemSigner,
) -> Result<SignedCheckpoint, CheckpointError> {
    if frontier.leaf_count == 0 {
        return Err(CheckpointError::EmptyFrontier);
    }
    let mut checkpoint = SignedCheckpoint {
        format_version,
        last_integrity_id,
        leaf_count: frontier.leaf_count,
        peaks: frontier.peaks.clone(),
        commitment: frontier.commitment(),
        system_uid,
        created_at_unix_micros,
        system_signature: [0_u8; 64],
    };
    checkpoint.system_signature =
        signer.sign_digest(SIGNATURE_DOMAIN, &checkpoint_hash(&checkpoint));
    Ok(checkpoint)
}

/// Incremental frontier update failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AppendError {
    /// No additional leaf index can be represented.
    LeafCountOverflow,
    /// The in-memory peak stack contradicted its observed state.
    InvalidFrontier,
}

/// Checkpoint construction failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CheckpointError {
    /// An empty MMR has no newest integrity row and cannot be checkpointed.
    EmptyFrontier,
}

fn checkpoint_hash(checkpoint: &SignedCheckpoint) -> Digest32 {
    let mut encoded_peaks = Vec::with_capacity(checkpoint.peaks.len() * 44);
    for peak in &checkpoint.peaks {
        encoded_peaks.extend_from_slice(&peak.start_index.to_be_bytes());
        encoded_peaks.extend_from_slice(&peak.height.to_be_bytes());
        encoded_peaks.extend_from_slice(peak.hash.as_bytes());
    }
    hash_fields(
        CHECKPOINT_DOMAIN,
        &[
            &checkpoint.format_version.to_be_bytes(),
            checkpoint.last_integrity_id.as_bytes(),
            &checkpoint.leaf_count.to_be_bytes(),
            &encoded_peaks,
            checkpoint.commitment.as_bytes(),
            checkpoint.system_uid.as_bytes(),
            &checkpoint.created_at_unix_micros.to_be_bytes(),
        ],
    )
}

/// Checkpoint verification failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerificationError {
    /// Stored commitment does not describe the stored frontier.
    CommitmentMismatch,
    /// Signature is not valid for the complete checkpoint payload.
    InvalidSignature,
}

#[cfg(test)]
mod tests {
    use relic_crypto::sha256;

    use super::*;

    #[test]
    fn frontier_grows_as_a_binary_counter() {
        let expected_heights = [
            vec![0],
            vec![1],
            vec![1, 0],
            vec![2],
            vec![2, 0],
            vec![2, 1],
            vec![2, 1, 0],
            vec![3],
        ];
        let mut frontier = MmrFrontier::new();
        for (index, expected) in expected_heights.iter().enumerate() {
            frontier.append(sha256(&index.to_be_bytes())).unwrap();
            let heights: Vec<_> = frontier.peaks().iter().map(|peak| peak.height).collect();
            assert_eq!(&heights, expected);
            assert_eq!(frontier.leaf_count(), u64::try_from(index + 1).unwrap());
        }
    }

    #[test]
    fn commitment_is_deterministic_and_extent_sensitive() {
        let mut first = MmrFrontier::new();
        let mut second = MmrFrontier::new();
        for index in 0_u64..7 {
            let leaf = sha256(&index.to_be_bytes());
            first.append(leaf).unwrap();
            second.append(leaf).unwrap();
        }
        assert_eq!(first.commitment(), second.commitment());
        second.append(sha256(b"next")).unwrap();
        assert_ne!(first.commitment(), second.commitment());
    }

    #[test]
    fn checkpoint_signature_covers_identity_extent_frontier_and_time() {
        let signer = SystemSigner::from_seed([19; 32]);
        let mut frontier = MmrFrontier::new();
        for index in 0_u64..5 {
            frontier.append(sha256(&index.to_be_bytes())).unwrap();
        }
        let mut checkpoint = sign_checkpoint(
            &frontier,
            1,
            "integrity-5".into(),
            "mmr-worker".into(),
            1_800_000_000_123_456,
            &signer,
        )
        .unwrap();
        assert_eq!(checkpoint.verify(&signer.verifying_key()), Ok(()));

        checkpoint.last_integrity_id.push('x');
        assert_eq!(
            checkpoint.verify(&signer.verifying_key()),
            Err(VerificationError::InvalidSignature)
        );
    }
}
