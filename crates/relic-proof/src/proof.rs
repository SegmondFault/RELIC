//! Inclusion proofs for the RELIC Merkle Mountain Range.
//!
//! An [`InclusionProof`] shows that one integrity row (a leaf) is covered by a
//! signed [`SignedCheckpoint`], without the verifier having to download or
//! replay the integrity chain.
//!
//! # Shape of a proof
//!
//! Every peak is a perfect binary tree whose first leaf is a multiple of the
//! tree's size, so the position of every node on the path from a leaf to its
//! peak follows from the leaf index alone. A proof therefore carries only the
//! sibling hashes, bottom-up, plus the leaf index and the leaf count of the
//! checkpoint it targets:
//!
//! * the sibling at level `k` is on the right when bit `k` of the leaf index
//!   is `0` and on the left otherwise;
//! * the proof has exactly as many siblings as the height of the peak that
//!   holds the leaf, and that peak is determined by the leaf count.
//!
//! The proof deliberately does not carry the leaf's `chain_hash`, the peak or
//! the checkpoint: the verifier supplies the `chain_hash` it wants to check
//! and the signed checkpoint it trusts. A proof is only meaningful for the
//! `leaf_count` it names; a later checkpoint needs its own proof.

use relic_crypto::Digest32;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{Peak, SignedCheckpoint, VerificationError, leaf_hash, node_hash};

/// Version of the proof encoding and of the hashing it relies on.
pub const PROOF_FORMAT_VERSION: u32 = 1;

/// Largest possible number of siblings: the height of a peak of a `u64` tree.
const MAX_SIBLINGS: usize = 63;

/// Proof that the leaf at `leaf_index` is covered by an MMR of `leaf_count`
/// leaves.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(into = "WireProof", try_from = "WireProof")]
pub struct InclusionProof {
    /// Zero-based position of the leaf on the integrity chain.
    pub leaf_index: u64,
    /// Number of leaves of the MMR (checkpoint) the proof targets.
    pub leaf_count: u64,
    /// Sibling hashes from the leaf level upwards.
    pub siblings: Vec<Digest32>,
}

/// Canonical JSON form: fixed fields, lowercase hexadecimal digests.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireProof {
    format_version: u32,
    leaf_index: u64,
    leaf_count: u64,
    siblings: Vec<String>,
}

impl From<InclusionProof> for WireProof {
    fn from(proof: InclusionProof) -> Self {
        Self {
            format_version: PROOF_FORMAT_VERSION,
            leaf_index: proof.leaf_index,
            leaf_count: proof.leaf_count,
            siblings: proof.siblings.iter().map(ToString::to_string).collect(),
        }
    }
}

impl TryFrom<WireProof> for InclusionProof {
    type Error = ProofError;

    fn try_from(wire: WireProof) -> Result<Self, ProofError> {
        if wire.format_version != PROOF_FORMAT_VERSION {
            return Err(ProofError::UnsupportedFormat(wire.format_version));
        }
        if wire.siblings.len() > MAX_SIBLINGS {
            return Err(ProofError::TooManySiblings(wire.siblings.len()));
        }
        let siblings = wire
            .siblings
            .iter()
            .map(|sibling| sibling.parse().map_err(|_| ProofError::MalformedDigest))
            .collect::<Result<Vec<Digest32>, _>>()?;
        Ok(Self {
            leaf_index: wire.leaf_index,
            leaf_count: wire.leaf_count,
            siblings,
        })
    }
}

/// Start index and height of every peak of an MMR with `leaf_count` leaves,
/// from left to right.
///
/// The heights are the set bits of `leaf_count`, largest first, so the layout
/// is fully determined by the count.
#[must_use]
pub fn peak_layout(leaf_count: u64) -> Vec<(u64, u32)> {
    let mut layout = Vec::new();
    let mut start = 0_u64;
    for height in (0..u64::BITS).rev() {
        if (leaf_count >> height) & 1 == 1 {
            layout.push((start, height));
            start += 1_u64 << height;
        }
    }
    layout
}

/// Start index and height of the peak that holds `leaf_index`.
fn locate_peak(leaf_index: u64, leaf_count: u64) -> Result<(u64, u32), ProofError> {
    if leaf_index >= leaf_count {
        return Err(ProofError::LeafOutOfRange {
            leaf_index,
            leaf_count,
        });
    }
    peak_layout(leaf_count)
        .into_iter()
        .find(|&(start, height)| leaf_index >= start && leaf_index - start < (1_u64 << height))
        .ok_or(ProofError::LeafOutOfRange {
            leaf_index,
            leaf_count,
        })
}

/// Hash of the complete subtree of `height` whose first leaf is `start`.
fn subtree_hash(chain_hashes: &[Digest32], start: u64, height: u32) -> Digest32 {
    if height == 0 {
        let position = usize::try_from(start).expect("leaf below the slice length fits usize");
        return leaf_hash(start, &chain_hashes[position]);
    }
    let child_height = height - 1;
    let left = subtree_hash(chain_hashes, start, child_height);
    let right = subtree_hash(chain_hashes, start + (1_u64 << child_height), child_height);
    node_hash(start, height, &left, &right)
}

/// Build the inclusion proof of `leaf_index` in the MMR formed by the first
/// `leaf_count` entries of `chain_hashes`.
///
/// `chain_hashes` is the integrity chain in leaf order, so
/// `chain_hashes[i]` is the `chain_hash` of leaf `i`. Only the entries of the
/// peak that holds the leaf are read, and the work is proportional to that
/// peak's size.
///
/// # Errors
///
/// Returns an error if the leaf is not below `leaf_count` or if
/// `chain_hashes` is shorter than `leaf_count`.
pub fn prove(
    chain_hashes: &[Digest32],
    leaf_index: u64,
    leaf_count: u64,
) -> Result<InclusionProof, ProofError> {
    let (_, height) = locate_peak(leaf_index, leaf_count)?;
    let covered = usize::try_from(leaf_count).map_err(|_| ProofError::ChainTooShort {
        needed: leaf_count,
        available: chain_hashes.len(),
    })?;
    if chain_hashes.len() < covered {
        return Err(ProofError::ChainTooShort {
            needed: leaf_count,
            available: chain_hashes.len(),
        });
    }
    let siblings = (0..height)
        .map(|level| {
            let own_start = leaf_index & !((1_u64 << level) - 1);
            subtree_hash(chain_hashes, own_start ^ (1_u64 << level), level)
        })
        .collect();
    Ok(InclusionProof {
        leaf_index,
        leaf_count,
        siblings,
    })
}

impl InclusionProof {
    /// Fold the proof into the peak it claims to belong to.
    ///
    /// This only computes the peak implied by `chain_hash`; it says nothing
    /// about whether that peak is trusted. Use
    /// [`verify_against_checkpoint`](Self::verify_against_checkpoint) for that.
    ///
    /// # Errors
    ///
    /// Returns an error if the leaf is not below `leaf_count` or the proof has
    /// the wrong number of siblings for the peak that holds the leaf.
    pub fn recompute_peak(&self, chain_hash: &Digest32) -> Result<Peak, ProofError> {
        let (start, height) = locate_peak(self.leaf_index, self.leaf_count)?;
        if self.siblings.len() != height as usize {
            return Err(ProofError::WrongProofLength {
                expected: height as usize,
                actual: self.siblings.len(),
            });
        }
        let mut node = leaf_hash(self.leaf_index, chain_hash);
        for (level, sibling) in (0..height).zip(&self.siblings) {
            let parent_start = self.leaf_index & !((1_u64 << (level + 1)) - 1);
            node = if (self.leaf_index >> level) & 1 == 0 {
                node_hash(parent_start, level + 1, &node, sibling)
            } else {
                node_hash(parent_start, level + 1, sibling, &node)
            };
        }
        Ok(Peak {
            start_index: start,
            height,
            hash: node,
        })
    }

    /// Check that `chain_hash` is the leaf `leaf_index` of the MMR committed
    /// to by `checkpoint`, as signed by `verifying_key`.
    ///
    /// The checkpoint's signature and commitment are verified first, then its
    /// peaks are checked against the shape its leaf count dictates, and
    /// finally the peak recomputed from the proof must be one of them.
    ///
    /// # Errors
    ///
    /// Returns an error if any of those checks fails.
    pub fn verify_against_checkpoint(
        &self,
        chain_hash: &Digest32,
        checkpoint: &SignedCheckpoint,
        verifying_key: &[u8; 32],
    ) -> Result<(), ProofError> {
        checkpoint
            .verify(verifying_key)
            .map_err(ProofError::Checkpoint)?;
        if checkpoint.leaf_count != self.leaf_count {
            return Err(ProofError::LeafCountMismatch {
                proof: self.leaf_count,
                checkpoint: checkpoint.leaf_count,
            });
        }
        let shape: Vec<(u64, u32)> = checkpoint
            .peaks
            .iter()
            .map(|peak| (peak.start_index, peak.height))
            .collect();
        if shape != peak_layout(checkpoint.leaf_count) {
            return Err(ProofError::PeakLayout);
        }
        let peak = self.recompute_peak(chain_hash)?;
        if checkpoint.peaks.contains(&peak) {
            Ok(())
        } else {
            Err(ProofError::PeakMismatch)
        }
    }
}

/// Inclusion proof construction or verification failure.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ProofError {
    /// The leaf is not covered by an MMR of that many leaves.
    #[error("leaf {leaf_index} is not covered by an MMR of {leaf_count} leaves")]
    LeafOutOfRange {
        /// Requested leaf.
        leaf_index: u64,
        /// Leaves of the MMR.
        leaf_count: u64,
    },
    /// Not enough chain hashes were supplied to build the proof.
    #[error("the proof needs {needed} chain hashes but only {available} were supplied")]
    ChainTooShort {
        /// Leaves the MMR covers.
        needed: u64,
        /// Hashes supplied.
        available: usize,
    },
    /// The proof carries the wrong number of siblings for its leaf.
    #[error("the proof has {actual} siblings but its leaf needs {expected}")]
    WrongProofLength {
        /// Height of the peak that holds the leaf.
        expected: usize,
        /// Siblings in the proof.
        actual: usize,
    },
    /// The proof targets a different leaf count than the checkpoint covers.
    #[error("the proof targets {proof} leaves but the checkpoint covers {checkpoint}")]
    LeafCountMismatch {
        /// Leaf count named by the proof.
        proof: u64,
        /// Leaf count of the checkpoint.
        checkpoint: u64,
    },
    /// The checkpoint's peaks do not have the shape its leaf count dictates.
    #[error("the checkpoint peaks do not match the shape of its leaf count")]
    PeakLayout,
    /// The recomputed peak is not one of the checkpoint's peaks.
    #[error("the proof does not lead to a peak of the checkpoint")]
    PeakMismatch,
    /// The checkpoint's own commitment or signature is invalid.
    #[error("invalid checkpoint: {0:?}")]
    Checkpoint(VerificationError),
    /// The encoded proof uses an unknown format version.
    #[error("unsupported proof format version {0}")]
    UnsupportedFormat(u32),
    /// The encoded proof lists more siblings than any tree can need.
    #[error("the proof lists {0} siblings, more than any MMR can need")]
    TooManySiblings(usize),
    /// A sibling is not a 64-character hexadecimal digest.
    #[error("a proof sibling is not a valid hexadecimal digest")]
    MalformedDigest,
}

#[cfg(test)]
mod tests {
    use relic_crypto::{SystemSigner, hash_fields, sha256};

    use super::*;
    use crate::{MmrFrontier, sign_checkpoint};

    fn chain(length: u64) -> Vec<Digest32> {
        (0..length)
            .map(|index| sha256(&index.to_be_bytes()))
            .collect()
    }

    fn frontier_of(chain_hashes: &[Digest32]) -> MmrFrontier {
        let mut frontier = MmrFrontier::new();
        for hash in chain_hashes {
            frontier.append(*hash).unwrap();
        }
        frontier
    }

    /// The construction written out again from the specification, without the
    /// shared helpers, so a change to them cannot go unnoticed.
    fn reference_root(chain_hashes: &[Digest32], start: u64, height: u32) -> Digest32 {
        if height == 0 {
            return hash_fields(
                b"RELIC:mmr-leaf:v1",
                &[
                    &start.to_be_bytes(),
                    chain_hashes[usize::try_from(start).unwrap()].as_bytes(),
                ],
            );
        }
        let half = 1_u64 << (height - 1);
        let left = reference_root(chain_hashes, start, height - 1);
        let right = reference_root(chain_hashes, start + half, height - 1);
        hash_fields(
            b"RELIC:mmr-node:v1",
            &[
                &start.to_be_bytes(),
                &height.to_be_bytes(),
                left.as_bytes(),
                right.as_bytes(),
            ],
        )
    }

    #[test]
    fn frontier_matches_the_specification() {
        for length in 1..=40 {
            let hashes = chain(length);
            let frontier = frontier_of(&hashes);
            let expected: Vec<_> = peak_layout(length)
                .into_iter()
                .map(|(start, height)| Peak {
                    start_index: start,
                    height,
                    hash: reference_root(&hashes, start, height),
                })
                .collect();
            assert_eq!(frontier.peaks(), expected.as_slice(), "{length} leaves");
        }
    }

    #[test]
    fn layout_is_the_binary_decomposition_of_the_count() {
        assert_eq!(peak_layout(0), vec![]);
        assert_eq!(peak_layout(1), vec![(0, 0)]);
        assert_eq!(peak_layout(7), vec![(0, 2), (4, 1), (6, 0)]);
        assert_eq!(peak_layout(8), vec![(0, 3)]);
        assert_eq!(peak_layout(13), vec![(0, 3), (8, 2), (12, 0)]);
        assert_eq!(peak_layout(u64::MAX).len(), 64);
    }

    #[test]
    fn layout_always_matches_the_incremental_frontier() {
        let hashes = chain(70);
        let mut frontier = MmrFrontier::new();
        for (index, hash) in hashes.iter().enumerate() {
            frontier.append(*hash).unwrap();
            let shape: Vec<_> = frontier
                .peaks()
                .iter()
                .map(|peak| (peak.start_index, peak.height))
                .collect();
            assert_eq!(shape, peak_layout(u64::try_from(index + 1).unwrap()));
        }
    }

    #[test]
    fn every_leaf_of_every_size_proves_and_verifies() {
        for length in 1..=40_u64 {
            let hashes = chain(length);
            let frontier = frontier_of(&hashes);
            for leaf in 0..length {
                let proof = prove(&hashes, leaf, length).unwrap();
                let peak = proof.recompute_peak(&hashes[usize::try_from(leaf).unwrap()]);
                let peak = peak.unwrap_or_else(|e| panic!("{length}/{leaf}: {e}"));
                assert!(
                    frontier.peaks().contains(&peak),
                    "{length} leaves, leaf {leaf}"
                );
                assert_eq!(proof.siblings.len(), peak.height as usize);
            }
        }
    }

    #[test]
    fn proofs_for_older_checkpoints_ignore_later_leaves() {
        let hashes = chain(30);
        for covered in [1_u64, 5, 12, 16, 29] {
            let frontier = frontier_of(&hashes[..usize::try_from(covered).unwrap()]);
            let proof = prove(&hashes, covered - 1, covered).unwrap();
            let peak = proof
                .recompute_peak(&hashes[usize::try_from(covered - 1).unwrap()])
                .unwrap();
            assert!(frontier.peaks().contains(&peak));
        }
    }

    #[test]
    fn a_proof_is_logarithmic() {
        let hashes = chain(1024);
        let proof = prove(&hashes, 517, 1024).unwrap();
        assert_eq!(proof.siblings.len(), 10);
    }

    #[test]
    fn a_wrong_leaf_hash_does_not_verify() {
        let hashes = chain(13);
        let frontier = frontier_of(&hashes);
        let proof = prove(&hashes, 6, 13).unwrap();
        let peak = proof.recompute_peak(&sha256(b"forged")).unwrap();
        assert!(!frontier.peaks().contains(&peak));
    }

    #[test]
    fn a_leaf_hash_cannot_be_replayed_at_another_position() {
        // Same proof, same sibling hashes, but claiming another index: the
        // leaf and every node commit to their position.
        let hashes = chain(16);
        let frontier = frontier_of(&hashes);
        let mut proof = prove(&hashes, 4, 16).unwrap();
        for forged_index in [0_u64, 5, 6, 12] {
            proof.leaf_index = forged_index;
            let peak = proof.recompute_peak(&hashes[4]).unwrap();
            assert!(
                !frontier.peaks().contains(&peak),
                "index 4 accepted as {forged_index}"
            );
        }
    }

    #[test]
    fn a_tampered_sibling_does_not_verify() {
        let hashes = chain(20);
        let frontier = frontier_of(&hashes);
        let proof = prove(&hashes, 9, 20).unwrap();
        for position in 0..proof.siblings.len() {
            let mut forged = proof.clone();
            forged.siblings[position] = sha256(b"forged");
            let peak = forged.recompute_peak(&hashes[9]).unwrap();
            assert!(!frontier.peaks().contains(&peak), "sibling {position}");
        }
    }

    #[test]
    fn swapped_siblings_do_not_verify() {
        let hashes = chain(16);
        let frontier = frontier_of(&hashes);
        let mut proof = prove(&hashes, 5, 16).unwrap();
        proof.siblings.swap(0, 1);
        let peak = proof.recompute_peak(&hashes[5]).unwrap();
        assert!(!frontier.peaks().contains(&peak));
    }

    #[test]
    fn the_wrong_number_of_siblings_is_rejected() {
        let hashes = chain(16);
        let proof = prove(&hashes, 5, 16).unwrap();
        let mut longer = proof.clone();
        longer.siblings.push(sha256(b"extra"));
        let mut shorter = proof.clone();
        shorter.siblings.pop();
        for bad in [longer, shorter] {
            assert!(matches!(
                bad.recompute_peak(&hashes[5]),
                Err(ProofError::WrongProofLength { expected: 4, .. })
            ));
        }
    }

    #[test]
    fn leaves_outside_the_range_are_rejected() {
        let hashes = chain(5);
        assert!(matches!(
            prove(&hashes, 5, 5),
            Err(ProofError::LeafOutOfRange { .. })
        ));
        assert!(matches!(
            prove(&hashes, 0, 0),
            Err(ProofError::LeafOutOfRange { .. })
        ));
        assert!(matches!(
            prove(&hashes, 2, 6),
            Err(ProofError::ChainTooShort { needed: 6, .. })
        ));
    }

    #[test]
    fn a_single_leaf_needs_no_siblings() {
        let hashes = chain(1);
        let proof = prove(&hashes, 0, 1).unwrap();
        assert_eq!(proof.siblings, Vec::<Digest32>::new());
        let peak = proof.recompute_peak(&hashes[0]).unwrap();
        assert_eq!(frontier_of(&hashes).peaks(), [peak]);
    }

    fn signed(length: u64, signer: &SystemSigner) -> (Vec<Digest32>, SignedCheckpoint) {
        let hashes = chain(length);
        let checkpoint = sign_checkpoint(
            &frontier_of(&hashes),
            1,
            length.to_string(),
            "system".into(),
            1_700_000_000_000_000,
            signer,
        )
        .unwrap();
        (hashes, checkpoint)
    }

    #[test]
    fn a_signed_checkpoint_accepts_every_leaf() {
        let signer = SystemSigner::from_seed([7; 32]);
        let key = signer.verifying_key();
        let (hashes, checkpoint) = signed(11, &signer);
        for leaf in 0..11_u64 {
            let proof = prove(&hashes, leaf, 11).unwrap();
            let index = usize::try_from(leaf).unwrap();
            proof
                .verify_against_checkpoint(&hashes[index], &checkpoint, &key)
                .unwrap();
        }
    }

    #[test]
    fn the_wrong_signing_key_is_rejected() {
        let signer = SystemSigner::from_seed([7; 32]);
        let other = SystemSigner::from_seed([8; 32]);
        let (hashes, checkpoint) = signed(6, &signer);
        let proof = prove(&hashes, 2, 6).unwrap();
        assert!(matches!(
            proof.verify_against_checkpoint(&hashes[2], &checkpoint, &other.verifying_key()),
            Err(ProofError::Checkpoint(VerificationError::InvalidSignature))
        ));
    }

    #[test]
    fn a_proof_for_another_checkpoint_is_rejected() {
        let signer = SystemSigner::from_seed([7; 32]);
        let key = signer.verifying_key();
        let (hashes, checkpoint) = signed(8, &signer);
        let proof = prove(&hashes, 2, 6).unwrap();
        assert_eq!(
            proof.verify_against_checkpoint(&hashes[2], &checkpoint, &key),
            Err(ProofError::LeafCountMismatch {
                proof: 6,
                checkpoint: 8
            })
        );
    }

    #[test]
    fn a_forged_leaf_is_rejected_against_a_signed_checkpoint() {
        let signer = SystemSigner::from_seed([7; 32]);
        let key = signer.verifying_key();
        let (hashes, checkpoint) = signed(9, &signer);
        let proof = prove(&hashes, 3, 9).unwrap();
        assert_eq!(
            proof.verify_against_checkpoint(&sha256(b"forged"), &checkpoint, &key),
            Err(ProofError::PeakMismatch)
        );
    }

    #[test]
    fn a_checkpoint_with_a_tampered_peak_is_rejected() {
        let signer = SystemSigner::from_seed([7; 32]);
        let key = signer.verifying_key();
        let (hashes, mut checkpoint) = signed(9, &signer);
        let proof = prove(&hashes, 3, 9).unwrap();
        checkpoint.peaks[0].hash = sha256(b"forged");
        assert!(matches!(
            proof.verify_against_checkpoint(&hashes[3], &checkpoint, &key),
            Err(ProofError::Checkpoint(
                VerificationError::CommitmentMismatch
            ))
        ));
    }

    #[test]
    fn a_signed_checkpoint_with_a_malformed_frontier_is_rejected() {
        // Even a correctly signed checkpoint must have the peaks its leaf
        // count dictates; a buggy or hostile signer cannot widen what a proof
        // may lead to.
        let signer = SystemSigner::from_seed([7; 32]);
        let key = signer.verifying_key();
        let hashes = chain(9);
        let mut frontier = frontier_of(&hashes);
        frontier.peaks.reverse();
        let checkpoint = sign_checkpoint(
            &frontier,
            1,
            "9".into(),
            "system".into(),
            1_700_000_000_000_000,
            &signer,
        )
        .unwrap();
        checkpoint.verify(&key).unwrap();
        let proof = prove(&hashes, 3, 9).unwrap();
        assert_eq!(
            proof.verify_against_checkpoint(&hashes[3], &checkpoint, &key),
            Err(ProofError::PeakLayout)
        );
    }

    #[test]
    fn the_json_encoding_is_canonical_and_round_trips() {
        let hashes = chain(6);
        let proof = prove(&hashes, 4, 6).unwrap();
        let json = serde_json::to_string(&proof).unwrap();
        let expected = format!(
            "{{\"format_version\":1,\"leaf_index\":4,\"leaf_count\":6,\"siblings\":[\"{}\"]}}",
            proof.siblings[0]
        );
        assert_eq!(json, expected);
        assert_eq!(
            serde_json::from_str::<InclusionProof>(&json).unwrap(),
            proof
        );
    }

    #[test]
    fn malformed_encodings_are_rejected() {
        let digest = "00".repeat(32);
        let decode = |text: &str| serde_json::from_str::<InclusionProof>(text);
        let base = |extra: &str, version: u32, sibling: &str| {
            format!(
                "{{\"format_version\":{version},\"leaf_index\":0,\"leaf_count\":2,\
                 \"siblings\":[\"{sibling}\"]{extra}}}"
            )
        };
        assert!(decode(&base("", 1, &digest)).is_ok());
        assert!(decode(&base("", 2, &digest)).is_err(), "unknown version");
        assert!(decode(&base("", 1, "abcd")).is_err(), "short digest");
        assert!(decode(&base("", 1, &"zz".repeat(32))).is_err(), "not hex");
        assert!(
            decode(&base(",\"extra\":1", 1, &digest)).is_err(),
            "unknown field"
        );
        let too_many = format!(
            "{{\"format_version\":1,\"leaf_index\":0,\"leaf_count\":2,\"siblings\":[{}]}}",
            vec![format!("\"{digest}\""); 64].join(",")
        );
        assert!(decode(&too_many).is_err(), "more siblings than any tree");
    }
}
