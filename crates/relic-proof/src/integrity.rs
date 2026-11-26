//! The chain hash of one integrity-chain entry.
//!
//! An entry's `chain_hash` is the MMR leaf, so a verifier that recomputes it
//! from the entry's fields (source, record hash, previous hash, ...) ties an
//! inclusion proof to that content instead of to a value the server reports.
//! `relic-integrity-worker` signs and stores entries built from this same
//! definition.

use relic_crypto::{Digest32, hash_fields};

const CHAIN_HASH_DOMAIN: &[u8] = b"RELIC:integrity-chain-hash:v1";

/// Unsigned, canonical fields committed by an integrity-chain entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IntegrityEnvelope {
    /// Identifier of the source record being admitted.
    pub source_id: String,
    /// Fixed source-type discriminator.
    pub source_type: String,
    /// Hash of the admitted record's canonical bytes.
    pub record_hash: Digest32,
    /// Previous chain hash, or `None` for the one genesis entry.
    pub prev_hash: Option<Digest32>,
    /// Canonical format version.
    pub format_version: u32,
    /// Worker-selected UTC timestamp in Unix microseconds.
    pub created_at_unix_micros: i64,
    /// Database identity of the integrity-signing system account.
    pub system_uid: String,
}

impl IntegrityEnvelope {
    /// Calculate the chain hash over every field of this envelope.
    #[must_use]
    pub fn chain_hash(&self) -> Digest32 {
        let previous = self
            .prev_hash
            .map_or([0_u8; 32], |digest| *digest.as_bytes());
        let has_previous = [u8::from(self.prev_hash.is_some())];
        hash_fields(
            CHAIN_HASH_DOMAIN,
            &[
                self.source_id.as_bytes(),
                self.source_type.as_bytes(),
                self.record_hash.as_bytes(),
                &has_previous,
                &previous,
                &self.format_version.to_be_bytes(),
                &self.created_at_unix_micros.to_be_bytes(),
                self.system_uid.as_bytes(),
            ],
        )
    }
}
