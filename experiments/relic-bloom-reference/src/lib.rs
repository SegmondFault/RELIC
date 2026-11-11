//! Synthetic reference model for RELIC's future Bloom-filter design.
//!
//! This crate deliberately has no PostgreSQL, network, object-storage, mmap or
//! service integration. It validates only deterministic calculation and
//! artifact-boundary decisions documented in `docs/bloom-filters.md`.

use std::str;

use relic_crypto::{Digest32, hash_fields, sha256};
use thiserror::Error;

const MAGIC: &[u8; 8] = b"RELICBF\0";
const FORMAT_VERSION: u16 = 1;
const INDEX_DOMAIN: &[u8] = b"relic-bloom-index-v1";
const MANIFEST_DOMAIN: &[u8] = b"relic-bloom-manifest-v1";
const FIXED_HEADER_LENGTH: usize = 8 + 2 + 2 + 8 + 4 + 8;
const MAX_HASH_FUNCTION_COUNT: u32 = 64;
const MAX_EXPECTED_UNIQUE_VALUES: u64 = 300_000_000;
const MIN_TARGET_FALSE_POSITIVE_PROBABILITY: f64 = 1e-12;

/// A small unpartitioned reference filter used only by synthetic tests.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReferenceBloom {
    namespace: String,
    bit_count: u64,
    hash_function_count: u32,
    bits: Vec<u8>,
}

/// Errors produced by the bounded reference model.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum BloomError {
    /// Namespace is empty, non-ASCII or too large for the reference header.
    #[error("invalid Bloom namespace")]
    InvalidNamespace,
    /// The expected count or probability cannot produce a bounded allocation.
    #[error("invalid Bloom sizing parameters")]
    InvalidSizing,
    /// The payload is malformed, unsupported or inconsistent.
    #[error("invalid Bloom payload: {0}")]
    InvalidPayload(&'static str),
}

impl ReferenceBloom {
    /// Allocate a reference filter using the standard optimal sizing formula.
    ///
    /// Empty sets retain one zero byte and one index operation so their
    /// serialization remains explicit and membership always returns false.
    ///
    /// # Errors
    ///
    /// Returns [`BloomError::InvalidNamespace`] for a non-canonical namespace
    /// and [`BloomError::InvalidSizing`] for an unsupported count/probability
    /// or allocation.
    pub fn with_rate(
        namespace: &str,
        expected_unique_values: u64,
        target_false_positive_probability: f64,
    ) -> Result<Self, BloomError> {
        validate_namespace(namespace)?;
        let (bit_count, hash_function_count) =
            calculate_sizing(expected_unique_values, target_false_positive_probability)?;

        let byte_count = usize::try_from(bit_count / 8).map_err(|_| BloomError::InvalidSizing)?;
        let mut bits = Vec::new();
        bits.try_reserve_exact(byte_count)
            .map_err(|_| BloomError::InvalidSizing)?;
        bits.resize(byte_count, 0);

        Ok(Self {
            namespace: namespace.to_owned(),
            bit_count,
            hash_function_count,
            bits,
        })
    }

    /// Return the exact filter namespace.
    #[must_use]
    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    /// Return the rounded bit count.
    #[must_use]
    pub const fn bit_count(&self) -> u64 {
        self.bit_count
    }

    /// Return the number of derived bit indexes per value.
    #[must_use]
    pub const fn hash_function_count(&self) -> u32 {
        self.hash_function_count
    }

    /// Idempotently insert canonical bytes.
    ///
    /// # Panics
    ///
    /// Panics only if this value was constructed outside its private validated
    /// invariants, which safe callers cannot do.
    pub fn insert(&mut self, canonical_value: &[u8]) {
        let indexes: Vec<_> = self.indexes(canonical_value).collect();
        for index in indexes {
            let byte_index = usize::try_from(index / 8).expect("index fits allocated bitset");
            let bit_index = u32::try_from(index % 8).expect("bit index is below eight");
            self.bits[byte_index] |= 1_u8 << bit_index;
        }
    }

    /// Return false only when the value is definitely absent from this filter.
    ///
    /// # Panics
    ///
    /// Panics only if this value was constructed outside its private validated
    /// invariants, which safe callers cannot do.
    #[must_use]
    pub fn possibly_contains(&self, canonical_value: &[u8]) -> bool {
        self.indexes(canonical_value).all(|index| {
            let byte_index = usize::try_from(index / 8).expect("index fits allocated bitset");
            let bit_index = u32::try_from(index % 8).expect("bit index is below eight");
            self.bits[byte_index] & (1_u8 << bit_index) != 0
        })
    }

    /// Serialize the small reference payload deterministically.
    ///
    /// This is a golden-vector format for design validation, not the planned
    /// production 256-shard container.
    ///
    /// # Panics
    ///
    /// Panics only if this value was constructed outside its private validated
    /// invariants, which safe callers cannot do.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let namespace_length = u16::try_from(self.namespace.len()).expect("validated namespace");
        let bitset_length = u64::try_from(self.bits.len()).expect("bitset length fits u64");
        let mut output = Vec::with_capacity(
            FIXED_HEADER_LENGTH + usize::from(namespace_length) + self.bits.len(),
        );
        output.extend_from_slice(MAGIC);
        output.extend_from_slice(&FORMAT_VERSION.to_be_bytes());
        output.extend_from_slice(&namespace_length.to_be_bytes());
        output.extend_from_slice(&self.bit_count.to_be_bytes());
        output.extend_from_slice(&self.hash_function_count.to_be_bytes());
        output.extend_from_slice(&bitset_length.to_be_bytes());
        output.extend_from_slice(self.namespace.as_bytes());
        output.extend_from_slice(&self.bits);
        output
    }

    /// Strictly parse a bounded reference payload.
    ///
    /// # Errors
    ///
    /// Returns [`BloomError::InvalidPayload`] for unsupported, truncated,
    /// inconsistent or non-canonical bytes.
    pub fn from_bytes(payload: &[u8]) -> Result<Self, BloomError> {
        if payload.len() < FIXED_HEADER_LENGTH {
            return Err(BloomError::InvalidPayload("truncated header"));
        }
        if &payload[..8] != MAGIC {
            return Err(BloomError::InvalidPayload("wrong magic"));
        }

        let format_version = read_u16(payload, 8)?;
        if format_version != FORMAT_VERSION {
            return Err(BloomError::InvalidPayload("unsupported version"));
        }
        let namespace_length = usize::from(read_u16(payload, 10)?);
        let bit_count = read_u64(payload, 12)?;
        let hash_function_count = read_u32(payload, 20)?;
        let bitset_length = usize::try_from(read_u64(payload, 24)?)
            .map_err(|_| BloomError::InvalidPayload("bitset length exceeds platform"))?;

        if bit_count == 0 || bit_count % 8 != 0 {
            return Err(BloomError::InvalidPayload("invalid bit count"));
        }
        if !(1..=MAX_HASH_FUNCTION_COUNT).contains(&hash_function_count) {
            return Err(BloomError::InvalidPayload("invalid hash-function count"));
        }
        if usize::try_from(bit_count / 8).ok() != Some(bitset_length) {
            return Err(BloomError::InvalidPayload("bit count/length mismatch"));
        }

        let expected_length = FIXED_HEADER_LENGTH
            .checked_add(namespace_length)
            .and_then(|length| length.checked_add(bitset_length))
            .ok_or(BloomError::InvalidPayload("length overflow"))?;
        if payload.len() != expected_length {
            return Err(BloomError::InvalidPayload("trailing or missing bytes"));
        }

        let namespace_end = FIXED_HEADER_LENGTH + namespace_length;
        let namespace = str::from_utf8(&payload[FIXED_HEADER_LENGTH..namespace_end])
            .map_err(|_| BloomError::InvalidPayload("namespace is not UTF-8"))?;
        validate_namespace(namespace)
            .map_err(|_| BloomError::InvalidPayload("invalid namespace"))?;

        Ok(Self {
            namespace: namespace.to_owned(),
            bit_count,
            hash_function_count,
            bits: payload[namespace_end..].to_vec(),
        })
    }

    /// Hash the exact reference payload bytes.
    #[must_use]
    pub fn payload_sha256(&self) -> Digest32 {
        sha256(&self.to_bytes())
    }

    fn indexes(&self, canonical_value: &[u8]) -> impl Iterator<Item = u64> + '_ {
        let digest = hash_fields(INDEX_DOMAIN, &[self.namespace.as_bytes(), canonical_value]);
        let bytes = digest.as_bytes();
        let h1 = u128::from_be_bytes(bytes[..16].try_into().expect("fixed digest half"));
        let raw_h2 = u128::from_be_bytes(bytes[16..].try_into().expect("fixed digest half"));
        let modulus = u128::from(self.bit_count);
        let h1 = h1 % modulus;
        let h2 = match raw_h2 % modulus {
            0 => 1,
            value => value,
        };
        (0..self.hash_function_count).map(move |index| {
            let value = (h1 + u128::from(index) * h2) % modulus;
            u64::try_from(value).expect("modulo u64 bit count")
        })
    }
}

/// Canonical fields that the future Bloom publisher signs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReferenceManifestCore {
    /// Artifact format name.
    pub format: String,
    /// Artifact format version.
    pub format_version: u32,
    /// Exact filter namespace.
    pub namespace: String,
    /// Covered MMR checkpoint ID.
    pub checkpoint_id: u64,
    /// Covered integrity-chain head.
    pub integrity_chain_head: [u8; 32],
    /// Covered MMR leaf count.
    pub mmr_leaf_count: u64,
    /// Covered rows including duplicates.
    pub entry_count: u64,
    /// Distinct values inserted.
    pub unique_value_count: u64,
    /// Total bit count.
    pub bit_count: u64,
    /// Index count per value.
    pub hash_function_count: u32,
    /// Canonical decimal probability.
    pub target_false_positive_probability: String,
    /// Index hash algorithm identifier.
    pub hash_algorithm: String,
    /// Index domain identifier.
    pub domain: String,
    /// Exact payload digest.
    pub payload_sha256: [u8; 32],
    /// Canonical UTC build timestamp.
    pub built_at: String,
    /// Reviewed builder version.
    pub builder_version: String,
    /// Dedicated system UUID bytes.
    pub system_uid: [u8; 16],
}

impl ReferenceManifestCore {
    /// Return the digest covered by the separate Ed25519 system signature.
    #[must_use]
    pub fn signed_digest(&self) -> Digest32 {
        let format_version = self.format_version.to_be_bytes();
        let checkpoint_id = self.checkpoint_id.to_be_bytes();
        let mmr_leaf_count = self.mmr_leaf_count.to_be_bytes();
        let entry_count = self.entry_count.to_be_bytes();
        let unique_value_count = self.unique_value_count.to_be_bytes();
        let bit_count = self.bit_count.to_be_bytes();
        let hash_function_count = self.hash_function_count.to_be_bytes();
        hash_fields(
            MANIFEST_DOMAIN,
            &[
                self.format.as_bytes(),
                &format_version,
                self.namespace.as_bytes(),
                &checkpoint_id,
                &self.integrity_chain_head,
                &mmr_leaf_count,
                &entry_count,
                &unique_value_count,
                &bit_count,
                &hash_function_count,
                self.target_false_positive_probability.as_bytes(),
                self.hash_algorithm.as_bytes(),
                self.domain.as_bytes(),
                &self.payload_sha256,
                self.built_at.as_bytes(),
                self.builder_version.as_bytes(),
                &self.system_uid,
            ],
        )
    }
}

#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    reason = "counts are bounded below 2^53 and finite positive sizing results are checked before conversion"
)]
fn calculate_sizing(
    expected_unique_values: u64,
    target_false_positive_probability: f64,
) -> Result<(u64, u32), BloomError> {
    if !(MIN_TARGET_FALSE_POSITIVE_PROBABILITY..1.0).contains(&target_false_positive_probability)
        || expected_unique_values > MAX_EXPECTED_UNIQUE_VALUES
    {
        return Err(BloomError::InvalidSizing);
    }
    if expected_unique_values == 0 {
        return Ok((8, 1));
    }

    let bits_per_value =
        -target_false_positive_probability.ln() / (std::f64::consts::LN_2 * std::f64::consts::LN_2);
    let raw_bit_count = (expected_unique_values as f64 * bits_per_value).ceil();
    if !raw_bit_count.is_finite() || raw_bit_count > u64::MAX as f64 {
        return Err(BloomError::InvalidSizing);
    }
    let raw_bit_count = raw_bit_count as u64;
    let byte_count = raw_bit_count
        .checked_add(7)
        .ok_or(BloomError::InvalidSizing)?
        / 8;
    let bit_count = byte_count.checked_mul(8).ok_or(BloomError::InvalidSizing)?;
    let raw_hash_function_count =
        ((bit_count as f64 / expected_unique_values as f64) * std::f64::consts::LN_2).round();
    if !(1.0..=f64::from(MAX_HASH_FUNCTION_COUNT)).contains(&raw_hash_function_count) {
        return Err(BloomError::InvalidSizing);
    }
    Ok((bit_count, raw_hash_function_count as u32))
}

fn validate_namespace(namespace: &str) -> Result<(), BloomError> {
    if namespace.is_empty()
        || namespace.len() > usize::from(u16::MAX)
        || !namespace
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return Err(BloomError::InvalidNamespace);
    }
    Ok(())
}

fn read_u16(payload: &[u8], offset: usize) -> Result<u16, BloomError> {
    let bytes = payload
        .get(offset..offset + 2)
        .ok_or(BloomError::InvalidPayload("truncated u16"))?;
    Ok(u16::from_be_bytes(bytes.try_into().expect("two bytes")))
}

fn read_u32(payload: &[u8], offset: usize) -> Result<u32, BloomError> {
    let bytes = payload
        .get(offset..offset + 4)
        .ok_or(BloomError::InvalidPayload("truncated u32"))?;
    Ok(u32::from_be_bytes(bytes.try_into().expect("four bytes")))
}

fn read_u64(payload: &[u8], offset: usize) -> Result<u64, BloomError> {
    let bytes = payload
        .get(offset..offset + 8)
        .ok_or(BloomError::InvalidPayload("truncated u64"))?;
    Ok(u64::from_be_bytes(bytes.try_into().expect("eight bytes")))
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use relic_crypto::{SystemSigner, hash_fields, verify_digest_signature};

    use super::{BloomError, ReferenceBloom, ReferenceManifestCore, calculate_sizing};

    fn synthetic_value(set: &[u8], index: u64) -> [u8; 32] {
        *hash_fields(
            b"relic-bloom-synthetic-value-v1",
            &[set, &index.to_be_bytes()],
        )
        .as_bytes()
    }

    fn example_manifest(payload_sha256: [u8; 32]) -> ReferenceManifestCore {
        ReferenceManifestCore {
            format: "relic-bloom-filter".to_owned(),
            format_version: 1,
            namespace: "binary-sha256".to_owned(),
            checkpoint_id: 42,
            integrity_chain_head: [0x11; 32],
            mmr_leaf_count: 1_000,
            entry_count: 950,
            unique_value_count: 900,
            bit_count: 25_880,
            hash_function_count: 20,
            target_false_positive_probability: "0.000001".to_owned(),
            hash_algorithm: "sha256-double-v1".to_owned(),
            domain: "relic-bloom-index-v1".to_owned(),
            payload_sha256,
            built_at: "2026-01-01T00:00:00.000000Z".to_owned(),
            builder_version: "0000000000000000000000000000000000000000".to_owned(),
            system_uid: [0x01; 16],
        }
    }

    #[test]
    fn no_false_negatives_for_synthetic_values() {
        let mut filter = ReferenceBloom::with_rate("binary-sha256", 50_000, 1e-6).unwrap();
        for index in 0..50_000 {
            filter.insert(&synthetic_value(b"inserted", index));
        }
        for index in 0..50_000 {
            assert!(filter.possibly_contains(&synthetic_value(b"inserted", index)));
        }
    }

    #[test]
    fn false_positive_rate_stays_within_synthetic_tolerance() {
        let mut filter = ReferenceBloom::with_rate("binary-sha256", 20_000, 1e-3).unwrap();
        for index in 0..20_000 {
            filter.insert(&synthetic_value(b"inserted", index));
        }
        let false_positives = (0..200_000)
            .filter(|index| filter.possibly_contains(&synthetic_value(b"disjoint", *index)))
            .count();

        // Expected value is about 200. The deliberately generous deterministic
        // bound catches a broken construction without pretending to be a full
        // production statistical qualification.
        assert!(
            false_positives <= 350,
            "observed {false_positives} false positives"
        );
    }

    #[test]
    fn input_order_and_duplicates_do_not_change_payload() {
        let values: Vec<_> = (0..2_000)
            .map(|index| synthetic_value(b"ordered", index))
            .collect();
        let mut forward = ReferenceBloom::with_rate("bsim-sha256", 2_000, 1e-6).unwrap();
        for value in &values {
            forward.insert(value);
            forward.insert(value);
        }

        let mut reverse = ReferenceBloom::with_rate("bsim-sha256", 2_000, 1e-6).unwrap();
        for value in values.iter().rev() {
            reverse.insert(value);
        }
        assert_eq!(forward.to_bytes(), reverse.to_bytes());
        assert_eq!(forward.payload_sha256(), reverse.payload_sha256());
    }

    #[test]
    fn namespace_separates_the_same_value() {
        let value = synthetic_value(b"same", 1);
        let mut binary = ReferenceBloom::with_rate("binary-sha256", 1, 1e-6).unwrap();
        binary.insert(&value);
        let mut bsim = ReferenceBloom::with_rate("bsim-sha256", 1, 1e-6).unwrap();
        bsim.insert(&value);
        assert_ne!(binary.to_bytes(), bsim.to_bytes());
        assert!(!binary.possibly_contains(&synthetic_value(b"different", 1)));
    }

    #[test]
    fn sizing_matches_documented_three_million_case() {
        let filter = ReferenceBloom::with_rate("function-full-hash", 3_000_000, 1e-6).unwrap();
        assert_eq!(filter.bit_count(), 86_265_528);
        assert_eq!(filter.hash_function_count(), 20);
        assert_eq!(filter.to_bytes().len(), 10_783_241);
    }

    #[test]
    fn sizing_matches_every_documented_scale_and_probability() {
        let cases = [
            (3_000_000, 1e-4, 7_188_794, 13),
            (30_000_000, 1e-4, 71_887_938, 13),
            (300_000_000, 1e-4, 718_879_379, 13),
            (3_000_000, 1e-6, 10_783_191, 20),
            (30_000_000, 1e-6, 107_831_907, 20),
            (300_000_000, 1e-6, 1_078_319_068, 20),
            (3_000_000, 1e-9, 16_174_787, 30),
            (30_000_000, 1e-9, 161_747_861, 30),
            (300_000_000, 1e-9, 1_617_478_602, 30),
        ];
        for (unique_values, probability, expected_bytes, expected_hashes) in cases {
            let (bits, hashes) = calculate_sizing(unique_values, probability).unwrap();
            assert_eq!(bits / 8, expected_bytes);
            assert_eq!(hashes, expected_hashes);
        }
    }

    #[test]
    fn empty_filter_is_explicit_and_negative() {
        let filter = ReferenceBloom::with_rate("fidbf-sha256", 0, 1e-6).unwrap();
        assert_eq!(filter.bit_count(), 8);
        assert!(!filter.possibly_contains(&[0; 32]));
        assert_eq!(
            ReferenceBloom::from_bytes(&filter.to_bytes()).unwrap(),
            filter
        );
    }

    #[test]
    fn strict_parser_rejects_corruption_truncation_and_trailing_data() {
        let mut filter = ReferenceBloom::with_rate("provenance-sha256", 10, 1e-4).unwrap();
        filter.insert(&synthetic_value(b"inserted", 1));
        let payload = filter.to_bytes();
        assert_eq!(ReferenceBloom::from_bytes(&payload).unwrap(), filter);

        let mut wrong_magic = payload.clone();
        wrong_magic[0] ^= 1;
        assert_eq!(
            ReferenceBloom::from_bytes(&wrong_magic),
            Err(BloomError::InvalidPayload("wrong magic"))
        );
        assert!(ReferenceBloom::from_bytes(&payload[..payload.len() - 1]).is_err());
        let mut trailing = payload;
        trailing.push(0);
        assert_eq!(
            ReferenceBloom::from_bytes(&trailing),
            Err(BloomError::InvalidPayload("trailing or missing bytes"))
        );
    }

    #[test]
    fn reference_payload_has_a_golden_digest() {
        let mut filter = ReferenceBloom::with_rate("binary-sha256", 3, 1e-4).unwrap();
        for index in 0..3 {
            filter.insert(&synthetic_value(b"golden", index));
        }
        assert_eq!(
            filter.payload_sha256().to_string(),
            "332f2160a98abf723401495606cbb1069adf0084b3134824bb3ae4ee07635cb1"
        );
    }

    #[test]
    fn manifest_signature_covers_every_core_field() {
        let manifest = example_manifest([0x22; 32]);
        let digest = manifest.signed_digest();
        assert_eq!(
            digest.to_string(),
            "95ca09201eb8b67cd860ee7be4258c2f200006d574643101b2c445f32274d2ff"
        );

        let signer = SystemSigner::from_seed([0x5a; 32]);
        let signature = signer.sign_digest(b"relic-bloom-manifest-signature-v1", &digest);
        verify_digest_signature(
            &signer.verifying_key(),
            b"relic-bloom-manifest-signature-v1",
            &digest,
            &signature,
        )
        .unwrap();

        let mut changed_manifests = Vec::new();
        macro_rules! changed {
            ($field:ident, $value:expr) => {{
                let mut changed = manifest.clone();
                changed.$field = $value;
                changed_manifests.push(changed);
            }};
        }
        changed!(format, "other-format".to_owned());
        changed!(format_version, manifest.format_version + 1);
        changed!(namespace, "fidbf-sha256".to_owned());
        changed!(checkpoint_id, manifest.checkpoint_id + 1);
        changed!(integrity_chain_head, [0x12; 32]);
        changed!(mmr_leaf_count, manifest.mmr_leaf_count + 1);
        changed!(entry_count, manifest.entry_count + 1);
        changed!(unique_value_count, manifest.unique_value_count + 1);
        changed!(bit_count, manifest.bit_count + 8);
        changed!(
            hash_function_count,
            manifest.hash_function_count.saturating_sub(1)
        );
        changed!(target_false_positive_probability, "0.0001".to_owned());
        changed!(hash_algorithm, "other-hash".to_owned());
        changed!(domain, "other-domain".to_owned());
        changed!(payload_sha256, [0x23; 32]);
        changed!(built_at, "2026-01-01T00:00:01.000000Z".to_owned());
        changed!(builder_version, "1".repeat(40));
        changed!(system_uid, [0x02; 16]);

        for changed in changed_manifests {
            assert_ne!(changed.signed_digest(), digest);
            assert!(
                verify_digest_signature(
                    &signer.verifying_key(),
                    b"relic-bloom-manifest-signature-v1",
                    &changed.signed_digest(),
                    &signature,
                )
                .is_err()
            );
        }
    }

    #[test]
    fn invalid_namespace_and_sizing_are_rejected() {
        assert!(ReferenceBloom::with_rate("", 1, 1e-6).is_err());
        assert!(ReferenceBloom::with_rate("Binary SHA256", 1, 1e-6).is_err());
        assert!(ReferenceBloom::with_rate("binary-sha256", 1, 0.0).is_err());
        assert!(ReferenceBloom::with_rate("binary-sha256", 1, 1.0).is_err());
        assert!(ReferenceBloom::with_rate("binary-sha256", u64::MAX, 1e-9).is_err());
    }

    #[test]
    #[ignore = "local synthetic timing diagnostic, not a portable benchmark"]
    fn synthetic_three_million_report() {
        let mut filter = ReferenceBloom::with_rate("function-full-hash", 3_000_000, 1e-6)
            .expect("bounded synthetic filter");
        let started = Instant::now();
        for index in 0..3_000_000 {
            filter.insert(&synthetic_value(b"three-million", index)[..8]);
        }
        let elapsed = started.elapsed();
        for index in 0..3_000_000 {
            assert!(filter.possibly_contains(&synthetic_value(b"three-million", index)[..8]));
        }
        eprintln!(
            "synthetic only: inserted 3,000,000 values in {elapsed:?}; payload={} bytes",
            filter.to_bytes().len()
        );
    }
}
