//! Deterministic integrity-chain calculation and signing.
//!
//! Database adapters perform tip locking and integrity insertion in one
//! transaction. Private-key loading remains in the producing CLI process.

use std::{collections::HashSet, str::FromStr};

use chrono::{DateTime, Utc};
use postgres::{Client, IsolationLevel};
use relic_crypto::{Digest32, SystemSigner, hash_fields, verify_digest_signature};
use thiserror::Error;
use uuid::Uuid;

/// The chain-hash definition lives in the database-free `relic-proof` crate,
/// so an offline verifier recomputes exactly what this worker signs.
pub use relic_proof::IntegrityEnvelope;

const SIGNATURE_DOMAIN: &[u8] = b"RELIC:integrity-system-signature:v1";
const BSIM_RECORD_DOMAIN: &[u8] = b"RELIC:bsim-record:v1";
const PROVENANCE_RECORD_DOMAIN: &[u8] = b"RELIC:provenance-record:v1";

/// The stored `BSim` fields an integrity entry commits to.
#[derive(Clone, Copy, Debug)]
pub struct BsimRecord<'a> {
    pub bsim_id: Uuid,
    pub source_id: Uuid,
    /// Lowercase hex, exactly as stored.
    pub sha256: &'a str,
    pub md5: &'a str,
    pub created_at_micros: i64,
    pub submitter: Uuid,
    pub signature: &'a [u8],
}

/// The integrity-chain `record_hash` of a `BSim` object.
#[must_use]
pub fn bsim_record_hash(record: &BsimRecord<'_>) -> Digest32 {
    hash_fields(
        BSIM_RECORD_DOMAIN,
        &[
            record.bsim_id.as_bytes(),
            record.source_id.as_bytes(),
            record.sha256.as_bytes(),
            record.md5.as_bytes(),
            &record.created_at_micros.to_be_bytes(),
            record.submitter.as_bytes(),
            record.signature,
        ],
    )
}

/// The stored provenance fields an integrity entry commits to.
#[derive(Clone, Copy, Debug)]
pub struct ProvenanceRecord<'a> {
    pub provenance_id: Uuid,
    pub source_id: Uuid,
    /// Lowercase hex, exactly as stored.
    pub sha256: &'a str,
    pub md5: &'a str,
    pub created_at_micros: i64,
    pub submitter: Uuid,
    pub signature: &'a [u8],
}

/// The integrity-chain `record_hash` of a provenance seal.
#[must_use]
pub fn provenance_record_hash(record: &ProvenanceRecord<'_>) -> Digest32 {
    hash_fields(
        PROVENANCE_RECORD_DOMAIN,
        &[
            record.provenance_id.as_bytes(),
            record.source_id.as_bytes(),
            record.sha256.as_bytes(),
            record.md5.as_bytes(),
            &record.created_at_micros.to_be_bytes(),
            record.submitter.as_bytes(),
            record.signature,
        ],
    )
}

/// Complete integrity entry ready for atomic insertion.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedIntegrityEntry {
    /// Fields included in the chain hash.
    pub envelope: IntegrityEnvelope,
    /// Domain-separated chain hash.
    pub chain_hash: Digest32,
    /// Ed25519 signature made by the integrity system identity.
    pub system_signature: [u8; 64],
}

impl SignedIntegrityEntry {
    /// Strictly verify the chain hash and its signature.
    ///
    /// # Errors
    ///
    /// Returns an error if the canonical envelope hash differs from the stored
    /// chain hash, or if the system signature is invalid.
    pub fn verify(&self, verifying_key: &[u8; 32]) -> Result<(), VerificationError> {
        if self.envelope.chain_hash() != self.chain_hash {
            return Err(VerificationError::ChainHashMismatch);
        }
        verify_digest_signature(
            verifying_key,
            SIGNATURE_DOMAIN,
            &self.chain_hash,
            &self.system_signature,
        )
        .map_err(|_| VerificationError::InvalidSignature)
    }
}

/// Build and sign an integrity entry after the database tip has been locked.
#[must_use]
pub fn sign_entry(envelope: IntegrityEnvelope, signer: &SystemSigner) -> SignedIntegrityEntry {
    let chain_hash = envelope.chain_hash();
    let system_signature = signer.sign_digest(SIGNATURE_DOMAIN, &chain_hash);
    SignedIntegrityEntry {
        envelope,
        chain_hash,
        system_signature,
    }
}

/// Summary of a `BSim` integrity reconciliation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BsimChainResult {
    pub inserted: usize,
    pub last_integrity_id: Option<i64>,
    pub chain_tip: Option<String>,
}

/// Append one real, system-signed integrity entry for every `BSim` row not yet
/// represented by its canonical record hash.
///
/// This is a legacy reconciliation path for `BSim` objects that were admitted
/// before atomic `BSim` ingestion existed. It never inserts or changes a `BSim`.
///
/// # Errors
///
/// Returns without commit if the chain, system identity, or database state is
/// invalid.
#[allow(clippy::too_many_lines)]
pub fn chain_uncovered_bsim_postgres(
    client: &mut Client,
    system_user_id: Uuid,
    signer: &SystemSigner,
) -> Result<BsimChainResult, BsimChainError> {
    let mut transaction = client
        .build_transaction()
        .isolation_level(IsolationLevel::Serializable)
        .start()?;
    transaction.query_one(
        "SELECT pg_advisory_xact_lock(hashtextextended('RELIC:integrity-sequencer:v1', 0))",
        &[],
    )?;

    let identity = transaction.query_opt(
        "SELECT owner_type::text, public_key,
                catalogue.account_is_revoked(user_id)
           FROM catalogue.user_public WHERE user_id = $1",
        &[&system_user_id],
    )?;
    let identity = identity.ok_or(BsimChainError::UnknownSystemIdentity)?;
    let owner_type: String = identity.get(0);
    let public_key: Vec<u8> = identity.get(1);
    let revoked: bool = identity.get(2);
    if owner_type != "system" || revoked || public_key.as_slice() != signer.verifying_key() {
        return Err(BsimChainError::SystemIdentityMismatch);
    }

    let covered = transaction
        .query("SELECT record_hash::text FROM catalogue.integrity", &[])?
        .into_iter()
        .map(|row| row.get::<_, String>(0))
        .collect::<HashSet<_>>();
    let rows = transaction.query(
        "SELECT b.bsim_id, b.source_id, s.source_type, b.sha256::text,
                b.md5::text, b.created_at, b.submitted_by_user_id, b.signature
           FROM catalogue.bsim AS b
           JOIN catalogue.source AS s USING (source_id)
          ORDER BY b.created_at, b.bsim_id",
        &[],
    )?;

    let mut previous = transaction
        .query_opt(
            "SELECT integrity_id, chain_hash::text
               FROM catalogue.integrity ORDER BY integrity_id DESC LIMIT 1",
            &[],
        )?
        .map(|row| {
            let integrity_id: i64 = row.get(0);
            let digest = Digest32::from_str(&row.get::<_, String>(1))
                .map_err(|_| BsimChainError::MalformedChainTip)?;
            Ok::<_, BsimChainError>((integrity_id, digest))
        })
        .transpose()?;
    let mut inserted = 0_usize;

    for row in rows {
        let bsim_id: Uuid = row.get(0);
        let source_id: Uuid = row.get(1);
        let source_type: String = row.get(2);
        let sha256: String = row.get(3);
        let md5: String = row.get(4);
        let created_at: DateTime<Utc> = row.get(5);
        let submitter: Uuid = row.get(6);
        let signature: Vec<u8> = row.get(7);
        let record_hash = bsim_record_hash(&BsimRecord {
            bsim_id,
            source_id,
            sha256: &sha256,
            md5: &md5,
            created_at_micros: created_at.timestamp_micros(),
            submitter,
            signature: &signature,
        });
        if covered.contains(&record_hash.to_string()) {
            continue;
        }

        let accepted_at_micros: i64 = transaction
            .query_one(
                "SELECT (extract(epoch FROM clock_timestamp()) * 1000000)::bigint",
                &[],
            )?
            .get(0);
        let accepted_at = DateTime::<Utc>::from_timestamp_micros(accepted_at_micros)
            .ok_or(BsimChainError::TimestampOutOfRange(accepted_at_micros))?;
        let entry = sign_entry(
            IntegrityEnvelope {
                source_id: source_id.to_string(),
                source_type: source_type.clone(),
                record_hash,
                prev_hash: previous.map(|(_, digest)| digest),
                format_version: 1,
                created_at_unix_micros: accepted_at_micros,
                system_uid: system_user_id.to_string(),
            },
            signer,
        );
        entry
            .verify(&signer.verifying_key())
            .map_err(|_| BsimChainError::GeneratedEntryInvalid)?;
        let integrity_id: i64 = transaction
            .query_one(
                "INSERT INTO catalogue.integrity
                (source_id, source_type, record_hash, prev_hash, chain_hash,
                 format_version, created_at, system_signature, system_uid)
             VALUES ($1,$2,CAST($3 AS text)::catalogue.sha256_hex,
                     CAST($4 AS text)::catalogue.sha256_hex,
                     CAST($5 AS text)::catalogue.sha256_hex,1,$6,$7,$8)
             RETURNING integrity_id",
                &[
                    &source_id,
                    &source_type,
                    &entry.envelope.record_hash.to_string(),
                    &entry.envelope.prev_hash.map(|digest| digest.to_string()),
                    &entry.chain_hash.to_string(),
                    &accepted_at,
                    &&entry.system_signature[..],
                    &system_user_id,
                ],
            )?
            .get(0);
        previous = Some((integrity_id, entry.chain_hash));
        inserted += 1;
    }

    transaction.commit()?;
    Ok(BsimChainResult {
        inserted,
        last_integrity_id: previous.map(|(id, _)| id),
        chain_tip: previous.map(|(_, digest)| digest.to_string()),
    })
}

/// A `PostgreSQL` error with the server's code, message and detail.
///
/// `postgres::Error`'s own text is only "db error" for server-side errors,
/// which hides the cause (e.g. a permission or constraint violation).
#[must_use]
pub fn describe_db_error(error: &postgres::Error) -> String {
    error.as_db_error().map_or_else(
        || error.to_string(),
        |db| {
            let detail = db
                .detail()
                .map(|detail| format!(" ({detail})"))
                .unwrap_or_default();
            format!("{} {}{detail}", db.code().code(), db.message())
        },
    )
}

#[derive(Debug, Error)]
pub enum BsimChainError {
    #[error("database operation failed: {}", describe_db_error(.0))]
    Database(#[from] postgres::Error),
    #[error("integrity system identity does not exist")]
    UnknownSystemIdentity,
    #[error("integrity system identity is revoked, wrong type, or does not match the key")]
    SystemIdentityMismatch,
    #[error("integrity chain tip is malformed")]
    MalformedChainTip,
    #[error("database timestamp is outside the supported range: {0}")]
    TimestampOutOfRange(i64),
    #[error("generated integrity entry failed self-verification")]
    GeneratedEntryInvalid,
}

/// Integrity verification failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerificationError {
    /// Stored chain hash differs from the canonical envelope hash.
    ChainHashMismatch,
    /// Signature is not valid for the chain hash and public key.
    InvalidSignature,
}

#[cfg(test)]
mod tests {
    use relic_crypto::sha256;

    use super::*;

    fn envelope() -> IntegrityEnvelope {
        IntegrityEnvelope {
            source_id: "01950f2a-test".into(),
            source_type: "BSIM".into(),
            record_hash: sha256(b"canonical record"),
            prev_hash: Some(sha256(b"previous")),
            format_version: 1,
            created_at_unix_micros: 1_800_000_000_123_456,
            system_uid: "integrity-worker".into(),
        }
    }

    #[test]
    fn entry_is_deterministic_and_verifiable() {
        let signer = SystemSigner::from_seed([11; 32]);
        let first = sign_entry(envelope(), &signer);
        let second = sign_entry(envelope(), &signer);
        assert_eq!(first, second);
        assert_eq!(first.verify(&signer.verifying_key()), Ok(()));
    }

    #[test]
    fn every_envelope_field_is_committed() {
        let baseline = envelope().chain_hash();
        let mut changed = envelope();
        changed.source_id.push('x');
        assert_ne!(baseline, changed.chain_hash());

        let mut changed = envelope();
        changed.created_at_unix_micros += 1;
        assert_ne!(baseline, changed.chain_hash());

        let mut changed = envelope();
        changed.prev_hash = None;
        assert_ne!(baseline, changed.chain_hash());
    }

    #[test]
    fn tampering_is_rejected() {
        let signer = SystemSigner::from_seed([11; 32]);
        let mut entry = sign_entry(envelope(), &signer);
        entry.envelope.source_type = "FIDBF".into();
        assert_eq!(
            entry.verify(&signer.verifying_key()),
            Err(VerificationError::ChainHashMismatch)
        );
    }
}
