//! Signed `BSim` objects and provenance seals: canonical formats, signing and
//! admission.
//!
//! The Analyst signs the object's exact JSON text by its SHA-256 and MD5,
//! together with its identity and links. `PostgreSQL` stores that text
//! verbatim and checks that the stored digests are its digests, so a row
//! rebuilds to exactly the signed record. Each admission appends one
//! integrity-chain entry, in the same transaction.

use chrono::{DateTime, Utc};
use md5::{Digest as _, Md5};
use postgres::Transaction;
use relic_crypto::{SystemSigner, encode_fields, sha256, verify_digest_signature};
use relic_integrity_worker::{
    BsimRecord, ProvenanceRecord, bsim_record_hash, provenance_record_hash,
};
use relic_object_worker::CompatibilityMd5;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    IngestError, SignatureHex, append_integrity_entry, database_clock, encode_optional,
    lock_sequencer, verify_database_identity,
};

/// Record domain of an Analyst's `BSim` object.
pub const BSIM_RECORD_DOMAIN: &[u8] = b"RELIC:analyst-bsim:v1";
/// Signature domain of an Analyst's `BSim` object.
pub const BSIM_SIGNATURE_DOMAIN: &[u8] = b"RELIC:analyst-bsim-signature:v1";
/// Record domain of an Analyst's provenance seal.
pub const PROVENANCE_RECORD_DOMAIN: &[u8] = b"RELIC:analyst-provenance:v1";
/// Signature domain of an Analyst's provenance seal.
pub const PROVENANCE_SIGNATURE_DOMAIN: &[u8] = b"RELIC:analyst-provenance-signature:v1";

/// Largest object JSON accepted, in bytes.
pub const MAX_OBJECT_JSON_BYTES: usize = 2 * 1024 * 1024;
/// Most function links one `BSim` object may carry.
pub const MAX_BSIM_FUNCTIONS: usize = 10_000;

/// One function occurrence a `BSim` object describes.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub struct FunctionLink {
    pub function_id: Uuid,
    pub binary_id: Uuid,
}

/// The body of `POST /v1/bsim`.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BsimSubmission {
    pub bsim_id: Uuid,
    pub analyst_id: Uuid,
    pub source_id: Uuid,
    /// The `BSim` object: a JSON object, signed and stored as this exact text.
    pub object_json: String,
    pub functions: Vec<FunctionLink>,
    pub signature: SignatureHex,
}

/// The body of `POST /v1/provenance`.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProvenanceSubmission {
    pub provenance_id: Uuid,
    pub analyst_id: Uuid,
    pub source_id: Uuid,
    #[serde(default)]
    pub fidbf_id: Option<Uuid>,
    #[serde(default)]
    pub bsim_id: Option<Uuid>,
    #[serde(default)]
    pub binary_id: Option<Uuid>,
    #[serde(default)]
    pub schema_name: Option<String>,
    #[serde(default)]
    pub schema_version: Option<String>,
    /// The seal: a JSON object, signed and stored as this exact text.
    pub object_json: String,
    pub signature: SignatureHex,
}

/// Lowercase hex SHA-256 and MD5 of an object's exact text.
#[must_use]
pub fn object_digests(object_json: &str) -> (String, String) {
    (
        sha256(object_json.as_bytes()).to_string(),
        CompatibilityMd5::from_bytes(Md5::digest(object_json.as_bytes()).into()).to_string(),
    )
}

/// Canonical bytes of a `BSim` object. The links are sorted (each is the 16
/// function-ID bytes then the 16 binary-ID bytes), so their order does not
/// matter.
#[must_use]
pub fn bsim_record(
    bsim_id: Uuid,
    analyst_id: Uuid,
    source_id: Uuid,
    sha256_hex: &str,
    md5_hex: &str,
    functions: &[FunctionLink],
) -> Vec<u8> {
    let mut links: Vec<[u8; 32]> = functions
        .iter()
        .map(|link| {
            let mut bytes = [0_u8; 32];
            bytes[..16].copy_from_slice(link.function_id.as_bytes());
            bytes[16..].copy_from_slice(link.binary_id.as_bytes());
            bytes
        })
        .collect();
    links.sort_unstable();
    encode_fields(
        BSIM_RECORD_DOMAIN,
        &[
            bsim_id.as_bytes(),
            analyst_id.as_bytes(),
            source_id.as_bytes(),
            sha256_hex.as_bytes(),
            md5_hex.as_bytes(),
            &links.concat(),
        ],
    )
}

/// Canonical bytes of a provenance seal.
#[allow(clippy::too_many_arguments)]
#[must_use]
pub fn provenance_record(
    provenance_id: Uuid,
    analyst_id: Uuid,
    source_id: Uuid,
    fidbf_id: Option<Uuid>,
    bsim_id: Option<Uuid>,
    binary_id: Option<Uuid>,
    schema_name: Option<&str>,
    schema_version: Option<&str>,
    sha256_hex: &str,
    md5_hex: &str,
) -> Vec<u8> {
    let optional_id =
        |id: Option<Uuid>| id.map_or_else(|| vec![0], |id| [&[1][..], id.as_bytes()].concat());
    encode_fields(
        PROVENANCE_RECORD_DOMAIN,
        &[
            provenance_id.as_bytes(),
            analyst_id.as_bytes(),
            source_id.as_bytes(),
            &optional_id(fidbf_id),
            &optional_id(bsim_id),
            &optional_id(binary_id),
            &encode_optional(schema_name),
            &encode_optional(schema_version),
            sha256_hex.as_bytes(),
            md5_hex.as_bytes(),
        ],
    )
}

impl BsimSubmission {
    /// The canonical record this submission's signature covers.
    #[must_use]
    pub fn record(&self) -> Vec<u8> {
        let (sha256_hex, md5_hex) = object_digests(&self.object_json);
        bsim_record(
            self.bsim_id,
            self.analyst_id,
            self.source_id,
            &sha256_hex,
            &md5_hex,
            &self.functions,
        )
    }

    /// Sign on the Analyst's machine (`signature` is replaced).
    #[must_use]
    pub fn signed(mut self, signer: &SystemSigner) -> Self {
        self.signature = SignatureHex::from_bytes(
            signer.sign_digest(BSIM_SIGNATURE_DOMAIN, &sha256(&self.record())),
        );
        self
    }

    fn validate(&self) -> Result<(), IngestError> {
        validate_object_json(&self.object_json)?;
        if self.functions.is_empty() || self.functions.len() > MAX_BSIM_FUNCTIONS {
            return Err(IngestError::Validation(format!(
                "a BSim object links 1 to {MAX_BSIM_FUNCTIONS} functions"
            )));
        }
        let mut sorted = self.functions.clone();
        sorted.sort_unstable();
        sorted.dedup();
        if sorted.len() != self.functions.len() {
            return Err(IngestError::Validation(
                "function links must be distinct".into(),
            ));
        }
        Ok(())
    }
}

impl ProvenanceSubmission {
    /// The canonical record this submission's signature covers.
    #[must_use]
    pub fn record(&self) -> Vec<u8> {
        let (sha256_hex, md5_hex) = object_digests(&self.object_json);
        provenance_record(
            self.provenance_id,
            self.analyst_id,
            self.source_id,
            self.fidbf_id,
            self.bsim_id,
            self.binary_id,
            self.schema_name.as_deref(),
            self.schema_version.as_deref(),
            &sha256_hex,
            &md5_hex,
        )
    }

    /// Sign on the Analyst's machine (`signature` is replaced).
    #[must_use]
    pub fn signed(mut self, signer: &SystemSigner) -> Self {
        self.signature = SignatureHex::from_bytes(
            signer.sign_digest(PROVENANCE_SIGNATURE_DOMAIN, &sha256(&self.record())),
        );
        self
    }

    fn validate(&self) -> Result<(), IngestError> {
        validate_object_json(&self.object_json)?;
        if self.fidbf_id.is_none() && self.bsim_id.is_none() && self.binary_id.is_none() {
            return Err(IngestError::Validation(
                "provenance names a FIDBF, BSim object or binary".into(),
            ));
        }
        for (field, value) in [
            ("schema_name", &self.schema_name),
            ("schema_version", &self.schema_version),
        ] {
            if value.as_deref().is_some_and(|text| text.trim().is_empty()) {
                return Err(IngestError::Validation(format!(
                    "{field} must not be blank"
                )));
            }
        }
        Ok(())
    }
}

fn validate_object_json(object_json: &str) -> Result<(), IngestError> {
    if object_json.len() > MAX_OBJECT_JSON_BYTES {
        return Err(IngestError::Validation(format!(
            "object_json is larger than {MAX_OBJECT_JSON_BYTES} bytes"
        )));
    }
    // PostgreSQL text and jsonb cannot hold NUL, raw or escaped.
    if object_json.contains('\0') || object_json.contains("\\u0000") {
        return Err(IngestError::Validation(
            "object_json must not contain NUL characters".into(),
        ));
    }
    match serde_json::from_str::<serde_json::Value>(object_json) {
        Ok(value) if value.is_object() => Ok(()),
        _ => Err(IngestError::Validation(
            "object_json must be a JSON object".into(),
        )),
    }
}

fn verify_signature(
    public_key: &[u8; 32],
    domain: &[u8],
    record: &[u8],
    signature: &SignatureHex,
    part: &'static str,
) -> Result<(), IngestError> {
    verify_digest_signature(public_key, domain, &sha256(record), signature.as_bytes())
        .map_err(|_| IngestError::InvalidAnalystSignature(part))
}

/// Database identities and digests returned after an admission.
#[derive(Clone, Debug, Serialize)]
pub struct ObjectAdmission {
    pub id: Uuid,
    pub sha256: String,
    pub md5: String,
    pub created_at: DateTime<Utc>,
    pub integrity_id: i64,
    pub chain_hash: String,
}

fn source_type(transaction: &mut Transaction<'_>, source_id: Uuid) -> Result<String, IngestError> {
    transaction
        .query_opt(
            "SELECT source_type FROM catalogue.source WHERE source_id = $1",
            &[&source_id],
        )
        .map_err(IngestError::Database)?
        .map(|row| row.get(0))
        .ok_or_else(|| IngestError::Validation(format!("unknown source {source_id}")))
}

/// Verify and admit one `BSim` object, its function links and its integrity
/// entry inside the caller's `SERIALIZABLE` transaction.
///
/// # Errors
///
/// Returns an error for malformed input, an unknown, revoked or non-Analyst
/// submitter, a bad signature, an integrity identity/key mismatch or a
/// database error (including unknown or revoked links and sources).
pub fn admit_bsim(
    transaction: &mut Transaction<'_>,
    submission: &BsimSubmission,
    integrity_system_user_id: Uuid,
    integrity_signer: &SystemSigner,
) -> Result<ObjectAdmission, IngestError> {
    submission.validate()?;
    lock_sequencer(transaction)?;
    let analyst_key = verify_database_identity(
        transaction,
        submission.analyst_id,
        "human",
        Some("analyst"),
        None,
    )?;
    verify_signature(
        &analyst_key,
        BSIM_SIGNATURE_DOMAIN,
        &submission.record(),
        &submission.signature,
        "BSim",
    )?;
    verify_database_identity(
        transaction,
        integrity_system_user_id,
        "system",
        None,
        Some(&integrity_signer.verifying_key()),
    )?;
    let source_type = source_type(transaction, submission.source_id)?;
    let (sha256_hex, md5_hex) = object_digests(&submission.object_json);
    let (accepted_at, accepted_at_micros) = database_clock(transaction)?;
    let signature = &submission.signature.as_bytes()[..];
    transaction
        .execute(
            "INSERT INTO catalogue.bsim
                (bsim_id, object_data, object_json, sha256, md5, created_at,
                 submitted_by_user_id, signature, source_id)
             VALUES ($1, CAST($2 AS text)::jsonb, $2,
                     CAST($3 AS text)::catalogue.sha256_hex,
                     CAST($4 AS text)::catalogue.md5_hex, $5, $6, $7, $8)",
            &[
                &submission.bsim_id,
                &submission.object_json,
                &sha256_hex,
                &md5_hex,
                &accepted_at,
                &submission.analyst_id,
                &signature,
                &submission.source_id,
            ],
        )
        .map_err(IngestError::Database)?;
    for link in &submission.functions {
        transaction
            .execute(
                "INSERT INTO catalogue.function_bsim (function_id, binary_id, bsim_id, created_at)
                 VALUES ($1, $2, $3, $4)",
                &[
                    &link.function_id,
                    &link.binary_id,
                    &submission.bsim_id,
                    &accepted_at,
                ],
            )
            .map_err(IngestError::Database)?;
    }
    let record_hash = bsim_record_hash(&BsimRecord {
        bsim_id: submission.bsim_id,
        source_id: submission.source_id,
        sha256: &sha256_hex,
        md5: &md5_hex,
        created_at_micros: accepted_at_micros,
        submitter: submission.analyst_id,
        signature,
    });
    let (integrity_id, chain_hash) = append_integrity_entry(
        transaction,
        submission.source_id,
        &source_type,
        record_hash,
        accepted_at,
        accepted_at_micros,
        integrity_system_user_id,
        integrity_signer,
    )?;
    Ok(ObjectAdmission {
        id: submission.bsim_id,
        sha256: sha256_hex,
        md5: md5_hex,
        created_at: accepted_at,
        integrity_id,
        chain_hash,
    })
}

/// Verify and admit one provenance seal and its integrity entry inside the
/// caller's `SERIALIZABLE` transaction.
///
/// # Errors
///
/// As [`admit_bsim`].
pub fn admit_provenance(
    transaction: &mut Transaction<'_>,
    submission: &ProvenanceSubmission,
    integrity_system_user_id: Uuid,
    integrity_signer: &SystemSigner,
) -> Result<ObjectAdmission, IngestError> {
    submission.validate()?;
    lock_sequencer(transaction)?;
    let analyst_key = verify_database_identity(
        transaction,
        submission.analyst_id,
        "human",
        Some("analyst"),
        None,
    )?;
    verify_signature(
        &analyst_key,
        PROVENANCE_SIGNATURE_DOMAIN,
        &submission.record(),
        &submission.signature,
        "provenance",
    )?;
    verify_database_identity(
        transaction,
        integrity_system_user_id,
        "system",
        None,
        Some(&integrity_signer.verifying_key()),
    )?;
    let source_type = source_type(transaction, submission.source_id)?;
    let (sha256_hex, md5_hex) = object_digests(&submission.object_json);
    let (accepted_at, accepted_at_micros) = database_clock(transaction)?;
    let signature = &submission.signature.as_bytes()[..];
    transaction
        .execute(
            "INSERT INTO catalogue.provenance
                (provenance_id, fidbf_id, bsim_id, binary_id, schema_name, schema_version,
                 object_data, object_json, sha256, md5, created_at, submitted_by_user_id,
                 signature, source_id)
             VALUES ($1, $2, $3, $4, $5, $6, CAST($7 AS text)::jsonb, $7,
                     CAST($8 AS text)::catalogue.sha256_hex,
                     CAST($9 AS text)::catalogue.md5_hex, $10, $11, $12, $13)",
            &[
                &submission.provenance_id,
                &submission.fidbf_id,
                &submission.bsim_id,
                &submission.binary_id,
                &submission.schema_name,
                &submission.schema_version,
                &submission.object_json,
                &sha256_hex,
                &md5_hex,
                &accepted_at,
                &submission.analyst_id,
                &signature,
                &submission.source_id,
            ],
        )
        .map_err(IngestError::Database)?;
    let record_hash = provenance_record_hash(&ProvenanceRecord {
        provenance_id: submission.provenance_id,
        source_id: submission.source_id,
        sha256: &sha256_hex,
        md5: &md5_hex,
        created_at_micros: accepted_at_micros,
        submitter: submission.analyst_id,
        signature,
    });
    let (integrity_id, chain_hash) = append_integrity_entry(
        transaction,
        submission.source_id,
        &source_type,
        record_hash,
        accepted_at,
        accepted_at_micros,
        integrity_system_user_id,
        integrity_signer,
    )?;
    Ok(ObjectAdmission {
        id: submission.provenance_id,
        sha256: sha256_hex,
        md5: md5_hex,
        created_at: accepted_at,
        integrity_id,
        chain_hash,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn link(byte: u8) -> FunctionLink {
        FunctionLink {
            function_id: Uuid::from_bytes([byte; 16]),
            binary_id: Uuid::from_bytes([byte.wrapping_add(1); 16]),
        }
    }

    #[test]
    fn bsim_record_does_not_depend_on_link_order() {
        let id = Uuid::from_bytes([7; 16]);
        let forward = bsim_record(id, id, id, "aa", "bb", &[link(1), link(9)]);
        let reverse = bsim_record(id, id, id, "aa", "bb", &[link(9), link(1)]);
        assert_eq!(forward, reverse);
        assert_ne!(forward, bsim_record(id, id, id, "aa", "bb", &[link(1)]));
    }

    #[test]
    fn signed_submissions_verify_and_alterations_do_not() {
        let signer = SystemSigner::from_seed([3; 32]);
        let key = signer.verifying_key();
        let bsim = BsimSubmission {
            bsim_id: Uuid::from_bytes([1; 16]),
            analyst_id: Uuid::from_bytes([2; 16]),
            source_id: Uuid::from_bytes([3; 16]),
            object_json: "{\"b\": 1,  \"a\": [2]}".into(),
            functions: vec![link(4)],
            signature: SignatureHex::from_bytes([0; 64]),
        }
        .signed(&signer);
        let check = |submission: &BsimSubmission| {
            verify_signature(
                &key,
                BSIM_SIGNATURE_DOMAIN,
                &submission.record(),
                &submission.signature,
                "BSim",
            )
        };
        assert!(check(&bsim).is_ok());
        let mut altered = bsim.clone();
        altered.object_json = "{\"a\": [2], \"b\": 1}".into(); // same value, other text
        assert!(check(&altered).is_err());
        let mut extra_link = bsim.clone();
        extra_link.functions.push(link(8));
        assert!(check(&extra_link).is_err());

        let provenance = ProvenanceSubmission {
            provenance_id: Uuid::from_bytes([5; 16]),
            analyst_id: Uuid::from_bytes([2; 16]),
            source_id: Uuid::from_bytes([3; 16]),
            fidbf_id: None,
            bsim_id: Some(Uuid::from_bytes([1; 16])),
            binary_id: None,
            schema_name: Some("ocsf".into()),
            schema_version: None,
            object_json: "{\"class_uid\": 5020}".into(),
            signature: SignatureHex::from_bytes([0; 64]),
        }
        .signed(&signer);
        let record = provenance.record();
        assert!(
            verify_signature(
                &key,
                PROVENANCE_SIGNATURE_DOMAIN,
                &record,
                &provenance.signature,
                "p"
            )
            .is_ok()
        );
        let mut moved = provenance;
        moved.binary_id = moved.bsim_id.take();
        assert_ne!(moved.record(), record);
    }

    #[test]
    fn object_json_must_be_an_object() {
        assert!(validate_object_json("{}").is_ok());
        for bad in [
            "[]",
            "1",
            "not json",
            "{\"a\":\"\\u0000\"}",
            "{\"a\":\"\u{0}\"}",
        ] {
            assert!(validate_object_json(bad).is_err(), "{bad}");
        }
    }
}
