//! `relic-admit`: admit the submissions the API staged.
//!
//! The API never holds the integrity key. It stores each signed FIDBF, `BSim`
//! or provenance submission in `catalogue.submission` (and a FIDBF object in
//! the staging directory). This worker, on the host as `relic_worker` with
//! the integrity key, takes one pending submission at a time and, in one
//! `SERIALIZABLE` transaction, verifies and admits it with its integrity
//! entry and marks it admitted, or marks it rejected with the reason.
//!
//! Everything read from the submission or the staging directory is treated
//! as untrusted: the API that wrote it may be compromised. Signatures are
//! verified here, the submission must name its own object and Analyst, and
//! staged files are opened without following links.

use std::{
    collections::HashSet,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    time::{Duration, SystemTime},
};

use md5::{Digest as _, Md5};
use postgres::{Client, IsolationLevel, Transaction};
use relic_crypto::SystemSigner;
use relic_object_worker::CompatibilityMd5;
use serde_json::{Value, json};
use sha2::Sha256;
use uuid::Uuid;

use crate::{
    IngestError, SignedFidbfIngestManifest, admit_fidbf,
    objects::{BsimSubmission, ProvenanceSubmission, admit_bsim, admit_provenance},
};

/// Where an admitted FIDBF object lives, relative to the object root.
///
/// Content-addressed, so the path in the signed manifest is fixed by the
/// object's digest and the Analyst can sign it before uploading.
#[must_use]
pub fn canonical_fidbf_storage_path(sha256_hex: &str) -> String {
    format!(
        "{}/{sha256_hex}.fidbf",
        &sha256_hex[..2.min(sha256_hex.len())]
    )
}

/// How the worker finds the integrity key and the object directories.
pub struct AdmitConfig<'a> {
    pub staging_dir: &'a Path,
    pub fidbf_root: &'a Path,
    pub integrity_system_user_id: Uuid,
    pub integrity_signer: &'a SystemSigner,
    pub max_object_bytes: u64,
    /// Transient failures (lost serialization, I/O) before a submission is
    /// rejected anyway.
    pub max_attempts: i32,
}

/// What happened to one submission.
#[derive(Debug)]
pub enum Outcome {
    Admitted(Value),
    /// `reason` is stored and shown to the submitter; `detail` is for the
    /// worker's log only (it may name rows the submitter did not).
    Rejected {
        reason: String,
        detail: String,
    },
    /// Left pending after a transient failure.
    Retry {
        reason: String,
        detail: String,
    },
}

/// The submission one call handled, or none left.
#[derive(Debug)]
pub struct Handled {
    pub submission_id: Uuid,
    pub kind: String,
    pub outcome: Outcome,
}

/// A failure: permanent ones reject the submission, transient ones retry it.
struct Failure {
    transient: bool,
    reason: String,
    detail: String,
}

impl Failure {
    fn permanent(reason: impl Into<String>) -> Self {
        let reason = reason.into();
        Self {
            transient: false,
            detail: reason.clone(),
            reason,
        }
    }

    fn transient(detail: impl Into<String>) -> Self {
        Self {
            transient: true,
            reason: "admission failed temporarily on the server".into(),
            detail: detail.into(),
        }
    }
}

impl From<IngestError> for Failure {
    fn from(error: IngestError) -> Self {
        let detail = error.to_string();
        let (transient, reason) = match &error {
            IngestError::Database(db) if is_transient(db) => (
                true,
                "admission failed temporarily on the server".to_owned(),
            ),
            // Only the message, never PostgreSQL's DETAIL (which can name
            // other rows); RELIC's own triggers write the messages.
            IngestError::Database(db) => (
                false,
                db.as_db_error().map_or_else(
                    || "rejected by the database".to_owned(),
                    |db| format!("rejected by the database: {}", db.message()),
                ),
            ),
            IngestError::Validation(message) => (false, format!("invalid submission: {message}")),
            IngestError::ObjectVerification(_) => (
                false,
                "the object does not match the manifest's digests".to_owned(),
            ),
            IngestError::InvalidAnalystSignature(part) => (
                false,
                format!("the {part} signature does not verify with the submitter's registered key"),
            ),
            // The integrity account is checked when relic-admit starts, so
            // an identity failure here is the submitter's.
            IngestError::UnknownIdentity(_)
            | IngestError::IdentityKindMismatch(_)
            | IngestError::RevokedIdentity(_)
            | IngestError::MalformedPublicKey(_) => (
                false,
                "the submitting account is not an active Analyst".to_owned(),
            ),
            IngestError::ObjectOpen { .. }
            | IngestError::IdentityKeyMismatch(_)
            | IngestError::TimestampOutOfRange(_)
            | IngestError::MalformedChainTip => (
                true,
                "admission failed temporarily on the server".to_owned(),
            ),
        };
        Self {
            transient,
            reason,
            detail,
        }
    }
}

/// Check, before taking any submission, that the integrity account exists, is
/// an active system account and matches the loaded key.
///
/// # Errors
///
/// Returns the identity problem; relic-admit refuses to start on it.
pub fn check_integrity_identity(
    client: &mut Client,
    integrity_system_user_id: Uuid,
    integrity_signer: &SystemSigner,
) -> Result<(), IngestError> {
    let mut transaction = client.transaction().map_err(IngestError::Database)?;
    crate::verify_database_identity(
        &mut transaction,
        integrity_system_user_id,
        "system",
        None,
        Some(&integrity_signer.verifying_key()),
    )?;
    transaction.commit().map_err(IngestError::Database)
}

fn is_transient(error: &postgres::Error) -> bool {
    error.as_db_error().is_none_or(|db| {
        // Class 40 (serialization failure, deadlock), 53 (resources),
        // 57 (operator intervention, e.g. shutdown), 08 (connection).
        let code = db.code().code();
        ["40", "53", "57", "08"]
            .iter()
            .any(|class| code.starts_with(class))
    })
}

/// Handle the oldest pending submission not in `skip`.
///
/// # Errors
///
/// Returns a database error only if the submission table itself cannot be
/// read or updated; a submission's own failures are recorded on it.
pub fn admit_next(
    client: &mut Client,
    config: &AdmitConfig<'_>,
    skip: &[Uuid],
) -> Result<Option<Handled>, postgres::Error> {
    let mut transaction = client
        .build_transaction()
        .isolation_level(IsolationLevel::Serializable)
        .start()?;
    let Some(row) = transaction.query_opt(
        "SELECT submission_id, kind::text, analyst_id, payload_json, object_sha256::text, attempts
           FROM catalogue.submission
          WHERE status = 'pending' AND submission_id <> ALL($1)
          ORDER BY received_at, submission_id
          LIMIT 1
          FOR UPDATE SKIP LOCKED",
        &[&skip],
    )?
    else {
        transaction.commit()?;
        return Ok(None);
    };
    let submission_id: Uuid = row.get(0);
    let kind: String = row.get(1);
    let analyst_id: Uuid = row.get(2);
    let payload: String = row.get(3);
    let object_sha256: Option<String> = row.get(4);
    let attempts: i32 = row.get(5);

    let admitted = admit_one(
        &mut transaction,
        config,
        &kind,
        submission_id,
        analyst_id,
        &payload,
        object_sha256.as_deref(),
    );
    let failure = match admitted {
        Ok(result) => {
            let recorded = transaction
                .execute(
                    "UPDATE catalogue.submission SET status = 'admitted', result = CAST($2 AS text)::jsonb
                      WHERE submission_id = $1",
                    &[&submission_id, &result.to_string()],
                )
                .and_then(|_| transaction.commit());
            match recorded {
                Ok(()) => {
                    if let Some(sha256) = object_sha256.as_deref() {
                        remove_staged_if_unused(client, config.staging_dir, sha256);
                    }
                    return Ok(Some(Handled {
                        submission_id,
                        kind,
                        outcome: Outcome::Admitted(result),
                    }));
                }
                Err(error) => Failure::from(IngestError::Database(error)),
            }
        }
        Err(failure) => {
            drop(transaction);
            failure
        }
    };

    let Failure {
        transient,
        reason,
        detail,
    } = failure;
    let outcome = if transient && attempts + 1 < config.max_attempts {
        client.execute(
            "UPDATE catalogue.submission SET attempts = attempts + 1
              WHERE submission_id = $1 AND status = 'pending'",
            &[&submission_id],
        )?;
        Outcome::Retry { reason, detail }
    } else {
        client.execute(
            "UPDATE catalogue.submission
                SET status = 'rejected', error = $2, attempts = attempts + 1
              WHERE submission_id = $1 AND status = 'pending'",
            &[&submission_id, &reason],
        )?;
        Outcome::Rejected { reason, detail }
    };
    Ok(Some(Handled {
        submission_id,
        kind,
        outcome,
    }))
}

fn admit_one(
    transaction: &mut Transaction<'_>,
    config: &AdmitConfig<'_>,
    kind: &str,
    submission_id: Uuid,
    analyst_id: Uuid,
    payload: &str,
    object_sha256: Option<&str>,
) -> Result<Value, Failure> {
    let mismatch = |what: &str| {
        Failure::permanent(format!(
            "the submission's {what} does not match its payload"
        ))
    };
    match kind {
        "fidbf" => {
            let manifest: SignedFidbfIngestManifest = parse(payload)?;
            let fidbf = &manifest.manifest.fidbf;
            if fidbf.fidbf_id != submission_id {
                return Err(mismatch("ID"));
            }
            if manifest.manifest.analyst_user_id != analyst_id {
                return Err(mismatch("Analyst"));
            }
            if object_sha256 != Some(fidbf.sha256.as_str()) {
                return Err(mismatch("object digest"));
            }
            let expected = canonical_fidbf_storage_path(fidbf.sha256.as_str());
            if fidbf.storage_path != expected {
                return Err(Failure::permanent(format!(
                    "storage_path must be {expected}"
                )));
            }
            let stored =
                store_object(config, fidbf.sha256.as_str(), fidbf.md5.as_str(), &expected)?;
            let result = admit_fidbf(
                transaction,
                &manifest,
                &stored,
                config.integrity_system_user_id,
                config.integrity_signer,
            )?;
            Ok(serde_json::to_value(result).unwrap_or(Value::Null))
        }
        "bsim" => {
            let submission: BsimSubmission = parse(payload)?;
            if submission.bsim_id != submission_id {
                return Err(mismatch("ID"));
            }
            if submission.analyst_id != analyst_id {
                return Err(mismatch("Analyst"));
            }
            let admitted = admit_bsim(
                transaction,
                &submission,
                config.integrity_system_user_id,
                config.integrity_signer,
            )?;
            Ok(json!({
                "bsim_id": admitted.id,
                "function_count": submission.functions.len(),
                "sha256": admitted.sha256,
                "integrity_id": admitted.integrity_id,
                "chain_hash": admitted.chain_hash,
            }))
        }
        "provenance" => {
            let submission: ProvenanceSubmission = parse(payload)?;
            if submission.provenance_id != submission_id {
                return Err(mismatch("ID"));
            }
            if submission.analyst_id != analyst_id {
                return Err(mismatch("Analyst"));
            }
            let admitted = admit_provenance(
                transaction,
                &submission,
                config.integrity_system_user_id,
                config.integrity_signer,
            )?;
            Ok(json!({
                "provenance_id": admitted.id,
                "sha256": admitted.sha256,
                "integrity_id": admitted.integrity_id,
                "chain_hash": admitted.chain_hash,
            }))
        }
        other => Err(Failure::permanent(format!(
            "unknown submission kind {other}"
        ))),
    }
}

fn parse<T: serde::de::DeserializeOwned>(payload: &str) -> Result<T, Failure> {
    serde_json::from_str(payload)
        .map_err(|error| Failure::permanent(format!("invalid payload: {error}")))
}

fn staged_path(staging_dir: &Path, sha256_hex: &str) -> PathBuf {
    staging_dir.join(format!("{sha256_hex}.fidbf"))
}

/// Copy the staged object into the content-addressed store and return its path.
///
/// The staged file was written by the API, so it is opened without following
/// a symbolic link and must be a single-link regular file: otherwise a
/// compromised API could point it at a host file (a private key, say) and
/// have it published as a FIDBF object.
fn store_object(
    config: &AdmitConfig<'_>,
    sha256_hex: &str,
    md5_hex: &str,
    storage_path: &str,
) -> Result<PathBuf, Failure> {
    let target = config.fidbf_root.join(storage_path);
    if target.exists() {
        // Content-addressed and immutable: an earlier admission stored it.
        return Ok(target);
    }
    let staged = staged_path(config.staging_dir, sha256_hex);
    let mut source = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(&staged)
        .map_err(|error| {
            Failure::permanent(format!("FIDBF object {sha256_hex} is not staged: {error}"))
        })?;
    let metadata = source
        .metadata()
        .map_err(|error| Failure::transient(error.to_string()))?;
    if !metadata.is_file() || metadata.nlink() != 1 {
        return Err(Failure::permanent("the staged object is not a plain file"));
    }
    if metadata.len() > config.max_object_bytes {
        return Err(Failure::permanent(format!(
            "the staged object is larger than {} bytes",
            config.max_object_bytes
        )));
    }

    let directory = target.parent().unwrap_or(config.fidbf_root);
    fs::create_dir_all(directory).map_err(|error| Failure::transient(error.to_string()))?;
    let temporary = directory.join(format!(".{sha256_hex}.{}.tmp", Uuid::new_v4()));
    let copied = copy_verified(&mut source, &temporary, sha256_hex, md5_hex).and_then(|()| {
        fs::rename(&temporary, &target).map_err(|e| Failure::transient(e.to_string()))
    });
    if copied.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    copied.map(|()| target)
}

fn copy_verified(
    source: &mut File,
    temporary: &Path,
    sha256_hex: &str,
    md5_hex: &str,
) -> Result<(), Failure> {
    let transient = |error: io::Error| Failure::transient(error.to_string());
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .open(temporary)
        .map_err(transient)?;
    let mut sha = Sha256::new();
    let mut md5 = Md5::new();
    let mut buffer = vec![0_u8; 1 << 16];
    loop {
        let read = source.read(&mut buffer).map_err(transient)?;
        if read == 0 {
            break;
        }
        sha.update(&buffer[..read]);
        md5.update(&buffer[..read]);
        output.write_all(&buffer[..read]).map_err(transient)?;
    }
    let sha_hex = relic_crypto::Digest32::from_bytes(sha.finalize().into()).to_string();
    let md5_actual = CompatibilityMd5::from_bytes(md5.finalize().into()).to_string();
    if sha_hex != sha256_hex || md5_actual != md5_hex {
        return Err(Failure::permanent(
            "the staged object does not match the manifest's digests",
        ));
    }
    output.sync_all().map_err(transient)?;
    output
        .set_permissions(fs::Permissions::from_mode(0o644))
        .map_err(transient)?;
    Ok(())
}

/// Delete a staged object once no pending submission refers to it.
fn remove_staged_if_unused(client: &mut Client, staging_dir: &Path, sha256_hex: &str) {
    let pending = client
        .query_one(
            "SELECT count(*) FROM catalogue.submission
              WHERE status = 'pending' AND object_sha256::text = $1",
            &[&sha256_hex],
        )
        .map_or(1, |row| row.get::<_, i64>(0));
    if pending == 0 {
        let _ = fs::remove_file(staged_path(staging_dir, sha256_hex));
    }
}

/// Remove staged uploads older than `older_than` that no pending submission
/// refers to: abandoned uploads, and partial files of interrupted ones.
///
/// # Errors
///
/// Returns a database error if pending submissions cannot be read.
pub fn prune_staging(
    client: &mut Client,
    staging_dir: &Path,
    older_than: Duration,
) -> Result<usize, postgres::Error> {
    let pending: HashSet<String> = client
        .query(
            "SELECT DISTINCT object_sha256::text FROM catalogue.submission
              WHERE status = 'pending' AND object_sha256 IS NOT NULL",
            &[],
        )?
        .iter()
        .map(|row| row.get(0))
        .collect();
    let Ok(entries) = fs::read_dir(staging_dir) else {
        return Ok(0);
    };
    let cutoff = SystemTime::now()
        .checked_sub(older_than)
        .unwrap_or(SystemTime::UNIX_EPOCH);
    let mut removed = 0;
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let staged = name
            .strip_suffix(".fidbf")
            .filter(|sha| sha.len() == 64 && sha.bytes().all(|b| b.is_ascii_hexdigit()));
        let partial = Path::new(&name)
            .extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("part"));
        if staged.is_none() && !partial {
            continue;
        }
        if staged.is_some_and(|sha| pending.contains(sha)) {
            continue;
        }
        let old = entry
            .metadata()
            .and_then(|metadata| metadata.modified())
            .is_ok_and(|modified| modified < cutoff);
        if old && fs::remove_file(entry.path()).is_ok() {
            removed += 1;
        }
    }
    Ok(removed)
}
