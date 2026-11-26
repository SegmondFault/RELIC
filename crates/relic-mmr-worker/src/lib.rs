//! Fail-closed PostgreSQL MMR checkpoint admission.
//!
//! The MMR itself (frontier, commitment, checkpoint signing and inclusion
//! proofs) lives in the database-free `relic-proof` crate and is re-exported
//! here; this crate adds the reconciler that rebuilds the frontier from the
//! integrity chain and stores signed checkpoints (`relic-checkpoint-mmr`).

use chrono::{DateTime, Utc};
use postgres::{Client, IsolationLevel, Transaction};
use relic_crypto::{Digest32, SystemSigner};
pub use relic_proof::{
    AppendError, CheckpointError, MmrFrontier, Peak, SignedCheckpoint, VerificationError,
    sign_checkpoint,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

/// Result of reconciling the durable MMR checkpoint with the integrity chain.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CheckpointResult {
    /// Database identifier of the checkpoint row.
    pub mmr_checkpoint_id: i64,
    /// Newest covered integrity row.
    pub last_integrity_id: i64,
    /// Number of covered leaves.
    pub leaf_count: u64,
    /// Ordered peak heights for concise operator inspection.
    pub peak_heights: Vec<u32>,
    /// Signed commitment to the complete frontier.
    pub commitment: String,
    /// Whether this invocation inserted a new checkpoint.
    pub inserted: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
struct StoredPeak {
    start_index: u64,
    height: u32,
    hash: String,
}

impl From<&Peak> for StoredPeak {
    fn from(peak: &Peak) -> Self {
        Self {
            start_index: peak.start_index,
            height: peak.height,
            hash: peak.hash.to_string(),
        }
    }
}

/// Connect to PostgreSQL without performing any mutation.
///
/// # Errors
///
/// Returns the PostgreSQL connection error unchanged.
pub fn connect(database_url: &str) -> Result<Client, postgres::Error> {
    Client::connect(database_url, postgres::NoTls)
}

/// Rebuild, verify, sign and atomically store the newest MMR checkpoint.
///
/// The worker always reconstructs the frontier from the immutable integrity
/// chain. If the latest stored checkpoint already covers the complete chain,
/// it is strictly verified and returned as an idempotent no-op.
///
/// # Errors
///
/// Returns an error without commit when the chain is empty or malformed, the
/// latest checkpoint diverges, the system identity/key is invalid, or
/// PostgreSQL rejects the serializable transaction.
pub fn checkpoint_postgres(
    client: &mut Client,
    format_version: u32,
    system_user_id: Uuid,
    signer: &SystemSigner,
) -> Result<CheckpointResult, StoreError> {
    if format_version == 0 {
        return Err(StoreError::InvalidFormatVersion);
    }
    let format_version_i32 =
        i32::try_from(format_version).map_err(|_| StoreError::InvalidFormatVersion)?;
    let mut transaction = client
        .build_transaction()
        .isolation_level(IsolationLevel::Serializable)
        .start()
        .map_err(StoreError::Database)?;
    let lock_scope = format!("RELIC:mmr-sequencer:v1:{format_version}");
    transaction
        .query_one(
            "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
            &[&lock_scope],
        )
        .map_err(StoreError::Database)?;

    verify_active_system_identity(&mut transaction, system_user_id, &signer.verifying_key())?;
    let leaves = load_integrity_chain(&mut transaction)?;
    let latest = load_latest_checkpoint(&mut transaction, format_version_i32)?;

    let mut frontier = MmrFrontier::new();
    let mut latest_frontier = None;
    for (_, chain_hash) in &leaves {
        frontier
            .append(*chain_hash)
            .map_err(|_| StoreError::InvalidFrontier)?;
        if latest
            .as_ref()
            .is_some_and(|stored| stored.leaf_count == frontier.leaf_count())
        {
            latest_frontier = Some(frontier.clone());
        }
    }

    if let Some(stored) = latest {
        let reconstructed = latest_frontier.ok_or(StoreError::CheckpointBeyondChain)?;
        verify_stored_checkpoint(&mut transaction, &stored, &reconstructed, &leaves)?;
        if stored.leaf_count == frontier.leaf_count() {
            transaction.commit().map_err(StoreError::Database)?;
            return Ok(stored.result(false));
        }
    }

    let (last_integrity_id, _) = leaves.last().ok_or(StoreError::EmptyChain)?;
    let created_at_micros: i64 = transaction
        .query_one(
            "SELECT (extract(epoch FROM clock_timestamp()) * 1000000)::bigint",
            &[],
        )
        .map_err(StoreError::Database)?
        .get(0);
    let created_at = DateTime::<Utc>::from_timestamp_micros(created_at_micros)
        .ok_or(StoreError::TimestampOutOfRange(created_at_micros))?;
    let checkpoint = sign_checkpoint(
        &frontier,
        format_version,
        last_integrity_id.to_string(),
        system_user_id.to_string(),
        created_at_micros,
        signer,
    )
    .map_err(|_| StoreError::EmptyChain)?;
    checkpoint
        .verify(&signer.verifying_key())
        .map_err(|_| StoreError::GeneratedCheckpointInvalid)?;
    let stored_peaks: Vec<_> = checkpoint.peaks.iter().map(StoredPeak::from).collect();
    let peaks_json = serde_json::to_value(&stored_peaks).map_err(StoreError::Json)?;
    let leaf_count_i64 = i64::try_from(checkpoint.leaf_count)
        .map_err(|_| StoreError::LeafCountOutOfRange(checkpoint.leaf_count))?;
    let checkpoint_id: i64 = transaction
        .query_one(
            "INSERT INTO catalogue.mmr_checkpoint
                (last_integrity_id, leaf_count, peaks, commitment,
                 format_version, created_at, system_uid, system_signature)
             VALUES ($1,$2,$3,
                     CAST($4 AS text)::catalogue.sha256_hex,
                     $5,$6,$7,$8)
             RETURNING mmr_checkpoint_id",
            &[
                last_integrity_id,
                &leaf_count_i64,
                &peaks_json,
                &checkpoint.commitment.to_string(),
                &format_version_i32,
                &created_at,
                &system_user_id,
                &&checkpoint.system_signature[..],
            ],
        )
        .map_err(StoreError::Database)?
        .get(0);
    transaction.commit().map_err(StoreError::Database)?;

    Ok(CheckpointResult {
        mmr_checkpoint_id: checkpoint_id,
        last_integrity_id: *last_integrity_id,
        leaf_count: checkpoint.leaf_count,
        peak_heights: checkpoint.peaks.iter().map(|peak| peak.height).collect(),
        commitment: checkpoint.commitment.to_string(),
        inserted: true,
    })
}

#[derive(Debug)]
struct StoredCheckpoint {
    checkpoint_id: i64,
    last_integrity_id: i64,
    leaf_count: u64,
    peaks: Vec<Peak>,
    commitment: Digest32,
    format_version: u32,
    created_at_micros: i64,
    system_user_id: Uuid,
    system_signature: [u8; 64],
}

impl StoredCheckpoint {
    fn signed(&self) -> SignedCheckpoint {
        SignedCheckpoint {
            format_version: self.format_version,
            last_integrity_id: self.last_integrity_id.to_string(),
            leaf_count: self.leaf_count,
            peaks: self.peaks.clone(),
            commitment: self.commitment,
            system_uid: self.system_user_id.to_string(),
            created_at_unix_micros: self.created_at_micros,
            system_signature: self.system_signature,
        }
    }

    fn result(&self, inserted: bool) -> CheckpointResult {
        CheckpointResult {
            mmr_checkpoint_id: self.checkpoint_id,
            last_integrity_id: self.last_integrity_id,
            leaf_count: self.leaf_count,
            peak_heights: self.peaks.iter().map(|peak| peak.height).collect(),
            commitment: self.commitment.to_string(),
            inserted,
        }
    }
}

fn load_integrity_chain(
    transaction: &mut Transaction<'_>,
) -> Result<Vec<(i64, Digest32)>, StoreError> {
    let total: i64 = transaction
        .query_one("SELECT count(*)::bigint FROM catalogue.integrity", &[])
        .map_err(StoreError::Database)?
        .get(0);
    if total == 0 {
        return Err(StoreError::EmptyChain);
    }
    let rows = transaction
        .query(
            "WITH RECURSIVE ordered AS (
                 SELECT integrity_id, chain_hash, 0::bigint AS leaf_index
                   FROM catalogue.integrity
                  WHERE prev_hash IS NULL
                 UNION ALL
                 SELECT child.integrity_id, child.chain_hash, parent.leaf_index + 1
                   FROM ordered AS parent
                   JOIN catalogue.integrity AS child
                     ON child.prev_hash = parent.chain_hash
             )
             SELECT integrity_id, chain_hash::text, leaf_index
               FROM ordered
              ORDER BY leaf_index",
            &[],
        )
        .map_err(StoreError::Database)?;
    if i64::try_from(rows.len()).ok() != Some(total) {
        return Err(StoreError::NonLinearChain);
    }
    rows.into_iter()
        .enumerate()
        .map(|(expected_index, row)| {
            let actual_index: i64 = row.get(2);
            if i64::try_from(expected_index).ok() != Some(actual_index) {
                return Err(StoreError::NonLinearChain);
            }
            let integrity_id = row.get(0);
            let hash = row
                .get::<_, String>(1)
                .parse()
                .map_err(|_| StoreError::MalformedDigest)?;
            Ok((integrity_id, hash))
        })
        .collect()
}

fn load_latest_checkpoint(
    transaction: &mut Transaction<'_>,
    format_version: i32,
) -> Result<Option<StoredCheckpoint>, StoreError> {
    let Some(row) = transaction
        .query_opt(
            "SELECT mmr_checkpoint_id, last_integrity_id, leaf_count, peaks,
                    commitment::text, format_version, created_at, system_uid,
                    system_signature
               FROM catalogue.mmr_checkpoint
              WHERE format_version = $1
              ORDER BY leaf_count DESC, mmr_checkpoint_id DESC
              LIMIT 1",
            &[&format_version],
        )
        .map_err(StoreError::Database)?
    else {
        return Ok(None);
    };
    let leaf_count_i64: i64 = row.get(2);
    let leaf_count =
        u64::try_from(leaf_count_i64).map_err(|_| StoreError::StoredCheckpointMalformed)?;
    if leaf_count == 0 {
        return Err(StoreError::StoredCheckpointMalformed);
    }
    let raw_peaks: serde_json::Value = row.get(3);
    let stored_peaks: Vec<StoredPeak> =
        serde_json::from_value(raw_peaks).map_err(StoreError::Json)?;
    let peaks = stored_peaks
        .into_iter()
        .map(|peak| {
            Ok(Peak {
                start_index: peak.start_index,
                height: peak.height,
                hash: peak.hash.parse().map_err(|_| StoreError::MalformedDigest)?,
            })
        })
        .collect::<Result<Vec<_>, StoreError>>()?;
    let signature: Vec<u8> = row.get(8);
    let system_signature = signature
        .try_into()
        .map_err(|_| StoreError::StoredCheckpointMalformed)?;
    let created_at: DateTime<Utc> = row.get(6);
    Ok(Some(StoredCheckpoint {
        checkpoint_id: row.get(0),
        last_integrity_id: row.get(1),
        leaf_count,
        peaks,
        commitment: row
            .get::<_, String>(4)
            .parse()
            .map_err(|_| StoreError::MalformedDigest)?,
        format_version: u32::try_from(row.get::<_, i32>(5))
            .map_err(|_| StoreError::StoredCheckpointMalformed)?,
        created_at_micros: created_at.timestamp_micros(),
        system_user_id: row.get(7),
        system_signature,
    }))
}

fn verify_stored_checkpoint(
    transaction: &mut Transaction<'_>,
    stored: &StoredCheckpoint,
    reconstructed: &MmrFrontier,
    leaves: &[(i64, Digest32)],
) -> Result<(), StoreError> {
    let expected_last_index = usize::try_from(stored.leaf_count - 1)
        .map_err(|_| StoreError::StoredCheckpointMalformed)?;
    if leaves.get(expected_last_index).map(|entry| entry.0) != Some(stored.last_integrity_id)
        || reconstructed.leaf_count() != stored.leaf_count
        || reconstructed.peaks() != stored.peaks
        || reconstructed.commitment() != stored.commitment
    {
        return Err(StoreError::StoredCheckpointDiverged);
    }
    let verifying_key = load_system_verifying_key(transaction, stored.system_user_id)?;
    stored
        .signed()
        .verify(&verifying_key)
        .map_err(|_| StoreError::StoredCheckpointSignatureInvalid)
}

fn verify_active_system_identity(
    transaction: &mut Transaction<'_>,
    system_user_id: Uuid,
    expected_public_key: &[u8; 32],
) -> Result<(), StoreError> {
    let row = transaction
        .query_opt(
            "SELECT public_key, role::text, owner_type::text,
                    catalogue.account_is_revoked($1)
               FROM catalogue.user_public
              WHERE user_id = $1",
            &[&system_user_id],
        )
        .map_err(StoreError::Database)?
        .ok_or(StoreError::UnknownSystemIdentity(system_user_id))?;
    let key = parse_public_key(row.get(0), system_user_id)?;
    let role: Option<String> = row.get(1);
    let owner: String = row.get(2);
    let revoked: bool = row.get(3);
    if owner != "system" || role.is_some() {
        return Err(StoreError::InvalidSystemIdentity(system_user_id));
    }
    if revoked {
        return Err(StoreError::RevokedSystemIdentity(system_user_id));
    }
    if key != *expected_public_key {
        return Err(StoreError::SystemKeyMismatch(system_user_id));
    }
    Ok(())
}

fn load_system_verifying_key(
    transaction: &mut Transaction<'_>,
    system_user_id: Uuid,
) -> Result<[u8; 32], StoreError> {
    let row = transaction
        .query_opt(
            "SELECT public_key, role::text, owner_type::text
               FROM catalogue.user_public
              WHERE user_id = $1",
            &[&system_user_id],
        )
        .map_err(StoreError::Database)?
        .ok_or(StoreError::UnknownSystemIdentity(system_user_id))?;
    let role: Option<String> = row.get(1);
    let owner: String = row.get(2);
    if owner != "system" || role.is_some() {
        return Err(StoreError::InvalidSystemIdentity(system_user_id));
    }
    parse_public_key(row.get(0), system_user_id)
}

fn parse_public_key(bytes: Vec<u8>, user_id: Uuid) -> Result<[u8; 32], StoreError> {
    bytes
        .try_into()
        .map_err(|_| StoreError::MalformedPublicKey(user_id))
}

/// A `PostgreSQL` error with the server's code, message and detail.
///
/// `postgres::Error`'s own text is only "db error" for server-side errors,
/// which hides the cause (e.g. a permission or constraint violation).
#[must_use]
fn describe_db_error(error: &postgres::Error) -> String {
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

/// Failure while rebuilding, verifying or storing a checkpoint.
#[derive(Debug, Error)]
pub enum StoreError {
    #[error("PostgreSQL operation failed: {}", describe_db_error(.0))]
    Database(#[from] postgres::Error),
    #[error("MMR format_version must fit a positive PostgreSQL integer")]
    InvalidFormatVersion,
    #[error("the integrity chain is empty")]
    EmptyChain,
    #[error("the integrity rows do not form one complete linear chain")]
    NonLinearChain,
    #[error("an integrity or checkpoint digest is malformed")]
    MalformedDigest,
    #[error("the MMR frontier is internally invalid")]
    InvalidFrontier,
    #[error("stored checkpoint extends beyond the current integrity chain")]
    CheckpointBeyondChain,
    #[error("stored checkpoint payload is malformed")]
    StoredCheckpointMalformed,
    #[error("stored checkpoint diverges from independent reconstruction")]
    StoredCheckpointDiverged,
    #[error("stored checkpoint signature is invalid")]
    StoredCheckpointSignatureInvalid,
    #[error("generated checkpoint failed self-verification")]
    GeneratedCheckpointInvalid,
    #[error("unknown MMR system identity {0}")]
    UnknownSystemIdentity(Uuid),
    #[error("identity {0} is not an MMR system identity")]
    InvalidSystemIdentity(Uuid),
    #[error("MMR system identity {0} is revoked")]
    RevokedSystemIdentity(Uuid),
    #[error("MMR signer does not match the registered public key for {0}")]
    SystemKeyMismatch(Uuid),
    #[error("MMR system identity {0} has a malformed Ed25519 public key")]
    MalformedPublicKey(Uuid),
    #[error("MMR leaf count {0} cannot be stored in PostgreSQL")]
    LeafCountOutOfRange(u64),
    #[error("database timestamp {0} is outside the supported range")]
    TimestampOutOfRange(i64),
    #[error("checkpoint JSON serialization failed: {0}")]
    Json(#[from] serde_json::Error),
}
