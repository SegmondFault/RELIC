//! Read-only re-verification of a RELIC database.
//!
//! `PostgreSQL` checks roles, shapes and who a row names, but not signatures:
//! the API verifies user signatures and the workers sign the chain. This
//! crate re-checks, from the stored rows alone, every signature that has a
//! canonical format, the integrity chain and every MMR checkpoint. It detects
//! rows written by a compromised API, a stolen database login or a direct
//! edit, after the fact.
//!
//! Everything is read in one read-only `REPEATABLE READ` snapshot.

use std::collections::{BTreeMap, HashMap, HashSet};

use chrono::{DateTime, Utc};
use postgres::{Client, IsolationLevel, Row, Transaction};
use relic_crypto::{
    Digest32,
    auth::{self, Decision},
    verify_digest_signature,
};
use relic_domain::{FidHash, Md5Hex, Sha256Hex};
use relic_ingest::{
    AnalystSignatures, BatchInput, BinaryInput, FidbfIngestManifest, FidbfInput, FunctionInput,
    SignatureHex, SourceInput, admission_record_hash, verify_manifest_signatures,
    verify_source_signature,
};
use relic_integrity_worker::{
    BsimRecord, IntegrityEnvelope, SignedIntegrityEntry, bsim_record_hash,
};
use relic_mmr_worker::{MmrFrontier, Peak, SignedCheckpoint};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Outcome of one run. Any failure means the database holds a row that its
/// own signatures or the chain do not support.
#[derive(Debug, Default, Serialize)]
pub struct Report {
    /// Rows whose signatures (or chain links) verified, by kind.
    pub checked: BTreeMap<&'static str, u64>,
    /// Rows that cannot be checked yet (no canonical signed format), by kind.
    pub unchecked: BTreeMap<&'static str, u64>,
    /// Noteworthy but not proof of tampering.
    pub warnings: Vec<Finding>,
    /// Rows that do not verify.
    pub failures: Vec<Finding>,
}

/// One problem with one row.
#[derive(Debug, Serialize)]
pub struct Finding {
    pub kind: &'static str,
    pub id: String,
    pub problem: String,
}

impl Report {
    /// True when nothing failed.
    #[must_use]
    pub fn ok(&self) -> bool {
        self.failures.is_empty()
    }

    fn checked(&mut self, kind: &'static str) {
        *self.checked.entry(kind).or_default() += 1;
    }

    #[allow(clippy::needless_pass_by_value)]
    fn fail(&mut self, kind: &'static str, id: impl ToString, problem: impl Into<String>) {
        self.failures.push(Finding {
            kind,
            id: id.to_string(),
            problem: problem.into(),
        });
    }

    #[allow(clippy::needless_pass_by_value)]
    fn warn(&mut self, kind: &'static str, id: impl ToString, problem: impl Into<String>) {
        self.warnings.push(Finding {
            kind,
            id: id.to_string(),
            problem: problem.into(),
        });
    }
}

struct Account {
    key: Option<[u8; 32]>,
    role: Option<String>,
    human: bool,
}

type Accounts = HashMap<Uuid, Account>;

/// First approvals by request: (Moderator, signature).
type Approvals = HashMap<Uuid, Vec<(Uuid, Vec<u8>)>>;

/// Re-verify the whole database in one read-only snapshot.
///
/// # Errors
///
/// Returns a database error if the snapshot cannot be read. Verification
/// problems are not errors: they are reported as failures.
pub fn verify(client: &mut Client) -> Result<Report, postgres::Error> {
    let mut tx = client
        .build_transaction()
        .isolation_level(IsolationLevel::RepeatableRead)
        .read_only(true)
        .start()?;
    let mut report = Report::default();
    let accounts = load_accounts(&mut tx)?;

    let registered = registrations(&mut tx, &accounts, &mut report)?;
    operator_accounts(&accounts, &registered, &mut report);
    revocations(&mut tx, &accounts, &mut report)?;
    flags(&mut tx, &accounts, &mut report)?;
    sources(&mut tx, &accounts, &mut report)?;

    let chain = integrity_chain(&mut tx, &accounts, &mut report)?;
    let mut explained = HashSet::new();
    fidbf_admissions(&mut tx, &accounts, &chain, &mut explained, &mut report)?;
    bsim_entries(&mut tx, &chain, &mut explained, &mut report)?;
    for entry in &chain.entries {
        if !explained.contains(&entry.integrity_id) {
            report.fail(
                "integrity entry",
                entry.integrity_id,
                "matches no FIDBF admission or BSim object as currently stored",
            );
        }
    }
    checkpoints(&mut tx, &accounts, &chain, &mut report)?;
    not_checkable(&mut tx, &mut report)?;
    tx.commit()?;
    Ok(report)
}

fn load_accounts(tx: &mut Transaction<'_>) -> Result<Accounts, postgres::Error> {
    let rows = tx.query(
        "SELECT user_id, public_key, role::text, owner_type::text = 'human'
           FROM catalogue.user_public",
        &[],
    )?;
    Ok(rows
        .iter()
        .map(|row| {
            let key: Vec<u8> = row.get(1);
            (
                row.get(0),
                Account {
                    key: key.try_into().ok(),
                    role: row.get(2),
                    human: row.get(3),
                },
            )
        })
        .collect())
}

/// Check that `signer` is a human with `role` and that `signature` verifies
/// with their registered key. Records a failure and returns false otherwise.
#[allow(clippy::too_many_arguments)]
fn check_signature(
    report: &mut Report,
    accounts: &Accounts,
    kind: &'static str,
    id: &str,
    signer: Uuid,
    role: &str,
    domain: &[u8],
    digest: &Digest32,
    signature: &[u8],
) -> bool {
    let Some(account) = accounts.get(&signer) else {
        report.fail(
            kind,
            id,
            format!("signed by {signer}, which is not an account"),
        );
        return false;
    };
    if !account.human || account.role.as_deref() != Some(role) {
        report.fail(
            kind,
            id,
            format!("signed by {signer}, which is not a {role}"),
        );
        return false;
    }
    verify_with(
        report,
        kind,
        id,
        account.key,
        signer,
        domain,
        digest,
        signature,
    )
}

#[allow(clippy::too_many_arguments)]
fn verify_with(
    report: &mut Report,
    kind: &'static str,
    id: &str,
    key: Option<[u8; 32]>,
    signer: Uuid,
    domain: &[u8],
    digest: &Digest32,
    signature: &[u8],
) -> bool {
    let (Some(key), Ok(signature)) = (key, <[u8; 64]>::try_from(signature)) else {
        report.fail(kind, id, "malformed key or signature");
        return false;
    };
    if verify_digest_signature(&key, domain, digest, &signature).is_err() {
        report.fail(
            kind,
            id,
            format!("signature does not verify with the key registered for {signer}"),
        );
        return false;
    }
    true
}

fn verdict(decision: &str) -> Decision {
    if decision == "approved" {
        Decision::Approved
    } else {
        Decision::Rejected
    }
}

fn micros(value: DateTime<Utc>) -> i64 {
    value.timestamp_micros()
}

// ---------------------------------------------------------------------------
// Accounts and registrations
// ---------------------------------------------------------------------------

fn approvals(tx: &mut Transaction<'_>, query: &str) -> Result<Approvals, postgres::Error> {
    let mut map = Approvals::new();
    for row in tx.query(query, &[])? {
        map.entry(row.get(0))
            .or_default()
            .push((row.get(1), row.get(2)));
    }
    Ok(map)
}

/// Returns the accounts created by an approved registration.
#[allow(clippy::too_many_lines)]
fn registrations(
    tx: &mut Transaction<'_>,
    accounts: &Accounts,
    report: &mut Report,
) -> Result<HashSet<Uuid>, postgres::Error> {
    const KIND: &str = "registration";
    let first = approvals(
        tx,
        "SELECT registration_request_id, moderator_id, approval_signature
           FROM catalogue.registration_approval",
    )?;
    let rows = tx.query(
        "SELECT r.registration_request_id, r.challenge_id, c.nonce, c.audience,
                (extract(epoch FROM c.expires_at) * 1000000)::bigint,
                r.public_key, r.requested_role::text, r.name, r.organisation, r.email,
                r.proof_signature, r.moderator_id, r.decision::text, r.decision_signature,
                r.user_id
           FROM catalogue.registration_request AS r
           JOIN catalogue.auth_challenge AS c ON c.challenge_id = r.challenge_id",
        &[],
    )?;
    let mut created = HashSet::new();
    for row in &rows {
        let id: Uuid = row.get(0);
        let id_text = id.to_string();
        let challenge_id: Uuid = row.get(1);
        let nonce: Vec<u8> = row.get(2);
        let key: Vec<u8> = row.get(5);
        let (Ok(nonce), Ok(key)) = (<[u8; 32]>::try_from(nonce), <[u8; 32]>::try_from(key)) else {
            report.fail(KIND, &id_text, "malformed nonce or public key");
            continue;
        };
        let role: String = row.get(6);
        let name: String = row.get(7);
        let organisation: Option<String> = row.get(8);
        let email: String = row.get(9);
        let details = auth::RegistrationDetails {
            public_key: &key,
            requested_role: &role,
            name: &name,
            organisation: organisation.as_deref(),
            email: &email,
        };
        let challenge = auth::AuthChallenge {
            challenge_id: *challenge_id.as_bytes(),
            nonce,
            audience: row.get(3),
            expires_at_unix_micros: row.get(4),
        };
        let proof: Vec<u8> = row.get(10);
        // Proof of possession: the applicant's own key over the challenge.
        if verify_with(
            report,
            KIND,
            &id_text,
            Some(key),
            id,
            auth::REGISTRATION_SIGNATURE_DOMAIN,
            &auth::registration_digest(&challenge, &details),
            &proof,
        ) {
            report.checked("registration proofs");
        }

        let decision_digest = |moderator: Uuid, decision| {
            auth::registration_decision_digest(
                id.as_bytes(),
                &details,
                moderator.as_bytes(),
                decision,
            )
        };
        let mut valid_approvers = HashSet::new();
        for (moderator, signature) in first.get(&id).into_iter().flatten() {
            if check_signature(
                report,
                accounts,
                "registration approval",
                &id_text,
                *moderator,
                "moderator",
                auth::REGISTRATION_DECISION_SIGNATURE_DOMAIN,
                &decision_digest(*moderator, Decision::Approved),
                signature,
            ) {
                valid_approvers.insert(*moderator);
                report.checked("first approvals");
            }
        }

        let decision: Option<String> = row.get(12);
        let Some(decision) = decision else { continue };
        let moderator: Uuid = row.get(11);
        let signature: Vec<u8> = row.get(13);
        if check_signature(
            report,
            accounts,
            KIND,
            &id_text,
            moderator,
            "moderator",
            auth::REGISTRATION_DECISION_SIGNATURE_DOMAIN,
            &decision_digest(moderator, verdict(&decision)),
            &signature,
        ) {
            report.checked("registration decisions");
        }
        if decision != "approved" {
            continue;
        }
        let user_id: Option<Uuid> = row.get(14);
        let matches = user_id
            .and_then(|user| accounts.get(&user))
            .is_some_and(|account| {
                account.human && account.key == Some(key) && account.role.as_deref() == Some(&role)
            });
        if !matches {
            report.fail(
                KIND,
                &id_text,
                "the approved account does not match the request",
            );
        }
        created.extend(user_id);
        if role == "moderator"
            && valid_approvers
                .iter()
                .all(|approver| *approver == moderator)
        {
            report.fail(
                KIND,
                &id_text,
                "Moderator approved without a second Moderator's signed approval",
            );
        }
    }
    Ok(created)
}

fn operator_accounts(accounts: &Accounts, registered: &HashSet<Uuid>, report: &mut Report) {
    let operator_created = accounts
        .iter()
        .filter(|(id, account)| account.human && !registered.contains(*id))
        .count();
    if operator_created > 0 {
        report.unchecked.insert(
            "human accounts created by the operator (no registration)",
            u64::try_from(operator_created).unwrap_or(u64::MAX),
        );
    }
}

// ---------------------------------------------------------------------------
// Revocations, flags and sources
// ---------------------------------------------------------------------------

fn revocations(
    tx: &mut Transaction<'_>,
    accounts: &Accounts,
    report: &mut Report,
) -> Result<(), postgres::Error> {
    const KIND: &str = "revocation";
    let first = approvals(
        tx,
        "SELECT revocation_id, moderator_id, approval_signature
           FROM catalogue.revocation_approval",
    )?;
    let rows = tx.query(
        "SELECT revocation_id, analyst_request_id, target_type::text, target_id, reason,
                request_signature, moderator_id, decision::text, decision_signature
           FROM catalogue.revocation",
        &[],
    )?;
    for row in &rows {
        let id: Uuid = row.get(0);
        let id_text = id.to_string();
        let analyst: Uuid = row.get(1);
        let target_type: String = row.get(2);
        let target: Uuid = row.get(3);
        let reason: String = row.get(4);
        let request = auth::RevocationRequest {
            revocation_id: id.as_bytes(),
            analyst_id: analyst.as_bytes(),
            target_type: &target_type,
            target_id: target.as_bytes(),
            reason: &reason,
        };
        let signature: Vec<u8> = row.get(5);
        if check_signature(
            report,
            accounts,
            KIND,
            &id_text,
            analyst,
            "analyst",
            auth::REVOCATION_REQUEST_SIGNATURE_DOMAIN,
            &auth::revocation_request_digest(&request),
            &signature,
        ) {
            report.checked("revocation requests");
        }

        let mut valid_approvers = HashSet::new();
        for (moderator, signature) in first.get(&id).into_iter().flatten() {
            if check_signature(
                report,
                accounts,
                "revocation approval",
                &id_text,
                *moderator,
                "moderator",
                auth::REVOCATION_DECISION_SIGNATURE_DOMAIN,
                &auth::revocation_decision_digest(
                    &request,
                    moderator.as_bytes(),
                    Decision::Approved,
                ),
                signature,
            ) {
                valid_approvers.insert(*moderator);
                report.checked("first approvals");
            }
        }

        let decision: Option<String> = row.get(7);
        let Some(decision) = decision else { continue };
        let moderator: Uuid = row.get(6);
        let signature: Vec<u8> = row.get(8);
        if check_signature(
            report,
            accounts,
            KIND,
            &id_text,
            moderator,
            "moderator",
            auth::REVOCATION_DECISION_SIGNATURE_DOMAIN,
            &auth::revocation_decision_digest(&request, moderator.as_bytes(), verdict(&decision)),
            &signature,
        ) {
            report.checked("revocation decisions");
        }
        let target_is_moderator = target_type == "user"
            && accounts.get(&target).and_then(|a| a.role.as_deref()) == Some("moderator");
        if decision == "approved"
            && target_is_moderator
            && !valid_approvers
                .iter()
                .any(|a| *a != moderator && *a != target)
        {
            report.warn(
                KIND,
                &id_text,
                "a Moderator was revoked by one Moderator; only the database operator can do that",
            );
        }
    }
    Ok(())
}

fn flags(
    tx: &mut Transaction<'_>,
    accounts: &Accounts,
    report: &mut Report,
) -> Result<(), postgres::Error> {
    let rows = tx.query(
        "SELECT flag_id, viewer_request_id, target_type::text, target_id, note, signature
           FROM catalogue.flag",
        &[],
    )?;
    let mut stored = HashMap::new();
    for row in &rows {
        let id: Uuid = row.get(0);
        let viewer: Uuid = row.get(1);
        let fields: (String, Uuid, String) = (row.get(2), row.get(3), row.get(4));
        let flag = auth::Flag {
            flag_id: id.as_bytes(),
            viewer_id: viewer.as_bytes(),
            target_type: &fields.0,
            target_id: fields.1.as_bytes(),
            note: &fields.2,
        };
        let signature: Vec<u8> = row.get(5);
        if check_signature(
            report,
            accounts,
            "flag",
            &id.to_string(),
            viewer,
            "viewer",
            auth::FLAG_SIGNATURE_DOMAIN,
            &auth::flag_digest(&flag),
            &signature,
        ) {
            report.checked("flags");
        }
        stored.insert(id, (viewer, fields));
    }

    let rows = tx.query(
        "SELECT flag_response_id, flag_id, analyst_request_id, note, signature
           FROM catalogue.flag_response",
        &[],
    )?;
    for row in &rows {
        let id: Uuid = row.get(0);
        let flag_id: Uuid = row.get(1);
        let analyst: Uuid = row.get(2);
        let note: String = row.get(3);
        let signature: Vec<u8> = row.get(4);
        let Some((viewer, (target_type, target, flag_note))) = stored.get(&flag_id) else {
            report.fail("flag response", id, "answers a flag that does not exist");
            continue;
        };
        let flag = auth::Flag {
            flag_id: flag_id.as_bytes(),
            viewer_id: viewer.as_bytes(),
            target_type,
            target_id: target.as_bytes(),
            note: flag_note,
        };
        if check_signature(
            report,
            accounts,
            "flag response",
            &id.to_string(),
            analyst,
            "analyst",
            auth::FLAG_RESPONSE_SIGNATURE_DOMAIN,
            &auth::flag_response_digest(&flag, id.as_bytes(), analyst.as_bytes(), &note),
            &signature,
        ) {
            report.checked("flag responses");
        }
    }
    Ok(())
}

fn source_input(row: &Row) -> SourceInput {
    SourceInput {
        source_id: row.get("source_id"),
        name: row.get("source_name"),
        source_type: row.get("source_type"),
        reference: row.get("reference"),
        snapshot_version: row.get("snapshot_version"),
        retrieved_at: row.get("retrieved_at"),
        is_ecological: row.get("is_ecological"),
    }
}

const SOURCE_COLUMNS: &str = "s.source_id, s.name AS source_name, s.source_type, s.reference,
    s.snapshot_version, s.retrieved_at, s.is_ecological,
    s.submitted_by_analyst_id AS source_analyst, s.signature AS source_signature";

fn sources(
    tx: &mut Transaction<'_>,
    accounts: &Accounts,
    report: &mut Report,
) -> Result<(), postgres::Error> {
    let rows = tx.query(
        &format!("SELECT {SOURCE_COLUMNS} FROM catalogue.source AS s"),
        &[],
    )?;
    for row in &rows {
        let source = source_input(row);
        let analyst: Uuid = row.get("source_analyst");
        let signature: Vec<u8> = row.get("source_signature");
        let id = source.source_id.to_string();
        let Some(account) = accounts
            .get(&analyst)
            .filter(|a| a.human && a.role.as_deref() == Some("analyst"))
        else {
            report.fail(
                "source",
                &id,
                format!("signed by {analyst}, which is not an analyst"),
            );
            continue;
        };
        let (Some(key), Ok(signature)) = (account.key, <[u8; 64]>::try_from(signature)) else {
            report.fail("source", &id, "malformed key or signature");
            continue;
        };
        match verify_source_signature(&source, analyst, &key, &SignatureHex::from_bytes(signature))
        {
            Ok(()) => report.checked("sources"),
            Err(_) => report.fail(
                "source",
                &id,
                format!("signature does not verify with the key registered for {analyst}"),
            ),
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Integrity chain, admissions, BSim and checkpoints
// ---------------------------------------------------------------------------

struct ChainEntry {
    integrity_id: i64,
    record_hash: String,
    created_at_micros: i64,
    chain_hash: Digest32,
}

struct Chain {
    /// In chain order, genesis first.
    entries: Vec<ChainEntry>,
    by_source: HashMap<Uuid, Vec<usize>>,
}

impl Chain {
    fn find(&self, source: Uuid, record_hash: &str, created_at_micros: Option<i64>) -> Option<i64> {
        self.by_source.get(&source)?.iter().find_map(|index| {
            let entry = &self.entries[*index];
            (entry.record_hash == record_hash
                && created_at_micros.is_none_or(|micros| micros == entry.created_at_micros))
            .then_some(entry.integrity_id)
        })
    }
}

#[allow(clippy::too_many_lines)]
fn integrity_chain(
    tx: &mut Transaction<'_>,
    accounts: &Accounts,
    report: &mut Report,
) -> Result<Chain, postgres::Error> {
    const KIND: &str = "integrity entry";
    let rows = tx.query(
        "SELECT integrity_id, source_id, source_type, record_hash::text, prev_hash::text,
                chain_hash::text, format_version, created_at, system_uid, system_signature
           FROM catalogue.integrity
          ORDER BY integrity_id",
        &[],
    )?;
    let mut by_prev: HashMap<Option<String>, Vec<usize>> = HashMap::new();
    for (index, row) in rows.iter().enumerate() {
        by_prev
            .entry(row.get::<_, Option<String>>(4))
            .or_default()
            .push(index);
    }
    let mut chain = Chain {
        entries: Vec::with_capacity(rows.len()),
        by_source: HashMap::new(),
    };
    let genesis = by_prev.get(&None).cloned().unwrap_or_default();
    if genesis.len() > 1 {
        report.fail(KIND, "chain", "more than one genesis entry");
    }
    let mut next = genesis.first().copied();
    while let Some(index) = next {
        let row = &rows[index];
        let integrity_id: i64 = row.get(0);
        let chain_hash_text: String = row.get(5);
        next = by_prev
            .get(&Some(chain_hash_text.clone()))
            .and_then(|children| children.first().copied());

        let parse = |text: &str| text.parse::<Digest32>().ok();
        let prev_text: Option<String> = row.get(4);
        let record_hash: String = row.get(3);
        let (Some(record), Some(chain_hash)) = (parse(&record_hash), parse(&chain_hash_text))
        else {
            report.fail(KIND, integrity_id, "malformed digest");
            continue;
        };
        let system_uid: Uuid = row.get(8);
        let created_at_micros = micros(row.get(7));
        let source_id: Uuid = row.get(1);
        let entry = SignedIntegrityEntry {
            envelope: IntegrityEnvelope {
                source_id: source_id.to_string(),
                source_type: row.get(2),
                record_hash: record,
                prev_hash: prev_text.as_deref().and_then(parse),
                format_version: u32::try_from(row.get::<_, i32>(6)).unwrap_or(0),
                created_at_unix_micros: created_at_micros,
                system_uid: system_uid.to_string(),
            },
            chain_hash,
            system_signature: <[u8; 64]>::try_from(row.get::<_, Vec<u8>>(9)).unwrap_or([0; 64]),
        };
        match accounts.get(&system_uid) {
            Some(account) if !account.human && account.role.is_none() => {
                match account.key.map(|key| entry.verify(&key)) {
                    Some(Ok(())) => report.checked("integrity entries"),
                    _ => report.fail(
                        KIND,
                        integrity_id,
                        "chain hash or system signature does not verify",
                    ),
                }
            }
            _ => report.fail(
                KIND,
                integrity_id,
                format!("{system_uid} is not a system account"),
            ),
        }
        chain
            .by_source
            .entry(source_id)
            .or_default()
            .push(chain.entries.len());
        chain.entries.push(ChainEntry {
            integrity_id,
            record_hash,
            created_at_micros,
            chain_hash,
        });
    }
    if chain.entries.len() != rows.len() {
        report.fail(
            KIND,
            "chain",
            format!(
                "{} of {} entries are not on one linear chain from the genesis entry",
                rows.len() - chain.entries.len(),
                rows.len()
            ),
        );
    }
    Ok(chain)
}

fn text<T>(row: &Row, column: &str, parse: impl Fn(String) -> Option<T>) -> Option<T> {
    parse(row.get::<_, String>(column))
}

fn admission_manifest(
    tx: &mut Transaction<'_>,
    row: &Row,
) -> Result<Option<FidbfIngestManifest>, postgres::Error> {
    let binary_id: Uuid = row.get("binary_id");
    let functions = tx.query(
        "SELECT function_id, name, full_hash::text, specific_hash::text, file_offset,
                virtual_address::text, size_bytes, section_name, symbol_name, mangled_name,
                demangled_name, is_import, is_export, is_thunk
           FROM catalogue.function_record WHERE binary_id = $1",
        &[&binary_id],
    )?;
    let mut parsed = Vec::with_capacity(functions.len());
    for function in &functions {
        let (Ok(full_hash), Ok(specific_hash)) = (
            FidHash::new(function.get::<_, String>(2)),
            FidHash::new(function.get::<_, String>(3)),
        ) else {
            return Ok(None);
        };
        parsed.push(FunctionInput {
            function_id: function.get(0),
            name: function.get(1),
            full_hash,
            specific_hash,
            file_offset: function.get(4),
            virtual_address: function.get(5),
            size_bytes: function.get(6),
            section_name: function.get(7),
            symbol_name: function.get(8),
            mangled_name: function.get(9),
            demangled_name: function.get(10),
            is_import: function.get(11),
            is_export: function.get(12),
            is_thunk: function.get(13),
        });
    }
    let (Some(content_sha256), Some(content_md5), Some(sha256), Some(md5)) = (
        text(row, "content_sha256", |v| Sha256Hex::new(v).ok()),
        text(row, "content_md5", |v| Md5Hex::new(v).ok()),
        text(row, "fidbf_sha256", |v| Sha256Hex::new(v).ok()),
        text(row, "fidbf_md5", |v| Md5Hex::new(v).ok()),
    ) else {
        return Ok(None);
    };
    Ok(Some(FidbfIngestManifest {
        analyst_user_id: row.get("fidbf_analyst"),
        source: source_input(row),
        batch: BatchInput {
            batch_id: row.get("batch_id"),
        },
        binary: BinaryInput {
            binary_id,
            content_sha256,
            content_md5,
            size_bytes: row.get("size_bytes"),
            original_filename: row.get("original_filename"),
            format: row.get("format"),
            architecture: row.get("architecture"),
            bit_width: row.get("bit_width"),
            endianness: row.get("endianness"),
            platform: row.get("platform"),
            abi: row.get("abi"),
            object_type: row.get("object_type"),
            entry_point: row.get("entry_point"),
            image_base: row.get("image_base"),
            build_id: row.get("build_id"),
            is_stripped: row.get("is_stripped"),
            compiler: row.get("compiler"),
            version: row.get("version"),
        },
        fidbf: FidbfInput {
            fidbf_id: row.get("fidbf_id"),
            storage_path: row.get("storage_path"),
            sha256,
            md5,
        },
        functions: parsed,
    }))
}

fn signature_hex(bytes: Vec<u8>) -> Option<SignatureHex> {
    <[u8; 64]>::try_from(bytes)
        .ok()
        .map(SignatureHex::from_bytes)
}

fn fidbf_admissions(
    tx: &mut Transaction<'_>,
    accounts: &Accounts,
    chain: &Chain,
    explained: &mut HashSet<i64>,
    report: &mut Report,
) -> Result<(), postgres::Error> {
    const KIND: &str = "FIDBF admission";
    let rows = tx.query(
        &format!(
            "SELECT f.fidbf_id, f.binary_id, f.storage_path, f.sha256::text AS fidbf_sha256,
                    f.md5::text AS fidbf_md5, f.submitted_by_user_id AS fidbf_analyst,
                    f.signature AS fidbf_signature,
                    b.batch_id, b.content_sha256::text AS content_sha256,
                    b.content_md5::text AS content_md5, b.size_bytes, b.original_filename,
                    b.format, b.architecture, b.bit_width, b.endianness, b.platform, b.abi,
                    b.object_type, b.entry_point::text AS entry_point,
                    b.image_base::text AS image_base, b.build_id, b.is_stripped, b.compiler,
                    b.version, b.source_id AS binary_source,
                    bt.analyst_user_id AS batch_analyst, bt.signature AS batch_signature,
                    {SOURCE_COLUMNS}
               FROM catalogue.fidbf AS f
               JOIN catalogue.binary_record AS b ON b.binary_id = f.binary_id
               JOIN catalogue.batch AS bt ON bt.batch_id = b.batch_id
               JOIN catalogue.source AS s ON s.source_id = f.source_id"
        ),
        &[],
    )?;
    for row in &rows {
        let fidbf_id: Uuid = row.get("fidbf_id");
        let id = fidbf_id.to_string();
        let analyst: Uuid = row.get("fidbf_analyst");
        let source_id: Uuid = row.get("source_id");
        if row.get::<_, Uuid>("batch_analyst") != analyst
            || row.get::<_, Uuid>("source_analyst") != analyst
            || row.get::<_, Uuid>("binary_source") != source_id
        {
            report.fail(KIND, &id, "source, batch, binary and FIDBF rows disagree");
            continue;
        }
        let Some(manifest) = admission_manifest(tx, row)? else {
            report.fail(KIND, &id, "stored values cannot form a canonical admission");
            continue;
        };
        let signatures = (
            signature_hex(row.get("source_signature")),
            signature_hex(row.get("batch_signature")),
            signature_hex(row.get("fidbf_signature")),
        );
        let (Some(source), Some(batch), Some(fidbf)) = signatures else {
            report.fail(KIND, &id, "malformed signature");
            continue;
        };
        let key = accounts
            .get(&analyst)
            .filter(|a| a.human && a.role.as_deref() == Some("analyst"))
            .and_then(|a| a.key);
        let Some(key) = key else {
            report.fail(
                KIND,
                &id,
                format!("signed by {analyst}, which is not an analyst"),
            );
            continue;
        };
        let signatures = AnalystSignatures {
            source,
            batch,
            fidbf,
        };
        if let Err(error) = verify_manifest_signatures(&manifest, &key, &signatures) {
            report.fail(KIND, &id, format!("{error} (rebuilt from the stored rows)"));
            continue;
        }
        report.checked("FIDBF admissions");

        // The chain entry was written in the same transaction, with the same
        // accepted-at time; find the one that commits to this admission.
        let committed = chain
            .by_source
            .get(&source_id)
            .into_iter()
            .flatten()
            .find_map(|index| {
                let entry = &chain.entries[*index];
                (admission_record_hash(&manifest, entry.created_at_micros).to_string()
                    == entry.record_hash)
                    .then_some(entry.integrity_id)
            });
        match committed {
            Some(integrity_id) => {
                explained.insert(integrity_id);
            }
            None => report.fail(KIND, &id, "no integrity entry commits to this admission"),
        }
    }
    Ok(())
}

fn bsim_entries(
    tx: &mut Transaction<'_>,
    chain: &Chain,
    explained: &mut HashSet<i64>,
    report: &mut Report,
) -> Result<(), postgres::Error> {
    let rows = tx.query(
        "SELECT bsim_id, source_id, sha256::text, md5::text, created_at, submitted_by_user_id,
                signature
           FROM catalogue.bsim",
        &[],
    )?;
    for row in &rows {
        let bsim_id: Uuid = row.get(0);
        let source_id: Uuid = row.get(1);
        let sha256: String = row.get(2);
        let md5: String = row.get(3);
        let signature: Vec<u8> = row.get(6);
        let record = bsim_record_hash(&BsimRecord {
            bsim_id,
            source_id,
            sha256: &sha256,
            md5: &md5,
            created_at_micros: micros(row.get(4)),
            submitter: row.get(5),
            signature: &signature,
        });
        match chain.find(source_id, &record.to_string(), None) {
            Some(integrity_id) => {
                explained.insert(integrity_id);
                report.checked("BSim chain entries");
            }
            None => report.warn("BSim object", bsim_id, "not yet in the integrity chain"),
        }
    }
    Ok(())
}

#[derive(Deserialize)]
struct StoredPeak {
    start_index: u64,
    height: u32,
    hash: String,
}

fn checkpoints(
    tx: &mut Transaction<'_>,
    accounts: &Accounts,
    chain: &Chain,
    report: &mut Report,
) -> Result<(), postgres::Error> {
    const KIND: &str = "MMR checkpoint";
    let rows = tx.query(
        "SELECT mmr_checkpoint_id, last_integrity_id, leaf_count, peaks, commitment::text,
                format_version, created_at, system_uid, system_signature
           FROM catalogue.mmr_checkpoint
          ORDER BY leaf_count, mmr_checkpoint_id",
        &[],
    )?;
    let mut frontier = MmrFrontier::new();
    let mut appended = 0_usize;
    for row in &rows {
        let id: i64 = row.get(0);
        let Ok(leaf_count) = usize::try_from(row.get::<_, i64>(2)) else {
            report.fail(KIND, id, "negative leaf count");
            continue;
        };
        if leaf_count == 0 || leaf_count > chain.entries.len() {
            report.fail(KIND, id, "covers more entries than the chain holds");
            continue;
        }
        while appended < leaf_count {
            if frontier.append(chain.entries[appended].chain_hash).is_err() {
                report.fail(KIND, id, "the chain cannot be rebuilt into an MMR");
                return Ok(());
            }
            appended += 1;
        }
        let last_integrity_id: i64 = row.get(1);
        let peaks: Option<Vec<Peak>> = serde_json::from_value::<Vec<StoredPeak>>(row.get(3))
            .ok()
            .and_then(|stored| {
                stored
                    .into_iter()
                    .map(|peak| {
                        Some(Peak {
                            start_index: peak.start_index,
                            height: peak.height,
                            hash: peak.hash.parse().ok()?,
                        })
                    })
                    .collect()
            });
        let commitment: Option<Digest32> = row.get::<_, String>(4).parse().ok();
        let (Some(peaks), Some(commitment)) = (peaks, commitment) else {
            report.fail(KIND, id, "malformed peaks or commitment");
            continue;
        };
        if chain.entries[leaf_count - 1].integrity_id != last_integrity_id
            || frontier.peaks() != peaks.as_slice()
            || frontier.commitment() != commitment
        {
            report.fail(
                KIND,
                id,
                "does not match the MMR rebuilt from the integrity chain",
            );
            continue;
        }
        let system_uid: Uuid = row.get(7);
        let signed = SignedCheckpoint {
            format_version: u32::try_from(row.get::<_, i32>(5)).unwrap_or(0),
            last_integrity_id: last_integrity_id.to_string(),
            leaf_count: frontier.leaf_count(),
            peaks,
            commitment,
            system_uid: system_uid.to_string(),
            created_at_unix_micros: micros(row.get(6)),
            system_signature: <[u8; 64]>::try_from(row.get::<_, Vec<u8>>(8)).unwrap_or([0; 64]),
        };
        let key = accounts
            .get(&system_uid)
            .filter(|a| !a.human && a.role.is_none())
            .and_then(|a| a.key);
        match key.map(|key| signed.verify(&key)) {
            Some(Ok(())) => report.checked("MMR checkpoints"),
            _ => report.fail(KIND, id, "system signature does not verify"),
        }
    }
    Ok(())
}

/// Rows whose signatures have no canonical format yet.
fn not_checkable(tx: &mut Transaction<'_>, report: &mut Report) -> Result<(), postgres::Error> {
    let counts = [
        (
            "BSim object signatures (no format yet)",
            "SELECT count(*) FROM catalogue.bsim",
        ),
        (
            "provenance (no format yet)",
            "SELECT count(*) FROM catalogue.provenance",
        ),
        (
            "licence assertions (no format yet)",
            "SELECT count(*) FROM catalogue.license_assertion",
        ),
        (
            "classifications (no format yet)",
            "SELECT count(*) FROM catalogue.classification",
        ),
        (
            "behavioural compositions (no format yet)",
            "SELECT count(*) FROM catalogue.behavioural_composition",
        ),
        (
            "binary-component assertions (no format yet)",
            "SELECT count(*) FROM catalogue.binary_component_assertion",
        ),
        (
            "batches outside FIDBF admissions",
            "SELECT count(*) FROM catalogue.batch AS bt
              WHERE NOT EXISTS (
                  SELECT 1 FROM catalogue.binary_record AS b
                    JOIN catalogue.fidbf AS f ON f.binary_id = b.binary_id
                   WHERE b.batch_id = bt.batch_id)",
        ),
    ];
    for (kind, query) in counts {
        let count: i64 = tx.query_one(query, &[])?.get(0);
        if count > 0 {
            report
                .unchecked
                .insert(kind, u64::try_from(count).unwrap_or(0));
        }
    }
    Ok(())
}
