//! The API's JSON, checked the way a client would: `verify_api_proof` and the
//! `relic-verify-proof` command.
//!
//! The fixture is a real integrity chain: every leaf is the chain hash of an
//! [`IntegrityEnvelope`] linked to the previous one, so a proof can be tied
//! back to the entry it is about exactly as a client does with `--entry`.

use std::{fmt::Write as _, fs, process::Command};

use chrono::DateTime;
use relic_crypto::{Digest32, SystemSigner, sha256};
use relic_proof::{
    IntegrityEnvelope, MmrFrontier,
    client::{ClientError, Expectations, LeafOrigin, Verified, verify_api_proof},
    proof::{ProofError, prove},
    sign_checkpoint,
};
use serde_json::{Value, json};
use uuid::Uuid;

type Mutation<'a> = Box<dyn Fn(&mut Value) + 'a>;

/// The MMR system account that signs checkpoints.
const SYSTEM_UID: &str = "7c9f1c2e-31a5-4b53-9d0e-0c8e8a8a1b11";
/// The integrity system account named by every entry.
const INTEGRITY_UID: &str = "0b5d8e3a-6f1c-4d2e-9a7b-3c4d5e6f7a8b";
const CREATED_AT_MICROS: i64 = 1_790_000_000_123_456;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    })
}

/// An instant written the way Python's `isoformat()` does (`+00:00`), or with
/// a `Z` as pydantic does.
fn iso(micros: i64, suffix: &str) -> String {
    DateTime::from_timestamp_micros(micros)
        .unwrap()
        .format(&format!("%Y-%m-%dT%H:%M:%S%.6f{suffix}"))
        .to_string()
}

struct Fixture {
    envelopes: Vec<IntegrityEnvelope>,
    hashes: Vec<Digest32>,
    key: [u8; 32],
    checkpoint: Value,
    leaf_count: u64,
}

fn envelope(index: u64, prev_hash: Option<Digest32>) -> IntegrityEnvelope {
    IntegrityEnvelope {
        source_id: Uuid::from_u128(0x5eed_0000 + u128::from(index)).to_string(),
        source_type: if index.is_multiple_of(2) {
            "FIDBF"
        } else {
            "BSIM"
        }
        .into(),
        record_hash: sha256(format!("relic record {index}").as_bytes()),
        prev_hash,
        format_version: 1,
        created_at_unix_micros: 1_780_000_000_000_000 + i64::try_from(index).unwrap() * 1_000_123,
        system_uid: INTEGRITY_UID.into(),
    }
}

fn fixture(length: u64) -> Fixture {
    let system = SystemSigner::from_seed([42; 32]);
    let mut envelopes = Vec::new();
    let mut hashes: Vec<Digest32> = Vec::new();
    for index in 0..length {
        let entry = envelope(index, hashes.last().copied());
        hashes.push(entry.chain_hash());
        envelopes.push(entry);
    }
    let mut frontier = MmrFrontier::new();
    for hash in &hashes {
        frontier.append(*hash).unwrap();
    }
    let signed = sign_checkpoint(
        &frontier,
        1,
        "100".into(),
        SYSTEM_UID.into(),
        CREATED_AT_MICROS,
        &system,
    )
    .unwrap();
    let checkpoint = json!({
        "mmr_checkpoint_id": 7,
        "last_integrity_id": 100,
        "leaf_count": length,
        "peaks": signed.peaks.iter().map(|peak| json!({
            "start_index": peak.start_index,
            "height": peak.height,
            "hash": peak.hash.to_string(),
        })).collect::<Vec<_>>(),
        "commitment": signed.commitment.to_string(),
        "format_version": 1,
        "created_at": iso(CREATED_AT_MICROS, "+00:00"),
        "system_uid": SYSTEM_UID,
        "system_signature": hex(&signed.system_signature),
    });
    Fixture {
        envelopes,
        hashes,
        key: system.verifying_key(),
        checkpoint,
        leaf_count: length,
    }
}

fn index(leaf: u64) -> usize {
    usize::try_from(leaf).unwrap()
}

impl Fixture {
    /// `GET /v1/integrity/{id}/proof`.
    fn response(&self, leaf: u64) -> Value {
        let proof = prove(&self.hashes, leaf, self.leaf_count).unwrap();
        json!({
            "integrity_id": 1000 + leaf,
            "chain_hash": self.hashes[index(leaf)].to_string(),
            "mmr_checkpoint_id": 7,
            "leaf_count": self.leaf_count,
            "commitment": self.checkpoint["commitment"],
            "proof": serde_json::to_value(&proof).unwrap(),
        })
    }

    /// `GET /v1/integrity/{id}`, with the fields the API returns.
    fn entry(&self, leaf: u64) -> Value {
        let envelope = &self.envelopes[index(leaf)];
        json!({
            "integrity_id": 1000 + leaf,
            "source_id": envelope.source_id,
            "source_type": envelope.source_type,
            "record_hash": envelope.record_hash.to_string(),
            "prev_hash": envelope.prev_hash.map(|hash| hash.to_string()),
            "chain_hash": self.hashes[index(leaf)].to_string(),
            "format_version": envelope.format_version,
            "created_at": iso(envelope.created_at_unix_micros, "Z"),
            "system_uid": envelope.system_uid,
            "system_signature": "11".repeat(64),
        })
    }

    fn check(
        &self,
        response: &Value,
        expected: &Expectations<'_>,
    ) -> Result<Verified, ClientError> {
        verify_api_proof(
            &response.to_string(),
            &self.checkpoint.to_string(),
            &self.key,
            expected,
        )
    }

    fn verify(&self, response: &Value) -> Result<(), ClientError> {
        self.check(response, &Expectations::default()).map(|_| ())
    }

    fn verify_with_entry(&self, response: &Value, entry: &Value) -> Result<Verified, ClientError> {
        let entry = entry.to_string();
        self.check(
            response,
            &Expectations {
                entry_json: Some(&entry),
                ..Expectations::default()
            },
        )
    }
}

#[test]
fn every_leaf_verifies_against_the_api_shaped_json() {
    for length in [1, 2, 7, 13, 20] {
        let fixture = fixture(length);
        for leaf in 0..length {
            let verified = fixture
                .check(
                    &fixture.response(leaf),
                    &Expectations {
                        chain_hash: Some(fixture.hashes[index(leaf)]),
                        ..Expectations::default()
                    },
                )
                .unwrap_or_else(|error| panic!("{length}/{leaf}: {error}"));
            assert_eq!(verified.leaf_index, leaf);
            assert_eq!(verified.integrity_id, i64::try_from(1000 + leaf).unwrap());
            assert_eq!(verified.leaf_count, length);
            assert_eq!(verified.system_uid.to_string(), SYSTEM_UID);
            assert_eq!(verified.leaf_origin, LeafOrigin::Expected);
            assert_eq!(verified.entry, None);
        }
    }
}

#[test]
fn without_the_entry_the_leaf_is_only_what_the_server_reported() {
    let fixture = fixture(9);
    let verified = fixture
        .check(&fixture.response(4), &Expectations::default())
        .unwrap();
    assert_eq!(verified.leaf_origin, LeafOrigin::ServerReported);
}

#[test]
fn the_entry_ties_every_proof_to_its_source_and_record() {
    for length in [1, 2, 7, 13] {
        let fixture = fixture(length);
        for leaf in 0..length {
            let verified = fixture
                .verify_with_entry(&fixture.response(leaf), &fixture.entry(leaf))
                .unwrap_or_else(|error| panic!("{length}/{leaf}: {error}"));
            let envelope = &fixture.envelopes[index(leaf)];
            assert_eq!(verified.leaf_origin, LeafOrigin::RecomputedFromEntry);
            let entry = verified.entry.unwrap();
            assert_eq!(entry.source_id.to_string(), envelope.source_id);
            assert_eq!(entry.source_type, envelope.source_type);
            assert_eq!(entry.record_hash, envelope.record_hash);
            assert_eq!(
                entry.created_at_unix_micros,
                envelope.created_at_unix_micros
            );
            assert_eq!(entry.system_uid.to_string(), INTEGRITY_UID);
        }
    }
}

#[test]
fn an_entry_whose_fields_were_changed_is_rejected() {
    let fixture = fixture(13);
    let response = fixture.response(6);
    let other = sha256(b"forged").to_string();
    let mutations: Vec<(&str, Mutation<'_>)> = vec![
        (
            "source_id",
            Box::new(|e| e["source_id"] = json!(Uuid::nil().to_string())),
        ),
        (
            "source_type",
            Box::new(|e| e["source_type"] = json!("PROVENANCE")),
        ),
        ("record_hash", Box::new(|e| e["record_hash"] = json!(other))),
        ("prev_hash", Box::new(|e| e["prev_hash"] = json!(other))),
        ("genesis claim", Box::new(|e| e["prev_hash"] = Value::Null)),
        (
            "created_at",
            Box::new(|e| e["created_at"] = json!("2026-01-01T00:00:00Z")),
        ),
        (
            "system_uid",
            Box::new(|e| e["system_uid"] = json!(SYSTEM_UID)),
        ),
    ];
    for (label, mutate) in mutations {
        let mut entry = fixture.entry(6);
        mutate(&mut entry);
        assert!(
            matches!(
                fixture.verify_with_entry(&response, &entry),
                Err(ClientError::EntryHashMismatch { .. })
            ),
            "{label} accepted"
        );
        // Restating the chain hash to match the changed fields does not help:
        // the proof is about the genuine leaf.
        let recomputed = recompute(&entry);
        entry["chain_hash"] = json!(recomputed.to_string());
        assert!(
            matches!(
                fixture.verify_with_entry(&response, &entry),
                Err(ClientError::EntryNotProven { .. })
            ),
            "{label} accepted with a restated chain hash"
        );
    }
}

/// What a client recomputes from an entry's JSON.
fn recompute(entry: &Value) -> Digest32 {
    let text = |field: &str| entry[field].as_str().unwrap().to_owned();
    IntegrityEnvelope {
        source_id: text("source_id"),
        source_type: text("source_type"),
        record_hash: text("record_hash").parse().unwrap(),
        prev_hash: entry["prev_hash"]
            .as_str()
            .map(|hash| hash.parse().unwrap()),
        format_version: 1,
        created_at_unix_micros: DateTime::parse_from_rfc3339(&text("created_at"))
            .unwrap()
            .timestamp_micros(),
        system_uid: text("system_uid"),
    }
    .chain_hash()
}

#[test]
fn a_genuine_entry_of_another_leaf_is_rejected() {
    let fixture = fixture(13);
    let response = fixture.response(6);
    // Another real entry, presented under the proven id.
    let mut neighbour = fixture.entry(5);
    neighbour["integrity_id"] = json!(1006);
    assert!(matches!(
        fixture.verify_with_entry(&response, &neighbour),
        Err(ClientError::EntryNotProven { .. })
    ));
    // The same entry under its own id is a different entry from the proof's.
    assert!(matches!(
        fixture.verify_with_entry(&response, &fixture.entry(5)),
        Err(ClientError::Mismatch(_))
    ));
    // And a proof rewritten to carry that entry's leaf does not reach a peak.
    let mut moved = response.clone();
    moved["chain_hash"] = json!(fixture.hashes[5].to_string());
    assert!(matches!(
        fixture.verify_with_entry(&moved, &neighbour),
        Err(ClientError::Rejected(ProofError::PeakMismatch))
    ));
}

#[test]
fn the_entry_timestamp_is_an_instant_whatever_its_offset() {
    let fixture = fixture(7);
    let response = fixture.response(3);
    let micros = fixture.envelopes[3].created_at_unix_micros;
    let local = DateTime::from_timestamp_micros(micros)
        .unwrap()
        .with_timezone(&chrono::FixedOffset::east_opt(3600).unwrap())
        .format("%Y-%m-%dT%H:%M:%S%.6f%:z")
        .to_string();
    for written in [iso(micros, "+00:00"), iso(micros, "Z"), local] {
        let mut entry = fixture.entry(3);
        entry["created_at"] = json!(written);
        fixture
            .verify_with_entry(&response, &entry)
            .unwrap_or_else(|error| panic!("{written}: {error}"));
    }
}

#[test]
fn an_unknown_entry_format_is_not_recomputed() {
    let fixture = fixture(5);
    let mut entry = fixture.entry(2);
    entry["format_version"] = json!(2);
    assert!(matches!(
        fixture.verify_with_entry(&fixture.response(2), &entry),
        Err(ClientError::UnsupportedEntryFormat(2))
    ));
}

#[test]
fn the_expected_source_and_record_hash_are_enforced() {
    let fixture = fixture(9);
    let response = fixture.response(4);
    let entry = fixture.entry(4).to_string();
    let envelope = &fixture.envelopes[4];
    let source = Uuid::parse_str(&envelope.source_id).unwrap();
    let with = |source_id, record_hash| Expectations {
        entry_json: Some(&entry),
        source_id,
        record_hash,
        ..Expectations::default()
    };

    fixture
        .check(&response, &with(Some(source), Some(envelope.record_hash)))
        .unwrap();
    assert!(matches!(
        fixture.check(&response, &with(Some(Uuid::nil()), None)),
        Err(ClientError::Unexpected {
            what: "the entry's source",
            ..
        })
    ));
    assert!(matches!(
        fixture.check(&response, &with(None, Some(sha256(b"my other record")))),
        Err(ClientError::Unexpected {
            what: "the entry's record hash",
            ..
        })
    ));
    // Without the entry there is nothing to compare them with.
    for expected in [
        Expectations {
            source_id: Some(source),
            ..Expectations::default()
        },
        Expectations {
            record_hash: Some(envelope.record_hash),
            ..Expectations::default()
        },
    ] {
        assert!(matches!(
            fixture.check(&response, &expected),
            Err(ClientError::EntryRequired(_))
        ));
    }
}

#[test]
fn the_pinned_system_account_and_commitment_are_enforced() {
    let fixture = fixture(9);
    let response = fixture.response(3);
    let commitment: Digest32 = fixture.checkpoint["commitment"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    let pinned = Expectations {
        system_uid: Some(Uuid::parse_str(SYSTEM_UID).unwrap()),
        commitment: Some(commitment),
        ..Expectations::default()
    };
    fixture.check(&response, &pinned).unwrap();
    assert!(matches!(
        fixture.check(
            &response,
            &Expectations {
                system_uid: Some(Uuid::nil()),
                ..pinned
            }
        ),
        Err(ClientError::Unexpected {
            what: "the checkpoint's system account",
            ..
        })
    ));
    assert!(matches!(
        fixture.check(
            &response,
            &Expectations {
                commitment: Some(sha256(b"an older checkpoint")),
                ..pinned
            }
        ),
        Err(ClientError::Unexpected {
            what: "the checkpoint commitment",
            ..
        })
    ));
}

#[test]
fn the_timestamp_is_signed_as_an_exact_instant() {
    let mut fixture = fixture(5);
    let response = fixture.response(2);
    // Four hours before the signed instant (14:13:20Z), so it is a
    // different instant and the signature must no longer verify.
    fixture.checkpoint["created_at"] = json!("2026-09-21T10:13:20.123456Z");
    assert!(matches!(
        fixture.verify(&response),
        Err(ClientError::Rejected(ProofError::Checkpoint(_)))
    ));
    fixture.checkpoint["created_at"] = json!(iso(CREATED_AT_MICROS, "Z"));
    fixture.verify(&response).unwrap();
}

#[test]
fn the_wrong_public_key_is_rejected() {
    let fixture = fixture(9);
    let other = SystemSigner::from_seed([43; 32]).verifying_key();
    let result = verify_api_proof(
        &fixture.response(3).to_string(),
        &fixture.checkpoint.to_string(),
        &other,
        &Expectations::default(),
    );
    assert!(matches!(
        result,
        Err(ClientError::Rejected(ProofError::Checkpoint(_)))
    ));
}

#[test]
fn a_leaf_other_than_the_expected_one_is_rejected() {
    let fixture = fixture(9);
    let result = fixture.check(
        &fixture.response(3),
        &Expectations {
            chain_hash: Some(sha256(b"the entry I actually recomputed")),
            ..Expectations::default()
        },
    );
    assert!(matches!(result, Err(ClientError::UnexpectedLeaf { .. })));
}

#[test]
fn forged_responses_are_rejected() {
    let fixture = fixture(13);
    let forged_digest = sha256(b"forged").to_string();

    let mut forged_leaf = fixture.response(5);
    forged_leaf["chain_hash"] = json!(forged_digest);
    assert!(matches!(
        fixture.verify(&forged_leaf),
        Err(ClientError::Rejected(ProofError::PeakMismatch))
    ));

    let mut forged_sibling = fixture.response(5);
    forged_sibling["proof"]["siblings"][0] = json!(forged_digest);
    assert!(matches!(
        fixture.verify(&forged_sibling),
        Err(ClientError::Rejected(ProofError::PeakMismatch))
    ));

    let mut moved = fixture.response(5);
    moved["proof"]["leaf_index"] = json!(4);
    assert!(fixture.verify(&moved).is_err());

    let mut other_checkpoint = fixture.response(5);
    other_checkpoint["mmr_checkpoint_id"] = json!(8);
    assert!(matches!(
        fixture.verify(&other_checkpoint),
        Err(ClientError::Mismatch(_))
    ));

    let mut other_count = fixture.response(5);
    other_count["leaf_count"] = json!(12);
    assert!(matches!(
        fixture.verify(&other_count),
        Err(ClientError::Mismatch(_))
    ));

    let mut other_proof_count = fixture.response(5);
    other_proof_count["proof"]["leaf_count"] = json!(12);
    assert!(matches!(
        fixture.verify(&other_proof_count),
        Err(ClientError::Mismatch(_))
    ));

    let mut other_commitment = fixture.response(5);
    other_commitment["commitment"] = json!(forged_digest);
    assert!(matches!(
        fixture.verify(&other_commitment),
        Err(ClientError::Mismatch(_))
    ));
}

#[test]
fn a_tampered_checkpoint_is_rejected() {
    let response = fixture(13).response(5);
    let forged_digest = sha256(b"forged").to_string();
    let mutations: Vec<(&str, Mutation<'_>)> = vec![
        (
            "peak hash",
            Box::new(|c| c["peaks"][0]["hash"] = json!(forged_digest)),
        ),
        (
            "signature",
            Box::new(|c| {
                let mut text = c["system_signature"].as_str().unwrap().to_owned();
                text.replace_range(0..2, if text.starts_with("00") { "ff" } else { "00" });
                c["system_signature"] = json!(text);
            }),
        ),
        (
            "timestamp",
            Box::new(|c| c["created_at"] = json!("2026-01-01T00:00:00+00:00")),
        ),
        (
            "system_uid",
            Box::new(|c| c["system_uid"] = json!(Uuid::nil().to_string())),
        ),
        (
            "last_integrity_id",
            Box::new(|c| c["last_integrity_id"] = json!(101)),
        ),
    ];
    for (label, mutate) in mutations {
        let mut fixture = fixture(13);
        mutate(&mut fixture.checkpoint);
        assert!(fixture.verify(&response).is_err(), "{label} accepted");
    }
}

#[test]
fn an_unsupported_checkpoint_format_is_rejected() {
    let mut fixture = fixture(5);
    fixture.checkpoint["format_version"] = json!(2);
    assert!(matches!(
        fixture.verify(&fixture.response(1)),
        Err(ClientError::UnsupportedFormat(2))
    ));
}

#[test]
fn malformed_inputs_are_reported_as_such() {
    let fixture = fixture(5);
    let good = fixture.response(1);
    let key = fixture.key;
    let check = |proof: &str, checkpoint: &str| {
        verify_api_proof(proof, checkpoint, &key, &Expectations::default())
    };
    let checkpoint = fixture.checkpoint.to_string();

    assert!(matches!(
        check("not json", &checkpoint),
        Err(ClientError::Malformed { .. })
    ));
    assert!(matches!(
        check(&good.to_string(), "{}"),
        Err(ClientError::Malformed { .. })
    ));

    let mut unknown_field = good.clone();
    unknown_field["proof"]["extra"] = json!(1);
    assert!(matches!(
        check(&unknown_field.to_string(), &checkpoint),
        Err(ClientError::Malformed { .. })
    ));

    let mut short_signature = fixture.checkpoint.clone();
    short_signature["system_signature"] = json!("00".repeat(63));
    assert!(matches!(
        check(&good.to_string(), &short_signature.to_string()),
        Err(ClientError::Malformed { .. })
    ));

    let mut bad_uid = fixture.checkpoint.clone();
    bad_uid["system_uid"] = json!("not-a-uuid");
    assert!(matches!(
        check(&good.to_string(), &bad_uid.to_string()),
        Err(ClientError::Malformed { .. })
    ));

    let mut bad_time = fixture.checkpoint.clone();
    bad_time["created_at"] = json!("yesterday");
    assert!(matches!(
        check(&good.to_string(), &bad_time.to_string()),
        Err(ClientError::Malformed { .. })
    ));

    let mut entry = fixture.entry(1);
    entry["record_hash"] = json!("abcd");
    assert!(matches!(
        fixture.verify_with_entry(&good, &entry),
        Err(ClientError::Malformed { .. })
    ));
    assert!(matches!(
        fixture.verify_with_entry(&good, &json!({"integrity_id": 1001})),
        Err(ClientError::Malformed { .. })
    ));
}

/// Runs `relic-verify-proof` on files written to a temporary directory.
struct Cli {
    directory: tempfile::TempDir,
}

impl Cli {
    fn new() -> Self {
        Self {
            directory: tempfile::tempdir().unwrap(),
        }
    }

    fn file(&self, name: &str, contents: &str) -> String {
        let path = self.directory.path().join(name);
        fs::write(&path, contents).unwrap();
        path.to_str().unwrap().to_owned()
    }

    fn run<S: AsRef<std::ffi::OsStr>>(
        &self,
        args: &[S],
        stdin: Option<&str>,
    ) -> (Option<i32>, String, String) {
        let mut command = Command::new(env!("CARGO_BIN_EXE_relic-verify-proof"));
        command.current_dir(self.directory.path()).args(args);
        let output = if let Some(input) = stdin {
            use std::io::Write as _;
            let mut child = command
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .unwrap();
            if let Err(error) = child.stdin.take().unwrap().write_all(input.as_bytes()) {
                // A command that rejects its arguments before reading stdin
                // may close the pipe before this test process writes to it.
                // Its exit status and stderr are asserted by the caller.
                assert_eq!(error.kind(), std::io::ErrorKind::BrokenPipe);
            }
            child.wait_with_output().unwrap()
        } else {
            command.output().unwrap()
        };
        (
            output.status.code(),
            String::from_utf8(output.stdout).unwrap(),
            String::from_utf8(output.stderr).unwrap(),
        )
    }

    fn path(&self, name: &str) -> String {
        self.directory
            .path()
            .join(name)
            .to_str()
            .unwrap()
            .to_owned()
    }
}

#[test]
fn the_command_ties_the_proof_to_the_entry_and_reports_what_it_established() {
    let fixture = fixture(11);
    let command = Cli::new();
    let checkpoint = command.file("checkpoint.json", &fixture.checkpoint.to_string());
    let proof = command.file("proof.json", &fixture.response(6).to_string());
    let entry = command.file("entry.json", &fixture.entry(6).to_string());
    let key = hex(&fixture.key);
    let source = fixture.envelopes[6].source_id.clone();
    let record = fixture.envelopes[6].record_hash.to_string();
    let commitment = fixture.checkpoint["commitment"]
        .as_str()
        .unwrap()
        .to_owned();
    let base = [
        "--proof",
        &proof,
        "--checkpoint",
        &checkpoint,
        "--public-key",
        &key,
    ];
    let with = |extra: &[&str]| -> Vec<String> {
        base.iter()
            .chain(extra)
            .map(|arg| (*arg).to_owned())
            .collect()
    };

    let (code, stdout, stderr) = command.run(
        &with(&[
            "--entry",
            &entry,
            "--source-id",
            &source,
            "--record-hash",
            &record,
            "--system-uid",
            SYSTEM_UID,
            "--commitment",
            &commitment,
        ]),
        None,
    );
    assert_eq!(code, Some(0), "{stdout}{stderr}");
    assert!(
        stdout.starts_with(&format!(
            "VERIFIED: leaf 6 of the MMR checkpoint of 11 entries signed by system account {SYSTEM_UID}\n"
        )),
        "{stdout}"
    );
    assert!(
        stdout.contains("recomputed from the integrity entry"),
        "{stdout}"
    );
    assert!(
        stdout.contains(&format!("source {source} (FIDBF), record hash {record}")),
        "{stdout}"
    );
    assert!(
        stdout.contains("integrity entry 1006 (ids are not covered"),
        "{stdout}"
    );
    assert!(stderr.is_empty(), "{stderr}");

    // The entry may come from standard input.
    let (code, ..) = command.run(
        &with(&["--entry", "-"]),
        Some(&fixture.entry(6).to_string()),
    );
    assert_eq!(code, Some(0));

    // Without the entry the leaf is only the server's word, and it says so.
    let (code, stdout, stderr) = command.run(&base, None);
    assert_eq!(code, Some(0));
    assert!(stdout.contains("as reported by the server"), "{stdout}");
    assert!(stderr.contains("warning"), "{stderr}");
}

#[test]
fn the_command_reports_through_its_exit_status() {
    let fixture = fixture(11);
    let command = Cli::new();
    let checkpoint = command.file("checkpoint.json", &fixture.checkpoint.to_string());
    let proof = command.file("proof.json", &fixture.response(6).to_string());
    let key = hex(&fixture.key);
    let run = |proof: &str, key: &str, extra: &[&str]| {
        let args = [
            &[
                "--proof",
                proof,
                "--checkpoint",
                &checkpoint,
                "--public-key",
                key,
            ][..],
            extra,
        ]
        .concat();
        let (code, stdout, stderr) = command.run(&args, None);
        assert!(
            code != Some(1) || stdout.starts_with("NOT VERIFIED:"),
            "{stdout}{stderr}"
        );
        code
    };

    assert_eq!(run(&proof, &key, &[]), Some(0));
    let expected = fixture.hashes[6].to_string();
    assert_eq!(run(&proof, &key, &["--chain-hash", &expected]), Some(0));

    // 1: the proof does not hold.
    let wrong_leaf = sha256(b"other").to_string();
    assert_eq!(run(&proof, &key, &["--chain-hash", &wrong_leaf]), Some(1));
    let other_key = hex(&SystemSigner::from_seed([1; 32]).verifying_key());
    assert_eq!(run(&proof, &other_key, &[]), Some(1));
    assert_eq!(
        run(&proof, &key, &["--system-uid", &Uuid::nil().to_string()]),
        Some(1)
    );
    let mut forged = fixture.response(6);
    forged["chain_hash"] = json!(sha256(b"forged").to_string());
    let forged = command.file("forged.json", &forged.to_string());
    assert_eq!(run(&forged, &key, &[]), Some(1));

    // 1 as well: whatever the server sent, however broken, is a rejection, so
    // a script that alerts on status 1 cannot be dodged by sending garbage.
    let garbage = command.file("garbage.json", "not json");
    assert_eq!(run(&garbage, &key, &[]), Some(1));
    let not_text = command.path("binary.json");
    fs::write(&not_text, [0xff_u8, 0xfe, 0x00]).unwrap();
    assert_eq!(run(&not_text, &key, &[]), Some(1));
    let huge = command.file("huge.json", &" ".repeat((1 << 20) + 1));
    assert_eq!(run(&huge, &key, &[]), Some(1));
    let bad_entry = command.file("entry.json", "{}");
    assert_eq!(run(&proof, &key, &["--entry", &bad_entry]), Some(1));

    // 2: the command line or a local file is the problem.
    assert_eq!(run(&proof, "zz", &[]), Some(2));
    assert_eq!(run(&command.path("missing.json"), &key, &[]), Some(2));
    assert_eq!(run(&proof, &key, &["--system-uid", "nobody"]), Some(2));
    assert_eq!(
        run(&proof, &key, &["--source-id", &Uuid::nil().to_string()]),
        Some(2)
    );
    assert_eq!(run("-", &key, &["--entry", "-"]), Some(2));
}

#[test]
fn standard_input_can_be_used_only_once() {
    let fixture = fixture(5);
    let command = Cli::new();
    let key = hex(&fixture.key);
    let (code, _, stderr) = command.run(
        &["--proof", "-", "--checkpoint", "-", "--public-key", &key],
        Some(&fixture.response(1).to_string()),
    );
    assert_eq!(code, Some(2));
    assert!(stderr.contains("standard input"), "{stderr}");

    let checkpoint = command.file("checkpoint.json", &fixture.checkpoint.to_string());
    let (code, stdout, stderr) = command.run(
        &[
            "--proof",
            "-",
            "--checkpoint",
            &checkpoint,
            "--public-key",
            &key,
        ],
        Some(&fixture.response(1).to_string()),
    );
    assert_eq!(code, Some(0), "{stdout}{stderr}");
}
