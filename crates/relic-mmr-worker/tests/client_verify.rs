//! The API's JSON, checked the way a client would: `verify_api_proof` and the
//! `relic-verify-proof` command.

use std::{fmt::Write as _, fs, process::Command};

use chrono::DateTime;
use relic_crypto::{Digest32, SystemSigner, sha256};
use relic_mmr_worker::{
    MmrFrontier,
    client::{ClientError, verify_api_proof},
    proof::{ProofError, prove},
    sign_checkpoint,
};
use serde_json::{Value, json};

type Mutation<'a> = Box<dyn Fn(&mut Value) + 'a>;

const SYSTEM_UID: &str = "7c9f1c2e-31a5-4b53-9d0e-0c8e8a8a1b11";
const CREATED_AT_MICROS: i64 = 1_790_000_000_123_456;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    })
}

struct Fixture {
    hashes: Vec<Digest32>,
    key: [u8; 32],
    checkpoint: Value,
    leaf_count: u64,
}

fn fixture(length: u64) -> Fixture {
    let system = SystemSigner::from_seed([42; 32]);
    let hashes: Vec<Digest32> = (0..length)
        .map(|index| sha256(&index.to_be_bytes()))
        .collect();
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
    let signature = hex(&signed.system_signature);
    // Python's isoformat(): microseconds and a numeric offset, as the API prints it.
    let created_at = DateTime::from_timestamp_micros(CREATED_AT_MICROS)
        .unwrap()
        .format("%Y-%m-%dT%H:%M:%S%.6f+00:00")
        .to_string();
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
        "created_at": created_at,
        "system_uid": SYSTEM_UID,
        "system_signature": signature,
    });
    Fixture {
        hashes,
        key: system.verifying_key(),
        checkpoint,
        leaf_count: length,
    }
}

impl Fixture {
    fn response(&self, leaf: u64) -> Value {
        let proof = prove(&self.hashes, leaf, self.leaf_count).unwrap();
        json!({
            "integrity_id": 1000 + leaf,
            "chain_hash": self.hashes[usize::try_from(leaf).unwrap()].to_string(),
            "mmr_checkpoint_id": 7,
            "leaf_count": self.leaf_count,
            "commitment": self.checkpoint["commitment"],
            "proof": serde_json::to_value(&proof).unwrap(),
        })
    }

    fn verify(&self, response: &Value) -> Result<(), ClientError> {
        verify_api_proof(
            &response.to_string(),
            &self.checkpoint.to_string(),
            &self.key,
            None,
        )
        .map(|_| ())
    }
}

#[test]
fn every_leaf_verifies_against_the_api_shaped_json() {
    for length in [1, 2, 7, 13, 20] {
        let fixture = fixture(length);
        for leaf in 0..length {
            let verified = verify_api_proof(
                &fixture.response(leaf).to_string(),
                &fixture.checkpoint.to_string(),
                &fixture.key,
                Some(&fixture.hashes[usize::try_from(leaf).unwrap()]),
            )
            .unwrap_or_else(|error| panic!("{length}/{leaf}: {error}"));
            assert_eq!(verified.leaf_index, leaf);
            assert_eq!(verified.integrity_id, i64::try_from(1000 + leaf).unwrap());
            assert_eq!(verified.leaf_count, length);
            assert_eq!(verified.system_uid.to_string(), SYSTEM_UID);
        }
    }
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
    let exact = DateTime::from_timestamp_micros(CREATED_AT_MICROS)
        .unwrap()
        .format("%Y-%m-%dT%H:%M:%S%.6fZ")
        .to_string();
    fixture.checkpoint["created_at"] = json!(exact);
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
        None,
    );
    assert!(matches!(
        result,
        Err(ClientError::Rejected(ProofError::Checkpoint(_)))
    ));
}

#[test]
fn a_leaf_other_than_the_expected_one_is_rejected() {
    let fixture = fixture(9);
    let result = verify_api_proof(
        &fixture.response(3).to_string(),
        &fixture.checkpoint.to_string(),
        &fixture.key,
        Some(&sha256(b"the entry I actually recomputed")),
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
        Err(ClientError::Mismatch("checkpoint id"))
    ));

    let mut other_count = fixture.response(5);
    other_count["leaf_count"] = json!(12);
    assert!(matches!(
        fixture.verify(&other_count),
        Err(ClientError::Mismatch("leaf count"))
    ));

    let mut other_proof_count = fixture.response(5);
    other_proof_count["proof"]["leaf_count"] = json!(12);
    assert!(matches!(
        fixture.verify(&other_proof_count),
        Err(ClientError::Mismatch("leaf count"))
    ));

    let mut other_commitment = fixture.response(5);
    other_commitment["commitment"] = json!(forged_digest);
    assert!(matches!(
        fixture.verify(&other_commitment),
        Err(ClientError::Mismatch("commitment"))
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
            Box::new(|c| c["system_uid"] = json!(uuid::Uuid::nil().to_string())),
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
    let check = |proof: &str, checkpoint: &str| verify_api_proof(proof, checkpoint, &key, None);
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
}

#[test]
fn the_command_reports_through_its_exit_status() {
    let fixture = fixture(11);
    let directory = tempfile::tempdir().unwrap();
    let write = |name: &str, value: &Value| {
        let path = directory.path().join(name);
        fs::write(&path, value.to_string()).unwrap();
        path
    };
    let checkpoint = write("checkpoint.json", &fixture.checkpoint);
    let proof = write("proof.json", &fixture.response(6));
    let key = hex(&fixture.key);

    let run = |proof: &std::path::Path, key: &str, extra: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_relic-verify-proof"))
            .args(["--proof", proof.to_str().unwrap()])
            .args(["--checkpoint", checkpoint.to_str().unwrap()])
            .args(["--public-key", key])
            .args(extra)
            .output()
            .unwrap()
    };

    let ok = run(&proof, &key, &[]);
    assert_eq!(
        ok.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&ok.stderr)
    );
    let stdout = String::from_utf8(ok.stdout).unwrap();
    assert!(
        stdout.starts_with("VERIFIED: integrity entry 1006 (leaf 6,"),
        "{stdout}"
    );

    let expected = fixture.hashes[6].to_string();
    assert_eq!(
        run(&proof, &key, &["--chain-hash", &expected])
            .status
            .code(),
        Some(0)
    );

    let wrong_leaf = sha256(b"other").to_string();
    let rejected = run(&proof, &key, &["--chain-hash", &wrong_leaf]);
    assert_eq!(rejected.status.code(), Some(1));
    assert!(
        String::from_utf8(rejected.stdout)
            .unwrap()
            .starts_with("NOT VERIFIED:")
    );

    let other_key = hex(&SystemSigner::from_seed([1; 32]).verifying_key());
    assert_eq!(run(&proof, &other_key, &[]).status.code(), Some(1));

    let mut forged = fixture.response(6);
    forged["chain_hash"] = json!(sha256(b"forged").to_string());
    let forged = write("forged.json", &forged);
    assert_eq!(run(&forged, &key, &[]).status.code(), Some(1));

    // Unusable inputs are a different failure from a proof that does not hold.
    assert_eq!(run(&proof, "zz", &[]).status.code(), Some(2));
    assert_eq!(
        run(&directory.path().join("missing.json"), &key, &[])
            .status
            .code(),
        Some(2)
    );
    let garbage = directory.path().join("garbage.json");
    fs::write(&garbage, "not json").unwrap();
    assert_eq!(run(&garbage, &key, &[]).status.code(), Some(2));
}
