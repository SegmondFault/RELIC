//! Cross-language test vectors for the MMR, its inclusion proofs and the
//! checkpoint signature.
//!
//! The Python API test-suite checks its own implementation against the same
//! file, so the server and the Rust verifier can never drift apart.
//! Regenerate deliberately with
//! `RELIC_WRITE_VECTORS=1 cargo test -p relic-proof --test inclusion_vectors`.

use std::{fmt::Write as _, fs, path::PathBuf};

use relic_crypto::{Digest32, SystemSigner, sha256};
use relic_proof::{
    MmrFrontier,
    proof::{InclusionProof, PROOF_FORMAT_VERSION, prove},
    sign_checkpoint,
};
use serde_json::{Value, json};

const LEAF_COUNTS: [u64; 8] = [1, 2, 3, 5, 7, 8, 13, 21];

fn vectors_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/inclusion-v1.json")
}

fn chain(length: u64) -> Vec<Digest32> {
    (0..length)
        .map(|index| sha256(format!("relic-mmr-vector-{index}").as_bytes()))
        .collect()
}

fn frontier_of(chain_hashes: &[Digest32]) -> MmrFrontier {
    let mut frontier = MmrFrontier::new();
    for hash in chain_hashes {
        frontier.append(*hash).unwrap();
    }
    frontier
}

fn peaks_json(frontier: &MmrFrontier) -> Value {
    Value::Array(
        frontier
            .peaks()
            .iter()
            .map(|peak| {
                json!({
                    "start_index": peak.start_index,
                    "height": peak.height,
                    "hash": peak.hash.to_string(),
                })
            })
            .collect(),
    )
}

fn forged_cases(hashes: &[Digest32]) -> Vec<Value> {
    let length = u64::try_from(hashes.len()).unwrap();
    let genuine = prove(hashes, 5, length).unwrap();
    let mut cases = Vec::new();

    let mut tampered = genuine.clone();
    tampered.siblings[0] = sha256(b"relic-mmr-vector-forged-sibling");
    cases.push(("tampered sibling", tampered, hashes[5]));

    let mut moved = genuine.clone();
    moved.leaf_index = 4;
    cases.push(("wrong leaf index", moved, hashes[5]));

    cases.push((
        "wrong leaf hash",
        genuine.clone(),
        sha256(b"relic-mmr-vector-forged-leaf"),
    ));

    let mut swapped = genuine;
    swapped.siblings.swap(0, 1);
    cases.push(("swapped siblings", swapped, hashes[5]));

    cases
        .into_iter()
        .map(|(name, proof, chain_hash)| {
            json!({
                "name": name,
                "leaf_count": length,
                "chain_hash": chain_hash.to_string(),
                "proof": serde_json::to_value(&proof).unwrap(),
            })
        })
        .collect()
}

fn build() -> Value {
    let hashes = chain(*LEAF_COUNTS.last().unwrap());
    let mut mmrs = Vec::new();
    for length in LEAF_COUNTS {
        let covered = &hashes[..usize::try_from(length).unwrap()];
        let frontier = frontier_of(covered);
        let proofs: Vec<Value> = (0..length)
            .map(|leaf| {
                let proof = prove(covered, leaf, length).unwrap();
                let peak = proof
                    .recompute_peak(&covered[usize::try_from(leaf).unwrap()])
                    .unwrap();
                assert!(frontier.peaks().contains(&peak));
                json!({
                    "leaf_index": leaf,
                    "proof": serde_json::to_value(&proof).unwrap(),
                    "peak": {
                        "start_index": peak.start_index,
                        "height": peak.height,
                        "hash": peak.hash.to_string(),
                    },
                })
            })
            .collect();
        mmrs.push(json!({
            "leaf_count": length,
            "peaks": peaks_json(&frontier),
            "commitment": frontier.commitment().to_string(),
            "proofs": proofs,
        }));
    }
    json!({
        "proof_format_version": PROOF_FORMAT_VERSION,
        "description": "MMR frontiers and inclusion proofs over chain hashes sha256(\"relic-mmr-vector-<i>\")",
        "chain_hashes": hashes.iter().map(ToString::to_string).collect::<Vec<_>>(),
        "mmrs": mmrs,
        "rejected": forged_cases(&hashes[..13]),
        "checkpoint_signature": checkpoint_signature(&hashes[..13]),
    })
}

/// A checkpoint over the first 13 leaves signed with a fixed Ed25519 seed.
/// Ed25519 signatures are deterministic, so another implementation of the
/// checkpoint hash must reproduce this exact signature.
fn checkpoint_signature(chain_hashes: &[Digest32]) -> Value {
    const SEED: [u8; 32] = [0x5a; 32];
    const SYSTEM_UID: &str = "1d0c5f00-7e57-4a11-8c0d-00000000c0de";
    const CREATED_AT_MICROS: i64 = 1_790_000_000_654_321;
    let signer = SystemSigner::from_seed(SEED);
    let checkpoint = sign_checkpoint(
        &frontier_of(chain_hashes),
        1,
        "4242".into(),
        SYSTEM_UID.into(),
        CREATED_AT_MICROS,
        &signer,
    )
    .unwrap();
    checkpoint.verify(&signer.verifying_key()).unwrap();
    let hex = |bytes: &[u8]| {
        bytes.iter().fold(String::new(), |mut out, byte| {
            let _ = write!(out, "{byte:02x}");
            out
        })
    };
    json!({
        "seed": hex(&SEED),
        "public_key": hex(&signer.verifying_key()),
        "format_version": checkpoint.format_version,
        "last_integrity_id": 4242,
        "leaf_count": checkpoint.leaf_count,
        "commitment": checkpoint.commitment.to_string(),
        "system_uid": SYSTEM_UID,
        "created_at_micros": CREATED_AT_MICROS,
        "system_signature": hex(&checkpoint.system_signature),
    })
}

#[test]
fn vectors_are_current_and_verify() {
    let expected = build();
    let path = vectors_path();
    if std::env::var_os("RELIC_WRITE_VECTORS").is_some() {
        let mut text = serde_json::to_string_pretty(&expected).unwrap();
        text.push('\n');
        fs::write(&path, text).unwrap();
    }
    let stored: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(
        stored, expected,
        "vectors are stale; regenerate deliberately with RELIC_WRITE_VECTORS=1"
    );
    // Sequential on purpose: the file may have just been rewritten.
    assert_forged_vectors_do_not_reach_a_peak(&stored);
}

fn assert_forged_vectors_do_not_reach_a_peak(stored: &Value) {
    let thirteen = stored["mmrs"]
        .as_array()
        .unwrap()
        .iter()
        .find(|mmr| mmr["leaf_count"] == 13)
        .unwrap();
    let peak_hashes: Vec<&str> = thirteen["peaks"]
        .as_array()
        .unwrap()
        .iter()
        .map(|peak| peak["hash"].as_str().unwrap())
        .collect();
    for case in stored["rejected"].as_array().unwrap() {
        let proof: InclusionProof = serde_json::from_value(case["proof"].clone()).unwrap();
        let chain_hash: Digest32 = case["chain_hash"].as_str().unwrap().parse().unwrap();
        let peak = proof.recompute_peak(&chain_hash).unwrap();
        assert!(
            !peak_hashes.contains(&peak.hash.to_string().as_str()),
            "{} reached a genuine peak",
            case["name"]
        );
    }
}
