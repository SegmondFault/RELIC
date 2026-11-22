//! Cross-language test vectors for canonical authentication messages.
//!
//! The Python API test-suite verifies its own encoder against the same file.
//! Regenerate deliberately with `RELIC_WRITE_VECTORS=1 cargo test -p relic-crypto`.

use std::{fmt::Write as _, fs, path::PathBuf};

use relic_crypto::{
    SystemSigner, auth, encode_fields, sha256, signing_message, verify_digest_signature,
};
use serde_json::{Value, json};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    })
}

fn vectors_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/auth-v1.json")
}

#[allow(clippy::needless_pass_by_value)]
fn signed_case(
    name: &str,
    seed: [u8; 32],
    record: &[u8],
    signature_domain: &[u8],
    inputs: Value,
) -> Value {
    let signer = SystemSigner::from_seed(seed);
    let digest = sha256(record);
    let signature = signer.sign_digest(signature_domain, &digest);
    assert!(
        verify_digest_signature(
            &signer.verifying_key(),
            signature_domain,
            &digest,
            &signature
        )
        .is_ok()
    );
    json!({
        "name": name,
        "seed": hex(&seed),
        "public_key": hex(&signer.verifying_key()),
        "inputs": inputs,
        "signature_domain": String::from_utf8(signature_domain.to_vec()).unwrap(),
        "record": hex(record),
        "digest": digest.to_string(),
        "signing_message": hex(&signing_message(signature_domain, &digest)),
        "signature": hex(&signature),
    })
}

fn challenge() -> auth::AuthChallenge {
    auth::AuthChallenge {
        challenge_id: *b"\x01\x23\x45\x67\x89\xab\x4c\xde\x8f\x01\x23\x45\x67\x89\xab\xcd",
        nonce: [0x5a; 32],
        audience: "https://relic.example.org".into(),
        expires_at_unix_micros: 1_794_900_000_123_456,
    }
}

fn challenge_json(challenge: &auth::AuthChallenge) -> Value {
    json!({
        "challenge_id": hex(&challenge.challenge_id),
        "nonce": hex(&challenge.nonce),
        "audience": challenge.audience,
        "expires_at_unix_micros": challenge.expires_at_unix_micros,
    })
}

fn build_vectors() -> Value {
    let challenge = challenge();

    let login_seed = [0x11; 32];
    let login_key = SystemSigner::from_seed(login_seed).verifying_key();
    let login = signed_case(
        "login",
        login_seed,
        &auth::login_record(&challenge, &login_key),
        auth::LOGIN_SIGNATURE_DOMAIN,
        json!({ "challenge": challenge_json(&challenge) }),
    );

    let mut registrations = Vec::new();
    for (name, seed, organisation, role) in [
        (
            "registration-with-organisation",
            [0x22; 32],
            Some("Ünïcode Org"),
            "analyst",
        ),
        (
            "registration-without-organisation",
            [0x33; 32],
            None,
            "viewer",
        ),
    ] {
        let public_key = SystemSigner::from_seed(seed).verifying_key();
        let details = auth::RegistrationDetails {
            public_key: &public_key,
            requested_role: role,
            name: "Ada Lovelace",
            organisation,
            email: "ada@example.org",
        };
        registrations.push(signed_case(
            name,
            seed,
            &auth::registration_record(&challenge, &details),
            auth::REGISTRATION_SIGNATURE_DOMAIN,
            json!({
                "challenge": challenge_json(&challenge),
                "requested_role": role,
                "name": details.name,
                "organisation": organisation,
                "email": details.email,
            }),
        ));
    }

    let request_id = *b"\x3c\x9e\x1d\x52\x0b\x7a\x4f\x10\x9e\x44\xd2\x61\x05\xaa\x7b\x38";
    let moderator_id = *b"\x9d\x02\x6e\x41\x5c\xb3\x47\x88\x81\x0f\x3a\x5e\xc4\x27\x19\x6b";
    let moderator_seed = [0x44; 32];
    let mut decisions = Vec::new();
    for (name, applicant_seed, organisation, decision) in [
        (
            "decision-approved",
            [0x22; 32],
            Some("Ünïcode Org"),
            auth::RegistrationDecision::Approved,
        ),
        (
            "decision-rejected",
            [0x33; 32],
            None,
            auth::RegistrationDecision::Rejected,
        ),
    ] {
        let public_key = SystemSigner::from_seed(applicant_seed).verifying_key();
        let details = auth::RegistrationDetails {
            public_key: &public_key,
            requested_role: "analyst",
            name: "Ada Lovelace",
            organisation,
            email: "ada@example.org",
        };
        decisions.push(signed_case(
            name,
            moderator_seed,
            &auth::registration_decision_record(&request_id, &details, &moderator_id, decision),
            auth::REGISTRATION_DECISION_SIGNATURE_DOMAIN,
            json!({
                "registration_request_id": hex(&request_id),
                "applicant_public_key": hex(&public_key),
                "requested_role": details.requested_role,
                "name": details.name,
                "organisation": organisation,
                "email": details.email,
                "moderator_id": hex(&moderator_id),
                "decision": decision.as_str(),
            }),
        ));
    }

    json!({
        "format": "relic-auth-vectors/1",
        "registration_decision": decisions,
        "encode_fields": [{
            "domain": "RELIC:test:v1",
            "fields": [hex(b"ab"), hex(b"c"), ""],
            "encoded": hex(&encode_fields(b"RELIC:test:v1", &[b"ab", b"c", b""])),
        }],
        "login": [login],
        "registration": registrations,
    })
}

#[test]
fn auth_vectors_match_committed_file() {
    let generated = build_vectors();
    let path = vectors_path();
    if std::env::var_os("RELIC_WRITE_VECTORS").is_some() {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let mut text = serde_json::to_string_pretty(&generated).unwrap();
        text.push('\n');
        fs::write(&path, text).unwrap();
    }
    let committed: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(
        committed, generated,
        "canonical auth encoding changed; bump the version instead of editing v1"
    );
}
