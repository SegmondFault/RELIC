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

/// One signed revocation request and an approved and a rejected decision on it.
fn revocation_vectors(
    moderator_id: &[u8; 16],
    moderator_seed: [u8; 32],
) -> (Vec<Value>, Vec<Value>) {
    let revocation_id = *b"\x5b\x1f\x0c\x93\x2e\x64\x4a\x0d\xb1\x7c\x08\xe2\x55\x3d\x91\xa4";
    let requester_id = *b"\x74\x4a\xb7\x4c\xf1\xd6\x42\x1a\xa4\x17\x60\x30\xef\x9e\x86\x06";
    let target_id = *b"\xc2\x48\x6a\x1e\x90\x3b\x4d\x75\x8f\x26\xe0\x14\x7d\xb9\x52\x0f";
    let revocation = auth::RevocationRequest {
        revocation_id: &revocation_id,
        requester_id: &requester_id,
        target_type: "user",
        target_id: &target_id,
        reason: "Key reported lost — Schlüssel verloren",
    };
    let revocation_json = json!({
        "revocation_id": hex(&revocation_id),
        "requester_id": hex(&requester_id),
        "target_type": revocation.target_type,
        "target_id": hex(&target_id),
        "reason": revocation.reason,
    });
    let revocation_requests = vec![signed_case(
        "revocation-request",
        [0x55; 32],
        &auth::revocation_request_record(&revocation),
        auth::REVOCATION_REQUEST_SIGNATURE_DOMAIN,
        revocation_json.clone(),
    )];
    let revocation_decisions: Vec<Value> = [
        ("revocation-approved", auth::Decision::Approved),
        ("revocation-rejected", auth::Decision::Rejected),
    ]
    .into_iter()
    .map(|(name, decision)| {
        let mut inputs = revocation_json.clone();
        inputs["moderator_id"] = json!(hex(moderator_id));
        inputs["decision"] = json!(decision.as_str());
        signed_case(
            name,
            moderator_seed,
            &auth::revocation_decision_record(&revocation, moderator_id, decision),
            auth::REVOCATION_DECISION_SIGNATURE_DOMAIN,
            inputs,
        )
    })
    .collect();
    (revocation_requests, revocation_decisions)
}

/// One signed flag and one signed response to it.
fn flag_vectors() -> (Vec<Value>, Vec<Value>) {
    let flag_id = *b"\x0e\x6d\x2a\x71\x8c\x15\x4b\x39\x9a\x52\x1f\xc0\x33\x87\xe4\x6b";
    let viewer_id = *b"\x2f\x90\x4c\x1b\x67\xa8\x4e\x02\xb5\x3d\x7c\x19\xe6\x40\x8a\x5d";
    let target_id = *b"\xa1\x37\x5e\x08\xd4\x6c\x41\x9f\x83\x2b\x90\x4e\x17\xf5\x6a\xc2";
    let response_id = *b"\x63\xb8\x19\xe2\x45\x0d\x4a\x76\x9c\x31\x58\xaf\x02\xd7\x6e\x94";
    let analyst_id = *b"\x74\x4a\xb7\x4c\xf1\xd6\x42\x1a\xa4\x17\x60\x30\xef\x9e\x86\x06";
    let flag = auth::Flag {
        flag_id: &flag_id,
        viewer_id: &viewer_id,
        target_type: "binary",
        target_id: &target_id,
        note: "Wrong licence — falsche Lizenz",
    };
    let flag_json = json!({
        "flag_id": hex(&flag_id),
        "viewer_id": hex(&viewer_id),
        "target_type": flag.target_type,
        "target_id": hex(&target_id),
        "note": flag.note,
    });
    let flags = vec![signed_case(
        "flag",
        [0x66; 32],
        &auth::flag_record(&flag),
        auth::FLAG_SIGNATURE_DOMAIN,
        flag_json.clone(),
    )];
    let note = "Checked: licence corrected";
    let mut inputs = flag_json;
    inputs["flag_response_id"] = json!(hex(&response_id));
    inputs["analyst_id"] = json!(hex(&analyst_id));
    inputs["response_note"] = json!(note);
    let responses = vec![signed_case(
        "flag-response",
        [0x55; 32],
        &auth::flag_response_record(&flag, &response_id, &analyst_id, note),
        auth::FLAG_RESPONSE_SIGNATURE_DOMAIN,
        inputs,
    )];
    (flags, responses)
}

/// Licence assertions (with and without optional fields) and classifications.
fn claim_vectors() -> (Vec<Value>, Vec<Value>) {
    let analyst_id = *b"\x74\x4a\xb7\x4c\xf1\xd6\x42\x1a\xa4\x17\x60\x30\xef\x9e\x86\x06";
    let target_id = *b"\xa1\x37\x5e\x08\xd4\x6c\x41\x9f\x83\x2b\x90\x4e\x17\xf5\x6a\xc2";
    let evidence_id = *b"\x19\x2c\x7d\x4e\x5f\x60\x41\x82\x93\xa4\xb5\xc6\xd7\xe8\xf9\x0a";
    let mut licenses = Vec::new();
    for (name, id_byte, confidence, evidence) in [
        (
            "license-assertion-full",
            0x31_u8,
            Some("0.9500"),
            Some(&evidence_id),
        ),
        ("license-assertion-minimal", 0x32_u8, None, None),
    ] {
        let id = [id_byte; 16];
        let assertion = auth::LicenseAssertion {
            license_assertion_id: &id,
            analyst_id: &analyst_id,
            target_type: "binary",
            target_id: &target_id,
            spdx_expression: "(MIT OR Apache-2.0) AND GPL-2.0-only WITH Classpath-exception-2.0",
            basis: "detected",
            confidence,
            evidence_provenance_id: evidence,
        };
        licenses.push(signed_case(
            name,
            [0x55; 32],
            &auth::license_assertion_record(&assertion),
            auth::LICENSE_ASSERTION_SIGNATURE_DOMAIN,
            json!({
                "license_assertion_id": hex(&id),
                "analyst_id": hex(&analyst_id),
                "target_type": assertion.target_type,
                "target_id": hex(&target_id),
                "spdx_expression": assertion.spdx_expression,
                "basis": assertion.basis,
                "confidence": confidence,
                "evidence_provenance_id": evidence.map(|id| hex(id)),
            }),
        ));
    }
    let misp_uuid = *b"\x5e\x6f\x70\x81\x92\xa3\x4b\xc4\x8d\xe5\xf6\x07\x18\x29\x3a\x4b";
    let mut classifications = Vec::new();
    for (name, id_byte, confidence, misp, evidence) in [
        (
            "classification-full",
            0x41_u8,
            Some("1.0000"),
            Some(("mitre-attack-pattern", &misp_uuid)),
            Some("{\"tool\": \"capa\",  \"score\": 0.93, \"Ünïcode\": [1, 2]}"),
        ),
        ("classification-minimal", 0x42_u8, None, None, None),
    ] {
        let id = [id_byte; 16];
        let classification = auth::Classification {
            classification_id: &id,
            analyst_id: &analyst_id,
            target_type: "function",
            target_id: &target_id,
            label: "crypto/aes-key-expansion",
            confidence,
            misp_universe: misp.map(|(universe, _)| universe),
            misp_uuid: misp.map(|(_, uuid)| uuid),
            evidence_json: evidence,
        };
        classifications.push(signed_case(
            name,
            [0x55; 32],
            &auth::classification_record(&classification),
            auth::CLASSIFICATION_SIGNATURE_DOMAIN,
            json!({
                "classification_id": hex(&id),
                "analyst_id": hex(&analyst_id),
                "target_type": classification.target_type,
                "target_id": hex(&target_id),
                "label": classification.label,
                "confidence": confidence,
                "misp_universe": classification.misp_universe,
                "misp_uuid": misp.map(|(_, uuid)| hex(uuid)),
                "evidence_json": evidence,
            }),
        ));
    }
    (licenses, classifications)
}

/// Software components, releases, binary-component assertions and
/// behavioural compositions (with and without optional fields).
#[allow(clippy::too_many_lines)]
fn component_vectors() -> Value {
    let analyst_id = *b"\x74\x4a\xb7\x4c\xf1\xd6\x42\x1a\xa4\x17\x60\x30\xef\x9e\x86\x06";
    let component_id = [0x51_u8; 16];
    let release_id = [0x52_u8; 16];
    let source_id = *b"\x2d\x3e\x4f\x50\x61\x72\x43\x84\x95\xa6\xb7\xc8\xd9\xea\xfb\x0c";
    let binary_id = *b"\xa1\x37\x5e\x08\xd4\x6c\x41\x9f\x83\x2b\x90\x4e\x17\xf5\x6a\xc2";
    let function_id = *b"\xc4\x15\x26\x37\x48\x59\x4a\x6b\x8c\x7d\x8e\x9f\xa0\xb1\xc2\xd3";
    let evidence_id = *b"\x19\x2c\x7d\x4e\x5f\x60\x41\x82\x93\xa4\xb5\xc6\xd7\xe8\xf9\x0a";
    let seed = [0x55; 32];

    let mut components = Vec::new();
    for (name, id, namespace, purl) in [
        (
            "software-component-full",
            component_id,
            Some("openssl.org"),
            Some("pkg:generic/openssl@3.0.13"),
        ),
        ("software-component-minimal", [0x53_u8; 16], None, None),
    ] {
        let component = auth::SoftwareComponent {
            component_id: &id,
            analyst_id: &analyst_id,
            name: "OpenSSL Ünïcode",
            component_kind: "library",
            namespace,
            purl,
        };
        components.push(signed_case(
            name,
            seed,
            &auth::software_component_record(&component),
            auth::SOFTWARE_COMPONENT_SIGNATURE_DOMAIN,
            json!({
                "component_id": hex(&id),
                "analyst_id": hex(&analyst_id),
                "name": component.name,
                "component_kind": component.component_kind,
                "namespace": namespace,
                "purl": purl,
            }),
        ));
    }

    let mut releases = Vec::new();
    for (name, id, version, source) in [
        (
            "software-release-full",
            release_id,
            Some("3.0.13"),
            Some(&source_id),
        ),
        ("software-release-minimal", [0x54_u8; 16], None, None),
    ] {
        let release = auth::SoftwareRelease {
            software_release_id: &id,
            analyst_id: &analyst_id,
            component_id: &component_id,
            version,
            source_id: source,
        };
        releases.push(signed_case(
            name,
            seed,
            &auth::software_release_record(&release),
            auth::SOFTWARE_RELEASE_SIGNATURE_DOMAIN,
            json!({
                "software_release_id": hex(&id),
                "analyst_id": hex(&analyst_id),
                "component_id": hex(&component_id),
                "version": version,
                "source_id": source.map(|id| hex(id)),
            }),
        ));
    }

    let mut assertions = Vec::new();
    for (name, id, confidence, evidence) in [
        (
            "binary-component-assertion-full",
            [0x56_u8; 16],
            Some("0.7500"),
            Some(&evidence_id),
        ),
        (
            "binary-component-assertion-minimal",
            [0x57_u8; 16],
            None,
            None,
        ),
    ] {
        let assertion = auth::BinaryComponentAssertion {
            binary_component_assertion_id: &id,
            analyst_id: &analyst_id,
            binary_id: &binary_id,
            software_release_id: &release_id,
            relationship: "statically_contains",
            basis: "detected",
            confidence,
            evidence_provenance_id: evidence,
        };
        assertions.push(signed_case(
            name,
            seed,
            &auth::binary_component_assertion_record(&assertion),
            auth::BINARY_COMPONENT_ASSERTION_SIGNATURE_DOMAIN,
            json!({
                "binary_component_assertion_id": hex(&id),
                "analyst_id": hex(&analyst_id),
                "binary_id": hex(&binary_id),
                "software_release_id": hex(&release_id),
                "relationship": assertion.relationship,
                "basis": assertion.basis,
                "confidence": confidence,
                "evidence_provenance_id": evidence.map(|id| hex(id)),
            }),
        ));
    }

    // Listed out of canonical order on purpose: the record sorts members.
    let members = [
        auth::CompositionMember {
            target_type: "function",
            target_id: &function_id,
            member_role: "decryptor",
            sequence_number: Some(2),
        },
        auth::CompositionMember {
            target_type: "binary",
            target_id: &binary_id,
            member_role: "loader",
            sequence_number: Some(1),
        },
        auth::CompositionMember {
            target_type: "binary",
            target_id: &binary_id,
            member_role: "persistence",
            sequence_number: None,
        },
    ];
    let members_json = |members: &[auth::CompositionMember<'_>]| -> Value {
        members
            .iter()
            .map(|member| {
                json!({
                    "target_type": member.target_type,
                    "target_id": hex(member.target_id),
                    "member_role": member.member_role,
                    "sequence_number": member.sequence_number,
                })
            })
            .collect()
    };
    let mut compositions = Vec::new();
    for (name, id, description, evidence, members) in [
        (
            "behavioural-composition-full",
            [0x58_u8; 16],
            Some("Loader drops and decrypts a payload"),
            Some(&evidence_id),
            &members[..],
        ),
        (
            "behavioural-composition-minimal",
            [0x59_u8; 16],
            None,
            None,
            &members[1..2],
        ),
    ] {
        let composition = auth::BehaviouralComposition {
            behavioural_composition_id: &id,
            analyst_id: &analyst_id,
            name: "Staged loader",
            description,
            evidence_provenance_id: evidence,
            members,
        };
        let mut reversed = members.to_vec();
        reversed.reverse();
        assert_eq!(
            auth::behavioural_composition_record(&composition),
            auth::behavioural_composition_record(&auth::BehaviouralComposition {
                members: &reversed,
                ..composition
            }),
            "member order must not change the record"
        );
        compositions.push(signed_case(
            name,
            seed,
            &auth::behavioural_composition_record(&composition),
            auth::BEHAVIOURAL_COMPOSITION_SIGNATURE_DOMAIN,
            json!({
                "behavioural_composition_id": hex(&id),
                "analyst_id": hex(&analyst_id),
                "name": composition.name,
                "description": description,
                "evidence_provenance_id": evidence.map(|id| hex(id)),
                "members": members_json(members),
            }),
        ));
    }

    json!({
        "software_component": components,
        "software_release": releases,
        "binary_component_assertion": assertions,
        "behavioural_composition": compositions,
    })
}

/// Registration proofs, with and without an organisation.
fn registration_vectors(challenge: &auth::AuthChallenge) -> Vec<Value> {
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
            &auth::registration_record(challenge, &details),
            auth::REGISTRATION_SIGNATURE_DOMAIN,
            json!({
                "challenge": challenge_json(challenge),
                "requested_role": role,
                "name": details.name,
                "organisation": organisation,
                "email": details.email,
            }),
        ));
    }
    registrations
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

    let registrations = registration_vectors(&challenge);

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

    let (revocation_requests, revocation_decisions) =
        revocation_vectors(&moderator_id, moderator_seed);

    let (flags, flag_responses) = flag_vectors();
    let (license_assertions, classifications) = claim_vectors();

    json!({
        "format": "relic-auth-vectors/1",
        "license_assertion": license_assertions,
        "classification": classifications,
        "components": component_vectors(),
        "flag": flags,
        "flag_response": flag_responses,
        "registration_decision": decisions,
        "revocation_request": revocation_requests,
        "revocation_decision": revocation_decisions,
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
