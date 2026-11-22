//! Client-side signer for RELIC account messages.
//!
//! `login` and `register` read a challenge exactly as returned by
//! `POST /v1/auth/challenge`; `decide-registration` and `decide-revocation`
//! read a request exactly as returned by `GET /v1/registrations/{id}` and
//! `GET /v1/revocations/{id}`, and `respond-flag` reads a flag as returned by
//! `GET /v1/flags/{id}`; `request-revocation` and `flag` take their fields as
//! arguments. Each signs the canonical message with the user's OpenSSH Ed25519
//! key and prints the JSON body to POST.

use std::{
    fs,
    path::{Path, PathBuf},
    process::ExitCode,
};

use clap::{Args, Parser, Subcommand};
use relic_crypto::{
    SystemSigner,
    auth::{self, AuthChallenge, Decision, Flag, RegistrationDetails, RevocationRequest},
    read_secret_file, verify_digest_signature,
};
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

#[derive(Debug, Parser)]
#[command(
    about = "Sign RELIC login, registration, revocation and flag messages on the user's machine"
)]
struct Arguments {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Prove possession of a registered key to obtain a session token.
    ///
    /// The account is identified by the key alone; `GET /v1/me` returns its
    /// User ID afterwards.
    Login {
        #[command(flatten)]
        common: Common,
    },
    /// Prove possession of a new key when requesting an account.
    Register {
        #[command(flatten)]
        common: Common,
        #[arg(long, value_parser = ["viewer", "analyst", "moderator"])]
        role: String,
        #[arg(long)]
        name: String,
        #[arg(long)]
        organisation: Option<String>,
        #[arg(long)]
        email: String,
    },
    /// Sign a Moderator's decision on a pending registration request.
    DecideRegistration {
        /// Request JSON returned by `GET /v1/registrations/{id}`.
        #[arg(long)]
        request: PathBuf,
        /// The deciding Moderator's own User ID.
        #[arg(long)]
        moderator_id: Uuid,
        #[arg(long, value_parser = ["approved", "rejected"])]
        decision: String,
        #[command(flatten)]
        key: KeyArgs,
    },
    /// Sign an Analyst's request to revoke a catalogue object or account.
    RequestRevocation {
        /// The requesting Analyst's own User ID.
        #[arg(long)]
        analyst_id: Uuid,
        #[arg(long, value_parser = TARGET_TYPES)]
        target_type: String,
        #[arg(long)]
        target_id: Uuid,
        #[arg(long)]
        reason: String,
        /// Request ID; a fresh random UUID if omitted. Reuse it to retry.
        #[arg(long)]
        revocation_id: Option<Uuid>,
        #[command(flatten)]
        key: KeyArgs,
    },
    /// Sign a Moderator's decision on a pending revocation request.
    ///
    /// Verifies the request's signature with the requester's registered key
    /// and shows the target before signing; refuses if either check fails.
    DecideRevocation {
        /// Request JSON returned by `GET /v1/revocations/{id}`.
        #[arg(long)]
        request: PathBuf,
        /// The requesting Analyst, as returned by `GET /v1/users/{analyst_id}`.
        #[arg(long)]
        requester: PathBuf,
        /// The target, as returned by its read route (e.g. `GET /v1/users/{id}`,
        /// `GET /v1/fidbf/{id}`). Required unless its type has no read route.
        #[arg(long)]
        target: Option<PathBuf>,
        /// The deciding Moderator's own User ID.
        #[arg(long)]
        moderator_id: Uuid,
        #[arg(long, value_parser = ["approved", "rejected"])]
        decision: String,
        #[command(flatten)]
        key: KeyArgs,
    },
    /// Sign a Viewer's flag on a catalogue object, account, flag or response.
    Flag {
        /// The flagging Viewer's own User ID.
        #[arg(long)]
        viewer_id: Uuid,
        #[arg(long, value_parser = TARGET_TYPES)]
        target_type: String,
        #[arg(long)]
        target_id: Uuid,
        #[arg(long)]
        note: String,
        /// Flag ID; a fresh random UUID if omitted. Reuse it to retry.
        #[arg(long)]
        flag_id: Option<Uuid>,
        #[command(flatten)]
        key: KeyArgs,
    },
    /// Sign an Analyst's response to a flag.
    RespondFlag {
        /// Flag JSON returned by `GET /v1/flags/{id}`.
        #[arg(long)]
        flag: PathBuf,
        /// The responding Analyst's own User ID.
        #[arg(long)]
        analyst_id: Uuid,
        #[arg(long)]
        note: String,
        /// Response ID; a fresh random UUID if omitted. Reuse it to retry.
        #[arg(long)]
        flag_response_id: Option<Uuid>,
        #[command(flatten)]
        key: KeyArgs,
    },
}

/// `catalogue.corpus_target_type`.
const TARGET_TYPES: [&str; 16] = [
    "user",
    "source",
    "batch",
    "binary",
    "function",
    "fidbf",
    "bsim",
    "provenance",
    "license_assertion",
    "software_component",
    "software_release",
    "binary_component_assertion",
    "behavioural_composition",
    "classification",
    "flag",
    "flag_response",
];

#[derive(Debug, Args)]
struct Common {
    /// Challenge JSON returned by `POST /v1/auth/challenge`.
    #[arg(long)]
    challenge: PathBuf,
    #[command(flatten)]
    key: KeyArgs,
}

#[derive(Debug, Args)]
struct KeyArgs {
    /// OpenSSH Ed25519 private key.
    #[arg(long)]
    key: PathBuf,
    /// File holding the key passphrase (mode 0600).
    #[arg(long)]
    key_passphrase_file: Option<PathBuf>,
}

#[derive(Debug, Deserialize)]
struct RegistrationFile {
    registration_request_id: Uuid,
    status: String,
    public_key: String,
    requested_role: String,
    name: String,
    organisation: Option<String>,
    email: String,
}

#[derive(Debug, Deserialize)]
struct RevocationFile {
    revocation_id: Uuid,
    status: String,
    analyst_id: Uuid,
    target_type: String,
    target_id: Uuid,
    reason: String,
    request_signature: String,
}

/// A public identity as returned by `GET /v1/users/{id}`.
#[derive(Debug, Deserialize)]
struct UserFile {
    user_id: Uuid,
    role: Option<String>,
    public_key: String,
    revoked: bool,
}

/// Target types without a read route, whose details cannot be shown yet.
const UNREADABLE_TARGET_TYPES: [&str; 4] = [
    "software_component",
    "software_release",
    "binary_component_assertion",
    "behavioural_composition",
];

#[derive(Debug, Deserialize)]
struct FlagFile {
    flag_id: Uuid,
    viewer_id: Uuid,
    target_type: String,
    target_id: Uuid,
    note: String,
    revoked: bool,
}

#[derive(Debug, Deserialize)]
struct ChallengeFile {
    challenge_id: Uuid,
    nonce: String,
    audience: String,
    expires_at_unix_micros: i64,
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("relic-sign-challenge: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let body = match Arguments::parse().command {
        Command::Login { common } => login(&common)?,
        Command::Register {
            common,
            role,
            name,
            organisation,
            email,
        } => {
            let (challenge_id, challenge, signer) = load(&common)?;
            let public_key = signer.verifying_key();
            let details = RegistrationDetails {
                public_key: &public_key,
                requested_role: &role,
                name: &name,
                organisation: organisation.as_deref(),
                email: &email,
            };
            let digest = auth::registration_digest(&challenge, &details);
            let signature = signer.sign_digest(auth::REGISTRATION_SIGNATURE_DOMAIN, &digest);
            json!({
                "challenge_id": challenge_id,
                "public_key": hex(&public_key),
                "requested_role": role,
                "name": name,
                "organisation": organisation,
                "email": email,
                "signature": hex(&signature),
            })
        }
        Command::DecideRegistration {
            request,
            moderator_id,
            decision,
            key,
        } => decide_registration(&request, moderator_id, parse_decision(&decision), &key)?,
        Command::RequestRevocation {
            analyst_id,
            target_type,
            target_id,
            reason,
            revocation_id,
            key,
        } => request_revocation(
            revocation_id.unwrap_or_else(Uuid::new_v4),
            analyst_id,
            &target_type,
            target_id,
            &reason,
            &key,
        )?,
        Command::DecideRevocation {
            request,
            requester,
            target,
            moderator_id,
            decision,
            key,
        } => decide_revocation(
            [&request, &requester],
            target.as_deref(),
            moderator_id,
            parse_decision(&decision),
            &key,
        )?,
        Command::Flag {
            viewer_id,
            target_type,
            target_id,
            note,
            flag_id,
            key,
        } => flag(
            &Flag {
                flag_id: flag_id.unwrap_or_else(Uuid::new_v4).as_bytes(),
                viewer_id: viewer_id.as_bytes(),
                target_type: &target_type,
                target_id: target_id.as_bytes(),
                note: &note,
            },
            &key,
        )?,
        Command::RespondFlag {
            flag,
            analyst_id,
            note,
            flag_response_id,
            key,
        } => respond_flag(
            &flag,
            flag_response_id.unwrap_or_else(Uuid::new_v4),
            analyst_id,
            &note,
            &key,
        )?,
    };
    println!("{}", serde_json::to_string_pretty(&body)?);
    Ok(())
}

/// Body for `POST /v1/registrations/{id}/decision`, signed over the request as stored.
fn decide_registration(
    request: &Path,
    moderator_id: Uuid,
    verdict: Decision,
    key: &KeyArgs,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let file: RegistrationFile = serde_json::from_slice(&fs::read(request)?)?;
    if file.status != "pending" {
        return Err(format!("request is already {}", file.status).into());
    }
    let public_key: [u8; 32] = unhex(&file.public_key)?
        .try_into()
        .map_err(|_| "applicant public key must be 32 bytes")?;
    let details = RegistrationDetails {
        public_key: &public_key,
        requested_role: &file.requested_role,
        name: &file.name,
        organisation: file.organisation.as_deref(),
        email: &file.email,
    };
    // Show exactly what is being signed before signing it.
    eprintln!(
        "Signing: {} registration {} for {} <{}>{} as {}, key {}",
        verdict.as_str(),
        file.registration_request_id,
        file.name,
        file.email,
        file.organisation
            .as_deref()
            .map(|org| format!(" ({org})"))
            .unwrap_or_default(),
        file.requested_role,
        file.public_key,
    );
    let signer = load_key(key)?;
    let digest = auth::registration_decision_digest(
        file.registration_request_id.as_bytes(),
        &details,
        moderator_id.as_bytes(),
        verdict,
    );
    let signature = signer.sign_digest(auth::REGISTRATION_DECISION_SIGNATURE_DOMAIN, &digest);
    Ok(json!({
        "moderator_id": moderator_id,
        "decision": verdict.as_str(),
        "signature": hex(&signature),
    }))
}

/// Body for `POST /v1/revocations`.
fn request_revocation(
    revocation_id: Uuid,
    analyst_id: Uuid,
    target_type: &str,
    target_id: Uuid,
    reason: &str,
    key: &KeyArgs,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let request = RevocationRequest {
        revocation_id: revocation_id.as_bytes(),
        analyst_id: analyst_id.as_bytes(),
        target_type,
        target_id: target_id.as_bytes(),
        reason,
    };
    eprintln!("Signing: revocation request {revocation_id} for {target_type} {target_id}");
    let signer = load_key(key)?;
    let digest = auth::revocation_request_digest(&request);
    let signature = signer.sign_digest(auth::REVOCATION_REQUEST_SIGNATURE_DOMAIN, &digest);
    Ok(json!({
        "revocation_id": revocation_id,
        "analyst_id": analyst_id,
        "target_type": target_type,
        "target_id": target_id,
        "reason": reason,
        "signature": hex(&signature),
    }))
}

/// Body for `POST /v1/revocations/{id}/decision`, signed over the request as stored.
///
/// Signs only after the stored request verifies with the requester's
/// registered key, and after showing the target being revoked.
fn decide_revocation(
    [request, requester]: [&Path; 2],
    target: Option<&Path>,
    moderator_id: Uuid,
    verdict: Decision,
    key: &KeyArgs,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let file: RevocationFile = serde_json::from_slice(&fs::read(request)?)?;
    if file.status != "pending" {
        return Err(format!("request is already {}", file.status).into());
    }
    let stored = RevocationRequest {
        revocation_id: file.revocation_id.as_bytes(),
        analyst_id: file.analyst_id.as_bytes(),
        target_type: &file.target_type,
        target_id: file.target_id.as_bytes(),
        reason: &file.reason,
    };
    let requester = verify_revocation_request(&file, &stored, requester)?;
    let target = describe_target(&file, target)?;

    // Show exactly what is being signed before signing it.
    eprintln!(
        "Request {} verified: signed by {} ({}, key {}{})",
        file.revocation_id,
        requester.user_id,
        requester.role.as_deref().unwrap_or("no role"),
        requester.public_key,
        if requester.revoked {
            ", now revoked"
        } else {
            ""
        },
    );
    eprintln!("Target: {} {}\n{target}", file.target_type, file.target_id);
    eprintln!(
        "Signing: {} revocation {} of {} {}: {}",
        verdict.as_str(),
        file.revocation_id,
        file.target_type,
        file.target_id,
        file.reason,
    );
    let signer = load_key(key)?;
    let digest = auth::revocation_decision_digest(&stored, moderator_id.as_bytes(), verdict);
    let signature = signer.sign_digest(auth::REVOCATION_DECISION_SIGNATURE_DOMAIN, &digest);
    Ok(json!({
        "moderator_id": moderator_id,
        "decision": verdict.as_str(),
        "signature": hex(&signature),
    }))
}

/// Check the stored request against the requester's registered key.
fn verify_revocation_request(
    file: &RevocationFile,
    stored: &RevocationRequest<'_>,
    requester: &Path,
) -> Result<UserFile, Box<dyn std::error::Error>> {
    let user: UserFile = serde_json::from_slice(&fs::read(requester)?)?;
    if user.user_id != file.analyst_id {
        return Err(format!(
            "requester file is for {}, but the request names {}",
            user.user_id, file.analyst_id
        )
        .into());
    }
    let public_key: [u8; 32] = unhex(&user.public_key)?
        .try_into()
        .map_err(|_| "requester public key must be 32 bytes")?;
    let signature: [u8; 64] = unhex(&file.request_signature)?
        .try_into()
        .map_err(|_| "request signature must be 64 bytes")?;
    verify_digest_signature(
        &public_key,
        auth::REVOCATION_REQUEST_SIGNATURE_DOMAIN,
        &auth::revocation_request_digest(stored),
        &signature,
    )
    .map_err(|_| {
        format!(
            "request {} does not verify with the key registered for {}; not signing",
            file.revocation_id, file.analyst_id
        )
    })?;
    Ok(user)
}

/// The target as read from its route, after checking it is the request's target.
fn describe_target(
    file: &RevocationFile,
    target: Option<&Path>,
) -> Result<String, Box<dyn std::error::Error>> {
    let Some(path) = target else {
        if UNREADABLE_TARGET_TYPES.contains(&file.target_type.as_str()) {
            return Ok(format!(
                "(no read route for {} yet; details not shown)",
                file.target_type
            ));
        }
        return Err(format!(
            "pass --target with the {} as returned by its read route",
            file.target_type
        )
        .into());
    };
    let value: serde_json::Value = serde_json::from_slice(&fs::read(path)?)?;
    let id_field = format!("{}_id", file.target_type);
    let target_id = file.target_id.to_string();
    if value.get(&id_field).and_then(serde_json::Value::as_str) != Some(target_id.as_str()) {
        return Err(format!("target file is not {} {target_id}", file.target_type).into());
    }
    Ok(serde_json::to_string_pretty(&value)?)
}

/// Body for `POST /v1/flags`.
fn flag(flag: &Flag<'_>, key: &KeyArgs) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let flag_id = Uuid::from_bytes(*flag.flag_id);
    let target_id = Uuid::from_bytes(*flag.target_id);
    eprintln!(
        "Signing: flag {flag_id} on {} {target_id}",
        flag.target_type
    );
    let signer = load_key(key)?;
    let signature = signer.sign_digest(auth::FLAG_SIGNATURE_DOMAIN, &auth::flag_digest(flag));
    Ok(json!({
        "flag_id": flag_id,
        "viewer_id": Uuid::from_bytes(*flag.viewer_id),
        "target_type": flag.target_type,
        "target_id": target_id,
        "note": flag.note,
        "signature": hex(&signature),
    }))
}

/// Body for `POST /v1/flags/{id}/responses`, signed over the flag as stored.
fn respond_flag(
    flag: &Path,
    flag_response_id: Uuid,
    analyst_id: Uuid,
    note: &str,
    key: &KeyArgs,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let file: FlagFile = serde_json::from_slice(&fs::read(flag)?)?;
    if file.revoked {
        return Err("flag is revoked".into());
    }
    let stored = Flag {
        flag_id: file.flag_id.as_bytes(),
        viewer_id: file.viewer_id.as_bytes(),
        target_type: &file.target_type,
        target_id: file.target_id.as_bytes(),
        note: &file.note,
    };
    // Show exactly what is being answered before signing it.
    eprintln!(
        "Signing: response {flag_response_id} to flag {} on {} {} by {}: {}",
        file.flag_id, file.target_type, file.target_id, file.viewer_id, file.note,
    );
    let signer = load_key(key)?;
    let digest = auth::flag_response_digest(
        &stored,
        flag_response_id.as_bytes(),
        analyst_id.as_bytes(),
        note,
    );
    let signature = signer.sign_digest(auth::FLAG_RESPONSE_SIGNATURE_DOMAIN, &digest);
    Ok(json!({
        "flag_response_id": flag_response_id,
        "analyst_id": analyst_id,
        "note": note,
        "signature": hex(&signature),
    }))
}

fn parse_decision(decision: &str) -> Decision {
    if decision == "approved" {
        Decision::Approved
    } else {
        Decision::Rejected
    }
}

/// Body for `POST /v1/auth/login`: the account is identified by the key alone.
fn login(common: &Common) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let (challenge_id, challenge, signer) = load(common)?;
    let public_key = signer.verifying_key();
    let digest = auth::login_digest(&challenge, &public_key);
    let signature = signer.sign_digest(auth::LOGIN_SIGNATURE_DOMAIN, &digest);
    Ok(json!({
        "challenge_id": challenge_id,
        "public_key": hex(&public_key),
        "signature": hex(&signature),
    }))
}

fn load(
    common: &Common,
) -> Result<(Uuid, AuthChallenge, SystemSigner), Box<dyn std::error::Error>> {
    let file: ChallengeFile = serde_json::from_slice(&fs::read(&common.challenge)?)?;
    let nonce: [u8; 32] = unhex(&file.nonce)?
        .try_into()
        .map_err(|_| "challenge nonce must be 32 bytes")?;
    let challenge = AuthChallenge {
        challenge_id: *file.challenge_id.as_bytes(),
        nonce,
        audience: file.audience,
        expires_at_unix_micros: file.expires_at_unix_micros,
    };
    Ok((file.challenge_id, challenge, load_key(&common.key)?))
}

fn load_key(key: &KeyArgs) -> Result<SystemSigner, Box<dyn std::error::Error>> {
    let passphrase = key
        .key_passphrase_file
        .as_ref()
        .map(read_secret_file)
        .transpose()?;
    Ok(SystemSigner::from_openssh_file(
        &key.key,
        passphrase.as_ref().map(|value| value.as_slice()),
    )?)
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    })
}

fn unhex(value: &str) -> Result<Vec<u8>, &'static str> {
    if value.len() % 2 != 0 {
        return Err("hex value has odd length");
    }
    (0..value.len())
        .step_by(2)
        .map(|index| {
            u8::from_str_radix(value.get(index..index + 2).ok_or("invalid hex")?, 16)
                .map_err(|_| "invalid hex")
        })
        .collect()
}
