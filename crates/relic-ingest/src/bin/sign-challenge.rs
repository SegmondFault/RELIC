//! Client-side signer for RELIC account messages.
//!
//! `login` and `register` read a challenge exactly as returned by
//! `POST /v1/auth/challenge`; `decide-registration` reads a request exactly as
//! returned by `GET /v1/registrations/{id}`. Each signs the canonical message
//! with the user's OpenSSH Ed25519 key and prints the JSON body to POST.

use std::{fs, path::PathBuf, process::ExitCode};

use clap::{Args, Parser, Subcommand};
use relic_crypto::{
    SystemSigner,
    auth::{self, AuthChallenge, RegistrationDecision, RegistrationDetails},
    read_secret_file,
};
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

#[derive(Debug, Parser)]
#[command(
    about = "Sign RELIC login, registration and registration-decision messages on the user's machine"
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
}

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
        } => {
            let file: RegistrationFile = serde_json::from_slice(&fs::read(&request)?)?;
            if file.status != "pending" {
                return Err(format!("request is already {}", file.status).into());
            }
            let public_key: [u8; 32] = unhex(&file.public_key)?
                .try_into()
                .map_err(|_| "applicant public key must be 32 bytes")?;
            let verdict = if decision == "approved" {
                RegistrationDecision::Approved
            } else {
                RegistrationDecision::Rejected
            };
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
            let signer = load_key(&key)?;
            let digest = auth::registration_decision_digest(
                file.registration_request_id.as_bytes(),
                &details,
                moderator_id.as_bytes(),
                verdict,
            );
            let signature =
                signer.sign_digest(auth::REGISTRATION_DECISION_SIGNATURE_DOMAIN, &digest);
            json!({
                "moderator_id": moderator_id,
                "decision": verdict.as_str(),
                "signature": hex(&signature),
            })
        }
    };
    println!("{}", serde_json::to_string_pretty(&body)?);
    Ok(())
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
