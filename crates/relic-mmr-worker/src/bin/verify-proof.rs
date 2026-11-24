//! `relic-verify-proof`: check an inclusion proof from the RELIC API against
//! the signed MMR checkpoint it names. Offline: reads two JSON files and a
//! public key, never a database.
//!
//! Exit status: 0 the proof holds, 1 it does not, 2 the inputs could not be
//! read or are not what the API produces.

use std::{
    fs::File,
    io::{self, Read},
    path::{Path, PathBuf},
    process::ExitCode,
};

use clap::Parser;
use relic_crypto::Digest32;
use relic_mmr_worker::client::{ClientError, verify_api_proof};

/// Inputs are small JSON documents; anything larger is not from the API.
const MAX_INPUT_BYTES: u64 = 1 << 20;

#[derive(Debug, Parser)]
#[command(
    about = "Verify a RELIC MMR inclusion proof against a signed checkpoint (offline)",
    after_help = "Fetch the inputs with:\n  \
        GET /v1/integrity/{id}/proof?checkpoint_id={n}   -> --proof\n  \
        GET /v1/mmr-checkpoints/{n}                      -> --checkpoint\n  \
        GET /v1/users/{system_uid}                       -> --public-key (pin it out of band)"
)]
struct Arguments {
    /// The response of `GET /v1/integrity/{id}/proof` (`-` for standard input).
    #[arg(long)]
    proof: PathBuf,
    /// The response of `GET /v1/mmr-checkpoints/{id}` for the same checkpoint.
    #[arg(long)]
    checkpoint: PathBuf,
    /// The system account's Ed25519 public key, 64 hexadecimal characters.
    #[arg(long)]
    public_key: String,
    /// The chain hash you expect the proof to be about, if you know it.
    #[arg(long)]
    chain_hash: Option<String>,
}

fn read_limited(path: &Path) -> io::Result<String> {
    let mut text = String::new();
    let mut reader: Box<dyn Read> = if path == Path::new("-") {
        Box::new(io::stdin())
    } else {
        Box::new(File::open(path)?)
    };
    reader
        .by_ref()
        .take(MAX_INPUT_BYTES + 1)
        .read_to_string(&mut text)?;
    if text.len() as u64 > MAX_INPUT_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "input is too large",
        ));
    }
    Ok(text)
}

fn main() -> ExitCode {
    let arguments = Arguments::parse();
    match run(&arguments) {
        Ok(()) => ExitCode::SUCCESS,
        Err(Failure::Usage(message)) => {
            eprintln!("relic-verify-proof: {message}");
            ExitCode::from(2)
        }
        Err(Failure::Rejected(message)) => {
            println!("NOT VERIFIED: {message}");
            ExitCode::from(1)
        }
    }
}

enum Failure {
    Usage(String),
    Rejected(String),
}

fn run(arguments: &Arguments) -> Result<(), Failure> {
    let usage = |message: String| Failure::Usage(message);
    let key = arguments
        .public_key
        .parse::<Digest32>()
        .map_err(|_| usage("--public-key must be 64 hexadecimal characters".into()))?;
    let expected = arguments
        .chain_hash
        .as_deref()
        .map(str::parse::<Digest32>)
        .transpose()
        .map_err(|_| usage("--chain-hash must be 64 hexadecimal characters".into()))?;
    let proof = read_limited(&arguments.proof)
        .map_err(|error| usage(format!("{}: {error}", arguments.proof.display())))?;
    let checkpoint = read_limited(&arguments.checkpoint)
        .map_err(|error| usage(format!("{}: {error}", arguments.checkpoint.display())))?;

    match verify_api_proof(&proof, &checkpoint, key.as_bytes(), expected.as_ref()) {
        Ok(verified) => {
            println!(
                "VERIFIED: integrity entry {} (leaf {}, chain hash {}) is covered by MMR \
                 checkpoint {} of {} entries, signed by system account {}",
                verified.integrity_id,
                verified.leaf_index,
                verified.chain_hash,
                verified.mmr_checkpoint_id,
                verified.leaf_count,
                verified.system_uid,
            );
            Ok(())
        }
        Err(error @ ClientError::Malformed { .. }) => Err(Failure::Usage(error.to_string())),
        Err(error) => Err(Failure::Rejected(error.to_string())),
    }
}
