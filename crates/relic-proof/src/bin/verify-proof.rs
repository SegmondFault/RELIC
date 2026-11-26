//! `relic-verify-proof`: check an inclusion proof from the RELIC API against
//! the signed MMR checkpoint it names and, with `--entry`, tie it to the
//! integrity entry it is about. Offline: reads JSON files and a public key,
//! never a database.
//!
//! Exit status: `0` the proof holds; `1` it does not, or what the server sent
//! is not usable (anything a tampering server controls); `2` the command line
//! is wrong or a file cannot be opened.

use std::{
    fs::File,
    io::{self, Read},
    path::{Path, PathBuf},
    process::ExitCode,
};

use chrono::{DateTime, SecondsFormat};
use clap::Parser;
use relic_crypto::Digest32;
use relic_proof::client::{Expectations, LeafOrigin, Verified, verify_api_proof};
use uuid::Uuid;

/// Inputs are small JSON documents; anything larger is not from the API.
const MAX_INPUT_BYTES: u64 = 1 << 20;

#[derive(Debug, Parser)]
#[command(
    about = "Verify a RELIC MMR inclusion proof against a signed checkpoint (offline)",
    after_help = "Fetch the inputs with:\n  \
        GET /v1/integrity/{id}/proof?checkpoint_id={n}   -> --proof\n  \
        GET /v1/mmr-checkpoints/{n}                      -> --checkpoint\n  \
        GET /v1/integrity/{id}                           -> --entry\n\
        Take --public-key and --system-uid from the operator's published pin, \
        never from the API that serves the proof.\n\n\
        Exit status: 0 verified; 1 not verified (including unusable server \
        responses); 2 bad command line or unreadable file."
)]
struct Arguments {
    /// The response of `GET /v1/integrity/{id}/proof` (`-` for standard input).
    #[arg(long)]
    proof: PathBuf,
    /// The response of `GET /v1/mmr-checkpoints/{n}` for the checkpoint the
    /// proof names (`-` for standard input).
    #[arg(long)]
    checkpoint: PathBuf,
    /// The pinned Ed25519 public key of the MMR system account, 64
    /// hexadecimal characters.
    #[arg(long)]
    public_key: String,
    /// The pinned MMR system account id: the checkpoint must name it.
    #[arg(long)]
    system_uid: Option<String>,
    /// Accept only the checkpoint with this commitment (64 hexadecimal
    /// characters), e.g. one recorded while the key that signed it was trusted.
    #[arg(long)]
    commitment: Option<String>,
    /// The response of `GET /v1/integrity/{id}` (`-` for standard input).
    /// Its chain hash is recomputed from its fields and must be the leaf the
    /// proof is about, which ties the proof to that source and record hash.
    #[arg(long)]
    entry: Option<PathBuf>,
    /// The source the entry must be about (a UUID).
    #[arg(long, requires = "entry")]
    source_id: Option<String>,
    /// The record hash the entry must commit to (64 hexadecimal characters).
    #[arg(long, requires = "entry")]
    record_hash: Option<String>,
    /// A chain hash you computed yourself; the proof must be about it.
    #[arg(long)]
    chain_hash: Option<String>,
}

/// How the command ends, short of success.
enum Failure {
    /// Exit 2: the command line or the local files are the problem.
    Usage(String),
    /// Exit 1: the proof does not hold, or an input the server produced is
    /// unusable.
    Rejected(String),
}

fn main() -> ExitCode {
    let arguments = Arguments::parse();
    match run(&arguments) {
        Ok(verified) => {
            print!("{}", report(&verified));
            if verified.leaf_origin == LeafOrigin::ServerReported {
                eprintln!(
                    "relic-verify-proof: warning: the chain hash is only what the server \
                     reported, so this shows the server is consistent with its own checkpoint, \
                     not which record the leaf is. Pass --entry (GET /v1/integrity/{{id}}) to \
                     recompute it, or --chain-hash with a value you computed yourself."
                );
            }
            ExitCode::SUCCESS
        }
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

fn run(arguments: &Arguments) -> Result<Verified, Failure> {
    let usage = |message: &str| Failure::Usage(message.to_owned());
    let hex = |flag: &str, value: &str| {
        value
            .parse::<Digest32>()
            .map_err(|_| usage(&format!("{flag} must be 64 hexadecimal characters")))
    };
    let key = hex("--public-key", &arguments.public_key)?;
    let optional_hex = |flag: &str, value: Option<&String>| value.map(|v| hex(flag, v)).transpose();
    let optional_uuid = |flag: &str, value: Option<&String>| {
        value
            .map(|v| Uuid::parse_str(v).map_err(|_| usage(&format!("{flag} must be a UUID"))))
            .transpose()
    };
    let system_uid = optional_uuid("--system-uid", arguments.system_uid.as_ref())?;
    let commitment = optional_hex("--commitment", arguments.commitment.as_ref())?;
    let source_id = optional_uuid("--source-id", arguments.source_id.as_ref())?;
    let record_hash = optional_hex("--record-hash", arguments.record_hash.as_ref())?;
    let chain_hash = optional_hex("--chain-hash", arguments.chain_hash.as_ref())?;

    let stdin_inputs = [
        Some(&arguments.proof),
        Some(&arguments.checkpoint),
        arguments.entry.as_ref(),
    ]
    .into_iter()
    .flatten()
    .filter(|path| path.as_path() == Path::new("-"))
    .count();
    if stdin_inputs > 1 {
        return Err(usage(
            "only one of the inputs can be read from standard input (-)",
        ));
    }

    let proof = read_input(&arguments.proof)?;
    let checkpoint = read_input(&arguments.checkpoint)?;
    let entry = arguments.entry.as_deref().map(read_input).transpose()?;

    let expected = Expectations {
        system_uid,
        commitment,
        chain_hash,
        entry_json: entry.as_deref(),
        source_id,
        record_hash,
    };
    verify_api_proof(&proof, &checkpoint, key.as_bytes(), &expected)
        .map_err(|error| Failure::Rejected(error.to_string()))
}

/// Read one input. Failing to open or read the file is a local problem
/// (exit 2); content that is too large or not text came from whoever produced
/// the file, so it is a rejection (exit 1).
fn read_input(path: &Path) -> Result<String, Failure> {
    let name = path.display();
    let reader: Box<dyn Read> = if path == Path::new("-") {
        Box::new(io::stdin())
    } else {
        Box::new(File::open(path).map_err(|error| Failure::Usage(format!("{name}: {error}")))?)
    };
    let mut text = String::new();
    match reader.take(MAX_INPUT_BYTES + 1).read_to_string(&mut text) {
        Ok(_) if text.len() as u64 > MAX_INPUT_BYTES => Err(Failure::Rejected(format!(
            "{name} is larger than anything the API produces"
        ))),
        Ok(_) => Ok(text),
        Err(error) if error.kind() == io::ErrorKind::InvalidData => {
            Err(Failure::Rejected(format!("{name} is not UTF-8 text")))
        }
        Err(error) => Err(Failure::Usage(format!("{name}: {error}"))),
    }
}

fn timestamp(micros: i64) -> String {
    DateTime::from_timestamp_micros(micros).map_or_else(
        || format!("{micros} µs after the Unix epoch"),
        |instant| instant.to_rfc3339_opts(SecondsFormat::Micros, true),
    )
}

/// What was established, one fact per line; the first line is stable for
/// scripts. Only signed or recomputed values are presented as verified.
fn report(verified: &Verified) -> String {
    let mut lines = vec![format!(
        "VERIFIED: leaf {} of the MMR checkpoint of {} entries signed by system account {}",
        verified.leaf_index, verified.leaf_count, verified.system_uid
    )];
    let origin = match verified.leaf_origin {
        LeafOrigin::RecomputedFromEntry => "recomputed from the integrity entry",
        LeafOrigin::Expected => "the value you passed with --chain-hash",
        LeafOrigin::ServerReported => "as reported by the server (see the warning)",
    };
    lines.push(format!(
        "  leaf:       chain hash {}, {origin}",
        verified.chain_hash
    ));
    if let Some(entry) = &verified.entry {
        lines.push(format!(
            "  entry:      source {} ({}), record hash {}, admitted {}",
            entry.source_id,
            entry.source_type,
            entry.record_hash,
            timestamp(entry.created_at_unix_micros)
        ));
    }
    lines.push(format!(
        "  checkpoint: commitment {}, signed {} (server id {})",
        verified.commitment,
        timestamp(verified.checkpoint_created_at_unix_micros),
        verified.mmr_checkpoint_id
    ));
    lines.push(format!(
        "  server ids: integrity entry {} (ids are not covered by the proof, the leaf position is)",
        verified.integrity_id
    ));
    let mut text = lines.join("\n");
    text.push('\n');
    text
}
