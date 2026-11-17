use std::{path::PathBuf, process::ExitCode};

use clap::Parser;
use postgres::Client;
use relic_crypto::{SystemSigner, read_secret_file};
use relic_integrity_worker::chain_uncovered_bsim_postgres;
use uuid::Uuid;

#[derive(Debug, Parser)]
#[command(about = "System-sign unchained legacy BSim rows into the RELIC integrity chain")]
struct Arguments {
    #[arg(long, env = "RELIC_DATABASE_URL", hide_env_values = true)]
    database_url: String,
    #[arg(long, env = "RELIC_INTEGRITY_SYSTEM_USER_ID")]
    integrity_system_user_id: Uuid,
    #[arg(long, env = "RELIC_INTEGRITY_KEY")]
    integrity_key: PathBuf,
    #[arg(long, env = "RELIC_INTEGRITY_KEY_PASSPHRASE_FILE")]
    integrity_key_passphrase_file: Option<PathBuf>,
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("relic-chain-bsim: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args = Arguments::parse();
    let passphrase = args
        .integrity_key_passphrase_file
        .as_ref()
        .map(read_secret_file)
        .transpose()?;
    let signer = SystemSigner::from_openssh_file(
        &args.integrity_key,
        passphrase.as_ref().map(|secret| secret.as_slice()),
    )?;
    let mut client = Client::connect(&args.database_url, postgres::NoTls)?;
    let result =
        chain_uncovered_bsim_postgres(&mut client, args.integrity_system_user_id, &signer)?;
    println!(
        "inserted={} last_integrity_id={:?} chain_tip={:?}",
        result.inserted, result.last_integrity_id, result.chain_tip
    );
    Ok(())
}
