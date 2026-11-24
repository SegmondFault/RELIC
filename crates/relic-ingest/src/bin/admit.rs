//! `relic-admit`: admit the FIDBF, `BSim` and provenance submissions the API staged.
//!
//! Runs on the host as `relic_worker`, with the integrity key the API never
//! holds. `--once` handles everything pending and exits (for a timer);
//! otherwise it keeps polling.

use std::{path::PathBuf, process::ExitCode, thread, time::Duration};

use clap::Parser;
use relic_crypto::{SystemSigner, read_secret_file};
use relic_ingest::{
    admission::{AdmitConfig, Outcome, admit_next, check_integrity_identity, prune_staging},
    connect,
};
use uuid::Uuid;

#[derive(Debug, Parser)]
#[command(about = "Verify and admit staged RELIC submissions with their integrity entries")]
struct Arguments {
    #[arg(long, env = "RELIC_DATABASE_URL", hide_env_values = true)]
    database_url: String,
    #[arg(long, env = "RELIC_INTEGRITY_SYSTEM_USER_ID")]
    integrity_system_user_id: Uuid,
    #[arg(long, env = "RELIC_INTEGRITY_KEY")]
    integrity_key: PathBuf,
    #[arg(long, env = "RELIC_INTEGRITY_KEY_PASSPHRASE_FILE")]
    integrity_key_passphrase_file: Option<PathBuf>,
    /// Where the API stages uploaded FIDBF objects.
    #[arg(
        long,
        env = "RELIC_STAGING_DIR",
        default_value = "/var/lib/relic/staging"
    )]
    staging_dir: PathBuf,
    /// The content-addressed FIDBF object store.
    #[arg(long, env = "RELIC_FIDBF_ROOT", default_value = "/srv/relic-objects")]
    fidbf_root: PathBuf,
    #[arg(long, env = "RELIC_MAX_OBJECT_BYTES", default_value_t = 64 * 1024 * 1024)]
    max_object_bytes: u64,
    /// Handle what is pending, then exit.
    #[arg(long)]
    once: bool,
    #[arg(long, default_value_t = 5)]
    poll_seconds: u64,
    /// Remove abandoned staged uploads older than this.
    #[arg(long, default_value_t = 24)]
    prune_after_hours: u64,
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("relic-admit: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let arguments = Arguments::parse();
    let passphrase = arguments
        .integrity_key_passphrase_file
        .as_ref()
        .map(read_secret_file)
        .transpose()?;
    let signer = SystemSigner::from_openssh_file(
        &arguments.integrity_key,
        passphrase.as_ref().map(|value| value.as_slice()),
    )?;
    let config = AdmitConfig {
        staging_dir: &arguments.staging_dir,
        fidbf_root: &arguments.fidbf_root,
        integrity_system_user_id: arguments.integrity_system_user_id,
        integrity_signer: &signer,
        max_object_bytes: arguments.max_object_bytes,
        max_attempts: 5,
    };
    let mut client = connect(&arguments.database_url)?;
    check_integrity_identity(&mut client, arguments.integrity_system_user_id, &signer).map_err(
        |error| {
            format!(
                "integrity account {}: {error}",
                arguments.integrity_system_user_id
            )
        },
    )?;
    loop {
        // Each submission is handled once per pass, so one that keeps failing
        // transiently cannot hold up the rest.
        let mut seen = Vec::new();
        while let Some(handled) = admit_next(&mut client, &config, &seen)
            .map_err(|error| relic_integrity_worker::describe_db_error(&error))?
        {
            let (verdict, detail) = match &handled.outcome {
                Outcome::Admitted(result) => ("admitted", result.to_string()),
                Outcome::Rejected { reason, detail } => {
                    ("rejected", format!("{reason} ({detail})"))
                }
                Outcome::Retry { reason, detail } => ("retry", format!("{reason} ({detail})")),
            };
            println!(
                "{verdict} {} {}: {detail}",
                handled.kind, handled.submission_id
            );
            seen.push(handled.submission_id);
        }
        let pruned = prune_staging(
            &mut client,
            &arguments.staging_dir,
            Duration::from_secs(arguments.prune_after_hours * 3600),
        )
        .map_err(|error| relic_integrity_worker::describe_db_error(&error))?;
        if pruned > 0 {
            println!("pruned {pruned} abandoned staged upload(s)");
        }
        if arguments.once {
            return Ok(());
        }
        thread::sleep(Duration::from_secs(arguments.poll_seconds));
    }
}
