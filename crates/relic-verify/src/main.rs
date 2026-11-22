//! `relic-verify`: re-check every stored signature, the integrity chain and
//! the MMR checkpoints of a RELIC database. Read-only; meant for cron.
//!
//! Exit status: 0 everything verified, 1 at least one failure, 2 the check
//! could not run (connection or query error).

use std::process::ExitCode;

use clap::Parser;
use relic_verify::{Finding, Report, verify};

#[derive(Debug, Parser)]
#[command(
    about = "Re-verify every signature, the integrity chain and the MMR checkpoints (read-only)"
)]
struct Arguments {
    /// Connect as `relic_auditor` (read-only), never as `relic_app` or a worker.
    #[arg(long, env = "RELIC_DATABASE_URL", hide_env_values = true)]
    database_url: String,
    /// Print the report as JSON instead of text.
    #[arg(long)]
    json: bool,
    /// Print only failures and warnings (nothing when all is well).
    #[arg(long, conflicts_with = "json")]
    quiet: bool,
}

fn main() -> ExitCode {
    let arguments = Arguments::parse();
    let report = match relic_ingest::connect(&arguments.database_url)
        .map_err(|error| error.to_string())
        .and_then(|mut client| verify(&mut client).map_err(|error| error.to_string()))
    {
        Ok(report) => report,
        Err(error) => {
            eprintln!("relic-verify: could not run: {error}");
            return ExitCode::from(2);
        }
    };
    if arguments.json {
        match serde_json::to_string_pretty(&report) {
            Ok(json) => println!("{json}"),
            Err(error) => {
                eprintln!("relic-verify: {error}");
                return ExitCode::from(2);
            }
        }
    } else {
        print_text(&report, arguments.quiet);
    }
    if report.ok() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

fn print_text(report: &Report, quiet: bool) {
    let line = |label: &str, finding: &Finding| {
        println!(
            "{label} {} {}: {}",
            finding.kind, finding.id, finding.problem
        );
    };
    for finding in &report.failures {
        line("FAIL", finding);
    }
    for finding in &report.warnings {
        line("WARN", finding);
    }
    if quiet {
        return;
    }
    for (kind, count) in &report.checked {
        println!("ok   {count:>8}  {kind}");
    }
    for (kind, count) in &report.unchecked {
        println!("skip {count:>8}  {kind}");
    }
    println!(
        "{}: {} failure(s), {} warning(s)",
        if report.ok() { "VERIFIED" } else { "FAILED" },
        report.failures.len(),
        report.warnings.len()
    );
}
