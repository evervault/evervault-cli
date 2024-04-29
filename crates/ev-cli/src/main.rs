use atty::Stream;
use clap::Parser;
use commands::Command;
use env_logger::fmt::Formatter;
use env_logger::{Builder, Env};
#[cfg(not(target_os = "windows"))]
#[cfg(feature = "internal_dependency")]
use ev_enclave::enclave::cli::{dev, encrypt, env};
use human_panic::setup_panic;
use log::Record;
use std::io::Write;
mod commands;

#[derive(Debug, Parser)]
#[clap(name = "Evervault Enclave CLI", version)]
pub struct BaseArgs {
    /// Toggle verbose output
    #[clap(short, long, global = true)]
    pub verbose: bool,

    /// Toggle JSON output for stdout
    #[clap(long, global = true)]
    pub json: bool,

    #[clap(subcommand)]
    pub command: Command,
}

#[tokio::main]
async fn main() {
    // Use human panic to give nicer error logs in the case of a runtime panic
    setup_panic!(Metadata {
        name: env!("CARGO_PKG_NAME").into(),
        version: env!("CARGO_PKG_VERSION").into(),
        authors: "Engineering <engineering@evervault.com>".into(),
        homepage: "https://github.com/evervault/cages".into(),
    });

    let base_args: BaseArgs = BaseArgs::parse();
    setup_logger(base_args.verbose);
    let exit_code = match base_args.command {
        Command::Enclave(enclave_args) => commands::run_enclave(enclave_args).await,
    };
    std::process::exit(exit_code);
}

fn setup_logger(verbose_logging: bool) {
    let env = Env::new()
        .filter_or("EV_LOG", "INFO")
        .write_style("EV_LOG_STYLE");
    let mut builder = Builder::from_env(env);

    let log_formatter = |buf: &mut Formatter, record: &Record| {
        // If stderr is being piped elsewhere, add timestamps and remove colors
        if atty::isnt(Stream::Stderr) {
            let timestamp = buf.timestamp_millis();
            writeln!(
                buf,
                "[{} {}] {}",
                timestamp,
                record.metadata().level(),
                record.args()
            )
        } else {
            writeln!(
                buf,
                "[{}] {}",
                buf.default_styled_level(record.metadata().level()),
                record.args()
            )
        }
    };

    builder
        .format_timestamp(None)
        .format_module_path(false)
        .format_target(false);
    if verbose_logging {
        builder.filter(Some("ev-enclave"), log::LevelFilter::Debug);
    } else {
        builder.filter(Some("ev-enclave"), log::LevelFilter::Info);
    }
    builder.format(log_formatter).init();
}
