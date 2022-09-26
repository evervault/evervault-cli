use atty::Stream;
use clap::{AppSettings, Parser};
use env_logger::fmt::Formatter;
use env_logger::{Builder, Env};
use ev_cage::cli::{build, cert, delete, deploy, describe, init, list, logs, update, Command};
use human_panic::setup_panic;
use log::Record;
use std::io::Write;

#[derive(Debug, Parser)]
#[clap(
    name = "Evervault Cage CLI",
    author = "engineering@evervault.com",
    version,
    setting = AppSettings::ArgRequiredElseHelp,
    setting = AppSettings::DeriveDisplayOrder
)]
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
        Command::Build(build_args) => build::run(build_args).await,
        Command::Cert(cert_args) => cert::run(cert_args),
        Command::Delete(delete_args) => delete::run(delete_args).await,
        Command::Deploy(deploy_args) => deploy::run(deploy_args).await,
        Command::Describe(describe_args) => describe::run(describe_args).await,
        Command::Init(init_args) => init::run(init_args).await,
        Command::List(list_args) => list::run(list_args).await,
        Command::Logs(log_args) => logs::run(log_args).await,
        Command::Update => update::run().await,
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
        builder.filter(Some("ev-cage"), log::LevelFilter::Debug);
    } else {
        builder.filter(Some("ev-cage"), log::LevelFilter::Info);
    }
    builder.format(log_formatter).init();
}
