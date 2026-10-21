use atty::Stream;
use clap::Parser;
use commands::Command;
use env_logger::fmt::Formatter;
use env_logger::{Builder, Env};
use human_panic::setup_panic;
use log::Record;
use serde_json::Value;
use std::io::{IsTerminal, Write};

mod auth;
mod commands;
mod errors;
mod fs;
mod function;
mod relay;
mod theme;
mod tty;
mod version;

pub use auth::get_auth;

pub trait CmdOutput: std::fmt::Display {
    fn code(&self) -> String;

    fn exitcode(&self) -> crate::errors::ExitCode;

    fn data(&self) -> Option<Value>;
}

pub fn run_cmd(r: Result<impl CmdOutput, impl CmdOutput>) -> ! {
    match r {
        Ok(output) => crate::print_and_exit(output, false),
        Err(e) => crate::print_and_exit(e, true),
    }
}

pub fn print_and_exit<T>(output: T, is_error: bool) -> !
where
    T: CmdOutput,
{
    let base_args = BaseArgs::parse();

    let msg = if base_args.json {
        fmt_json(&output, is_error)
    } else {
        output.to_string()
    };

    // when a we have json data to display in a non-json output, print it to stdout and print
    // the message to stderr, so a user that doesn't pass the --json flag can still pipe the json
    if !base_args.json {
        if let Some(Ok(data)) = output.data().map(|d| serde_json::to_string_pretty(&d)) {
            eprintln!("{msg}");
            println!("{data}");
        } else if is_error {
            eprintln!("{msg}");
        } else {
            println!("{msg}");
        }
    } else {
        println!("{msg}");
    }

    std::process::exit(output.exitcode());
}

fn fmt_json<T>(output: &T, is_error: bool) -> String
where
    T: CmdOutput,
{
    let mut json = serde_json::json!({
        "message": output.to_string(),
        "code": output.code(),
        "is_error": is_error
    });

    if let Some(data) = output.data() {
        json.as_object_mut()
            .expect("infallible")
            .insert("data".into(), data);
    }

    if std::io::stdout().is_terminal() {
        serde_json::to_string_pretty(&json).unwrap_or(json.to_string())
    } else {
        json.to_string()
    }
}

/// An argument parsing error, reported in the same shape as any other error when `--json` is passed
#[derive(Debug)]
struct ParseError(clap::Error);

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Only the first paragraph: the rest is the usage line and a pointer to `--help`
        let rendered = self.0.to_string();
        let message = rendered.split("\n\n").next().unwrap_or(&rendered);
        write!(f, "{}", message.trim_start_matches("error: ").trim_end())
    }
}

impl CmdOutput for ParseError {
    fn code(&self) -> String {
        "generic/invalid-arguments".to_string()
    }

    fn exitcode(&self) -> crate::errors::ExitCode {
        self.0.exit_code()
    }

    fn data(&self) -> Option<Value> {
        None
    }
}

/// `--json` can't be read off the parsed args when parsing failed, so it's looked for directly
fn exit_with_parse_error(error: clap::Error) -> ! {
    use clap::error::ErrorKind;

    let wants_json = std::env::args_os().any(|arg| arg == "--json");
    let is_help_or_version = matches!(
        error.kind(),
        ErrorKind::DisplayHelp
            | ErrorKind::DisplayVersion
            | ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand
    );
    if !wants_json || is_help_or_version {
        error.exit();
    }

    let output = ParseError(error);
    println!("{}", fmt_json(&output, true));
    std::process::exit(output.exitcode());
}

#[derive(Debug, Parser)]
#[clap(name = "Evervault CLI", version)]
pub struct BaseArgs {
    /// Toggle verbose output
    #[clap(short, long, global = true, default_value_t = false)]
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

    let base_args = BaseArgs::try_parse().unwrap_or_else(|e| exit_with_parse_error(e));
    setup_logger(base_args.verbose, base_args.json);
    commands::run(base_args).await;
}

fn setup_logger(verbose_logging: bool, json: bool) {
    let env = Env::new()
        .filter_or("EV_LOG", "INFO")
        .write_style("EV_LOG_STYLE");
    let mut builder = Builder::from_env(env);

    let log_formatter = move |buf: &mut Formatter, record: &Record| {
        // One JSON object per line, so logs can be parsed alongside `--json` output
        if json {
            let line = serde_json::json!({
                "timestamp": buf.timestamp_millis().to_string(),
                "level": record.metadata().level().to_string(),
                "message": record.args().to_string(),
            });
            return writeln!(buf, "{line}");
        }

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
            let level = record.metadata().level();
            let style = buf.default_level_style(level);
            writeln!(buf, "[{style}{level}{style:#}] {}", record.args())
        }
    };

    builder
        .format_timestamp(None)
        .format_module_path(false)
        .format_target(false);
    // Log targets are module paths, so crate names are spelled with underscores here
    // Without `--verbose`, EV_LOG (INFO by default) decides
    if verbose_logging {
        for target in ["ev", "common", "ev_enclave"] {
            builder.filter(Some(target), log::LevelFilter::Debug);
        }
    }
    builder.format(log_formatter).init();
}
