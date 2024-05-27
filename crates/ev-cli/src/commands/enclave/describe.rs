use clap::Parser;
use common::CliError;
use ev_enclave::describe::describe_eif;

/// Get the PCRs of a built EIF
#[derive(Debug, Parser)]
#[command(name = "describe", about)]
pub struct DescribeArgs {
    /// Path to the EIF to descibe.
    #[arg(default_value = "./enclave.eif")]
    pub eif_path: String,

    /// Disable verbose logging
    #[arg(long)]
    pub quiet: bool,

    /// Disables the use of cache during the image builds
    #[arg(long = "no-cache")]
    pub no_cache: bool,
}

pub async fn run(describe_args: DescribeArgs) -> exitcode::ExitCode {
    let description = match describe_eif(
        &describe_args.eif_path,
        !describe_args.quiet,
        describe_args.no_cache,
    ) {
        Ok(measurements) => measurements,
        Err(e) => {
            log::error!("{e}");
            return e.exitcode();
        }
    };

    println!("{}", serde_json::to_string_pretty(&description).unwrap());
    exitcode::OK
}
