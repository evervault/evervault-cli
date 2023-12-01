use crate::common::CliError;
use crate::describe::describe_eif;
use crate::version::check_version;
use clap::Parser;

/// Get the PCRs of a built EIF
#[derive(Debug, Parser)]
#[clap(name = "describe", about)]
pub struct DescribeArgs {
    /// Path to the EIF to descibe.
    #[clap(default_value = "./enclave.eif")]
    pub eif_path: String,

    /// Disable verbose logging
    #[clap(long)]
    pub quiet: bool,
}

pub async fn run(describe_args: DescribeArgs) -> exitcode::ExitCode {
    if let Err(e) = check_version().await {
        log::error!("{e}");
        return exitcode::SOFTWARE;
    };

    let description = match describe_eif(&describe_args.eif_path, !describe_args.quiet) {
        Ok(measurements) => measurements,
        Err(e) => {
            log::error!("{e}");
            return e.exitcode();
        }
    };

    println!("{}", serde_json::to_string_pretty(&description).unwrap());
    exitcode::OK
}
