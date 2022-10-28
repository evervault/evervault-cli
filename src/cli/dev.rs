use crate::dev::run_mock_crypto_api;
use clap::Parser;

/// Start a mock crypto API for local testing
#[derive(Debug, Parser)]
#[clap(name = "dev", about)]
pub struct DevArgs {
    /// The port to run the crypto API on
    #[clap(short = 'p', long = "port", default_value = "9999")]
    pub port: u16,
}

pub async fn run(dev_args: DevArgs) -> exitcode::ExitCode {
    run_mock_crypto_api(dev_args.port).await;
    exitcode::OK
}
