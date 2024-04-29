use crate::dev::run_mock_crypto_api;
use crate::version::check_version;
use clap::Parser;

/// Start a mock encryption API for local testing
#[derive(Debug, Parser)]
#[command(name = "dev", about)]
pub struct DevArgs {
    /// The port to run the crypto API on
    #[arg(short = 'p', long = "port", default_value = "9999")]
    pub port: u16,
}

pub async fn run(dev_args: DevArgs) -> exitcode::ExitCode {
    if let Err(e) = check_version().await {
        log::error!("{e}");
        return exitcode::SOFTWARE;
    };

    run_mock_crypto_api(dev_args.port).await;
    exitcode::OK
}
