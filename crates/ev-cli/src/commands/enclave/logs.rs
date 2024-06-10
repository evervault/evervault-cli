use clap::Parser;
use common::{
    api::{AuthMode, BasicAuth},
    CliError,
};
use ev_enclave::{api::enclave::EnclaveClient, config::EnclaveConfig, logs::get_logs};

/// Pull the logs for an Enclave
#[derive(Debug, Parser)]
#[command(name = "logs", about)]
pub struct LogArgs {
    /// Uuid of the Enclave show logs for. If not supplied, the CLI will look for a local enclave.toml
    #[arg(long = "enclave-uuid")]
    pub enclave_uuid: Option<String>,

    /// Path to the toml file containing the Enclave's config
    #[arg(short = 'c', long = "config", default_value = "./enclave.toml")]
    pub config: String,

    /// The start time in epoch milliseconds
    #[arg(long = "start-time")]
    pub start_time: Option<String>,

    /// The end time in epoch milliseconds
    #[arg(long = "end-time")]
    pub end_time: Option<String>,
}

pub async fn run(log_args: LogArgs, (_, api_key): BasicAuth) -> i32 {
    log::info!("Note: each query will return a maximum of 500 logs, if logs are missing reduce the time range");

    let enclave_client = EnclaveClient::new(AuthMode::ApiKey(api_key));

    let enclave_uuid = match log_args.enclave_uuid.clone() {
        Some(enclave_uuid) => enclave_uuid,
        None => {
            let enclave_uuid = match EnclaveConfig::try_from_filepath(&log_args.config) {
                Ok(config) => config.uuid,
                Err(e) => {
                    log::error!("An error occurred while resolving your Enclave toml.\n\nPlease make sure you have a enclave.toml file in the current directory, or have supplied a path with the --config flag.");
                    return e.exitcode();
                }
            };
            match enclave_uuid {
                Some(uuid) => uuid,
                None => {
                    log::error!("Enclave uuid is missing from toml");
                    return exitcode::DATAERR;
                }
            }
        }
    };

    match get_logs(
        log_args.start_time,
        log_args.end_time,
        enclave_uuid,
        enclave_client,
    )
    .await
    {
        Ok(_) => exitcode::OK,
        Err(err) => {
            log::error!("An error occurred while fetching logs: {err}");
            err.exitcode()
        }
    }
}
