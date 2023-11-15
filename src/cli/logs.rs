use crate::api;
use crate::api::AuthMode;
use crate::common::CliError;
use crate::config::CageConfig;
use crate::get_api_key;
use crate::logs::get_logs;
use crate::version::check_version;

use clap::Parser;

/// Pull the logs for a Cage
#[derive(Debug, Parser)]
#[clap(name = "logs", about)]
pub struct LogArgs {
    /// Uuid of the Cage show logs for. If not supplied, the CLI will look for a local cage.toml
    #[clap(long = "cage-uuid")]
    pub cage_uuid: Option<String>,

    /// Path to the toml file containing the Cage's config
    #[clap(short = 'c', long = "config", default_value = "./cage.toml")]
    pub config: String,

    /// The start time in epoch milliseconds
    #[clap(long = "start-time")]
    pub start_time: Option<String>,

    /// The end time in epoch milliseconds
    #[clap(long = "end-time")]
    pub end_time: Option<String>,
}

pub async fn run(log_args: LogArgs) -> i32 {
    log::info!("Note: each query will return a maximum of 500 logs, if logs are missing reduce the time range");
    if let Err(e) = check_version().await {
        log::error!("{}", e);
        return exitcode::SOFTWARE;
    };

    let api_key = get_api_key!();
    let cages_client = api::cage::CagesClient::new(AuthMode::ApiKey(api_key));

    let cage_uuid = match log_args.cage_uuid.clone() {
        Some(cage_uuid) => cage_uuid,
        None => {
            let cage_uuid = match CageConfig::try_from_filepath(&log_args.config) {
                Ok(config) => config.uuid,
                Err(e) => {
                    log::error!("An error occurred while resolving your Cage toml.\n\nPlease make sure you have a cage.toml file in the current directory, or have supplied a path with the --config flag.");
                    return e.exitcode();
                }
            };
            match cage_uuid {
                Some(uuid) => uuid,
                None => {
                    log::error!("Cage uuid is missing from toml");
                    return exitcode::DATAERR;
                }
            }
        }
    };

    match get_logs(
        log_args.start_time,
        log_args.end_time,
        cage_uuid,
        cages_client,
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
