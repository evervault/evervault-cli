use crate::api;
use crate::api::AuthMode;
use crate::common::CliError;
use crate::config::CageConfig;
use crate::get_api_key;
use crate::version::check_version;

use chrono::TimeZone;
use clap::Parser;
use std::fmt::Write;

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
}

pub async fn run(log_args: LogArgs) -> i32 {
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

    let now = std::time::SystemTime::now();
    let end_time = match now.duration_since(std::time::UNIX_EPOCH).ok() {
        Some(end_time) => end_time,
        None => {
            log::error!("Failed to compute current time");
            return exitcode::OSERR;
        }
    };

    let start_time = match now
        .checked_sub(std::time::Duration::from_secs(60 * 30))
        .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
    {
        Some(start_time) => start_time,
        None => {
            log::error!("Failed to compute start time.");
            return exitcode::SOFTWARE;
        }
    };

    let cage_logs = match cages_client
        .get_cage_logs(
            cage_uuid.as_str(),
            start_time.as_millis(),
            end_time.as_millis(),
        )
        .await
    {
        Ok(logs) => logs,
        Err(e) => {
            log::error!("Failed to retrieve logs for Cage - {:?}", e);
            return e.exitcode();
        }
    };

    let start_time = cage_logs.start_time().parse::<i64>().unwrap();
    let Some(logs_start) = format_timestamp(start_time) else {
        log::error!("Failed to parse timestamps.");
        return exitcode::SOFTWARE;
    };
    let end_time = cage_logs.end_time().parse::<i64>().unwrap();
    let Some(logs_end) = format_timestamp(end_time) else {
        log::error!("Failed to parse timestamps.");
        return exitcode::SOFTWARE;
    };

    if cage_logs.log_events().is_empty() {
        log::info!("No logs found between {logs_start} and {logs_end}",);
        return exitcode::OK;
    }

    let mut output = minus::Pager::new();

    if output
        .set_prompt(format!(
            "Retrieved {} logs from {logs_start} to {logs_end}",
            cage_logs.log_events().len()
        ))
        .is_err()
    {
        log::error!("An error occurred while displaying your Cage's logs.");
        return exitcode::TEMPFAIL;
    }

    // TODO: add support for loading more logs at end of page
    cage_logs
        .log_events()
        .iter()
        .filter_map(|event| {
            let mut instance_id = event.instance_id().to_string();
            let instance_len = instance_id.len();
            let _ = instance_id.drain(0..instance_len - 6);
            format_timestamp(event.timestamp()).map(|timestamp| {
                format!(
                    "[ Instance-{} @ {} ] {}",
                    instance_id,
                    timestamp,
                    event.message()
                )
            })
        })
        .for_each(|log_event| {
            writeln!(output, "{}", log_event).unwrap();
        });

    if let Err(e) = minus::page_all(output) {
        log::error!("An error occurred while paginating your log data - {:?}", e);
        exitcode::SOFTWARE
    } else {
        exitcode::OK
    }
}

fn format_timestamp(epoch: i64) -> Option<String> {
    let epoch_secs = epoch / 1000;
    let epoch_nsecs = epoch % 1000;
    chrono::Utc
        .timestamp_opt(epoch_secs, epoch_nsecs as u32)
        .single()
        .map(|timestamp| timestamp.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
}
