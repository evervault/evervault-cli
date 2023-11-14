use chrono::TimeZone;
use std::fmt::Write;
use thiserror::Error;

use crate::{api::cage::CagesClient, common::CliError};

#[derive(Debug, Error)]
pub enum LogsError {
    #[error("Could not get system time - {0}")]
    SystemTimeError(#[from] std::time::SystemTimeError),
    #[error("Failed to compute start time")]
    TimeError,
    #[error("Error retrieving logs - {0}")]
    ApiError(#[from] crate::api::client::ApiError),
    #[error("Couldn't parse time as millisecond - {0}")]
    ParseIntError(#[from] std::num::ParseIntError),
    #[error("Failed to parse timestamps")]
    TimestampFormatError,
    #[error("{0}")]
    NoLogsFound(String),
    #[error("An error occurred while paginating your log data - {0}")]
    MinusError(#[from] minus::MinusError),
}

impl CliError for LogsError {
    fn exitcode(&self) -> exitcode::ExitCode {
        match self {
            Self::SystemTimeError(_) => exitcode::OSERR,
            _ => exitcode::SOFTWARE,
        }
    }
}

pub async fn get_logs(
    start_time: Option<String>,
    end_time: Option<String>,
    cage_uuid: String,
    cages_client: CagesClient,
) -> Result<(), LogsError> {
    let now = std::time::SystemTime::now();
    let log_end_time = match end_time {
        Some(end) => end.parse::<u128>()?,
        None => now.duration_since(std::time::UNIX_EPOCH)?.as_millis(),
    };

    let log_start_time = match start_time {
        Some(start) => start.parse::<u128>()?,
        None => now
            .checked_sub(std::time::Duration::from_secs(60 * 30))
            .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
            .ok_or(LogsError::TimeError)?
            .as_millis(),
    };

    let cage_logs = cages_client
        .get_cage_logs(cage_uuid.as_str(), log_start_time, log_end_time)
        .await?;

    if cage_logs.log_events().is_empty() {
        return Err(LogsError::NoLogsFound(format!(
            "No logs found between {log_start_time} and {log_end_time}"
        )));
    }

    let mut output = minus::Pager::new();

    output.set_prompt(format!(
        "Retrieved {} logs from {log_start_time} to {log_end_time}",
        cage_logs.log_events().len()
    ))?;

    cage_logs
        .log_events()
        .iter()
        .filter_map(|event| {
            let mut instance_id = event.instance_id().to_string();
            let instance_len = instance_id.len();
            let _ = instance_id.drain(0..instance_len - 6);
            format_timestamp(event.timestamp())
                .map(|timestamp| {
                    format!(
                        "[ Instance-{} @ {} ] {}",
                        instance_id,
                        timestamp,
                        event.message()
                    )
                })
                .ok()
        })
        .for_each(|log_event| {
            writeln!(output, "{}", log_event).unwrap();
        });

    Ok(minus::page_all(output)?)
}

fn format_timestamp(epoch: i64) -> Result<String, LogsError> {
    let epoch_secs = epoch / 1000;
    let epoch_nsecs = epoch % 1000;
    let timestamp = chrono::Utc
        .timestamp_opt(epoch_secs, epoch_nsecs as u32)
        .single()
        .map(|timestamp| timestamp.to_rfc3339_opts(chrono::SecondsFormat::Secs, true));
    match timestamp {
        Some(timestamp) => Ok(timestamp),
        None => Err(LogsError::TimestampFormatError),
    }
}
