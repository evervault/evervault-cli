use chrono::Utc;
use common::api::assets::AssetsClient;
use common::api::client::ApiError;
use semver::Version;
use std::env;
use thiserror::Error;

use crate::CmdOutput;

#[derive(Debug, Error)]
pub enum VersionError {
    #[error("An error occurred getting CLI versions — {0}")]
    ApiError(#[from] ApiError),
    #[error("Couldn't parse the semver version - {0}")]
    SemverError(#[from] semver::Error),
    #[error("Couldn't parse env string as int - {0}")]
    ParseIntError(#[from] std::num::ParseIntError),
    #[error("Couldn't check version against latest")]
    FailedVersionCheck,
    #[error("IO error - {0}")]
    IoError(#[from] std::io::Error),
    #[error("This version was deprecated on {0}, please run ev update to continue")]
    IsDeprecated(String),
}

impl CmdOutput for VersionError {
    fn exitcode(&self) -> exitcode::ExitCode {
        match self {
            Self::IoError(_) => exitcode::IOERR,
            _ => exitcode::SOFTWARE,
        }
    }

    fn code(&self) -> String {
        match self {
            VersionError::IoError(_) => "version-io-error",
            VersionError::ApiError(_) => "version-api-error",
            VersionError::SemverError(_) => "version-semver-error",
            VersionError::ParseIntError(_) => "version-deprecation-date-parse-error",
            VersionError::FailedVersionCheck => "version-failed-version-check-error",
            VersionError::IsDeprecated(_) => "version-deprecated-error",
        }
        .to_string()
    }

    fn data(&self) -> Option<serde_json::Value> {
        None
    }
}
#[derive(strum_macros::Display, Debug)]
pub enum VersionMessage {
    #[strum(to_string = "This major version will be deprecated on {deprecation_date}")]
    WillBeDeprecated { deprecation_date: String },
    #[strum(
        to_string = "You are behind the latest version. Installed version: {}, latest version {}. Run ev update to update"
    )]
    Outdated(String, String),
}

impl CmdOutput for VersionMessage {
    fn exitcode(&self) -> exitcode::ExitCode {
        match self {
            Self::WillBeDeprecated { .. } => exitcode::OK,
            Self::Outdated(_, _) => exitcode::SOFTWARE,
        }
    }

    fn code(&self) -> String {
        match self {
            VersionMessage::WillBeDeprecated { .. } => "version-will-be-deprecated",
            VersionMessage::Outdated(_, _) => "version-outdated",
        }
        .to_string()
    }

    fn data(&self) -> Option<serde_json::Value> {
        None
    }
}

pub fn get_latest_major_version() -> Result<u8, VersionError> {
    Ok(env!("CARGO_PKG_VERSION_MAJOR").parse::<u8>()?)
}

pub async fn check_version() -> Result<Option<VersionMessage>, VersionError> {
    if std::env::var("EV_DOMAIN") != Ok("evervault.com".to_string()) {
        return Ok(None);
    }

    let assets_client = AssetsClient::new();
    let cli_versions = assets_client.get_cli_versions().await?;
    let installed_major_version = get_latest_major_version()?;
    let installed_semver = Version::parse(env!("CARGO_PKG_VERSION"))?;

    let current_version = cli_versions
        .versions
        .get(&installed_major_version.to_string())
        .ok_or(VersionError::FailedVersionCheck)?;

    let latest_semver = Version::parse(current_version.latest.as_str())?;

    if let Some(deprecation_date) = &current_version.deprecation_date {
        let current_time = Utc::now().timestamp();

        if current_time > deprecation_date.parse::<i64>()? {
            return Err(VersionError::IsDeprecated(deprecation_date.into()));
        } else {
            return Ok(Some(VersionMessage::WillBeDeprecated {
                deprecation_date: deprecation_date.into(),
            }));
        }
    } else if installed_semver < latest_semver {
        return Ok(Some(VersionMessage::Outdated(
            installed_semver.to_string(),
            latest_semver.to_string(),
        )));
    }

    Ok(None)
}
