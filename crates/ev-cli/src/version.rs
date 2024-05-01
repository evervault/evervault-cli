use common::api::assets::AssetsClient;
use chrono::Utc;
use common::api::client::ApiError;
use common::CliError;
use semver::Version;
use std::env;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum VersionError {
    #[error("An error occurred getting CLI versions — {0}")]
    ApiError(#[from] ApiError),
    #[error("Couldn't parse the semver version - {0}")]
    SemVerError(#[from] semver::Error),
    #[error("Couldn't parse env string as int - {0}")]
    ParseIntError(#[from] std::num::ParseIntError),
    #[error("This version is deprecated, please run ev update to continue")]
    DeprecatedVersion,
    #[error("Couldn't check version against latest")]
    FailedVersionCheck,
    #[error("IO error - {0}")]
    IoError(#[from] std::io::Error),
}

impl CliError for VersionError {
    fn exitcode(&self) -> exitcode::ExitCode {
        match self {
            Self::IoError(_) => exitcode::IOERR,
            _ => exitcode::SOFTWARE,
        }
    }
}

pub fn get_latest_major_version() -> Result<u8, VersionError> {
    Ok(env!("CARGO_PKG_VERSION_MAJOR").parse::<u8>()?)
}

pub async fn check_version() -> Result<(), VersionError> {
    if std::env::var("EV_DOMAIN").unwrap_or_else(|_| String::from("evervault.com"))
        == "evervault.io"
    {
        return Ok(());
    }
    match alert_on_deprecation().await? {
        Some(_) => Err(VersionError::DeprecatedVersion),
        _ => Ok(()),
    }
}

async fn alert_on_deprecation() -> Result<Option<i64>, VersionError> {
    let assets_client = AssetsClient::new();
    let version_info = assets_client.get_cli_versions().await?;
    let installed_major_version = get_latest_major_version()?;
    let installed_semver = Version::parse(env!("CARGO_PKG_VERSION"))?;
    let current_version = match version_info
        .versions
        .get(&installed_major_version.to_string())
    {
        Some(version) => version,
        None => return Err(VersionError::FailedVersionCheck),
    };
    let latest_semver = Version::parse(current_version.latest.as_str())?;
    if let Some(deprecation_date) = &current_version.deprecation_date {
        let current_time = Utc::now().timestamp();
        if current_time > deprecation_date.parse::<i64>()? {
            return Ok(Some(deprecation_date.parse::<i64>()?));
        } else {
            log::warn!(
                "This major version will be deprecated on {}",
                deprecation_date
            );
        }
    } else if installed_semver < latest_semver {
        log::warn!(
            "You are behind the latest version. Installed version: {}, latest version {}",
            installed_semver,
            latest_semver
        );
    }
    Ok(None)
}
