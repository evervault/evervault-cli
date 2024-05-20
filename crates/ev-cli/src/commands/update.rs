use crate::{errors, version::VersionError, CmdOutput};
use clap::Parser;
use common::api::{self, client::ApiError};
use dialoguer::Confirm;
use thiserror::Error;

/// Check for new versions of the CLI and install them
#[derive(Debug, Parser)]
#[command(name = "update", about)]
pub struct UpdateArgs {
    #[arg(short = 'f', long = "force")]
    force: bool,
}

#[derive(Error, Debug)]
pub enum UpdateError {
    #[error(transparent)]
    VersionError(#[from] VersionError),
    #[error("Failed to fetch information about the latest version of the CLI - {0}")]
    FetchLatestVersion(ApiError),
    #[error("Failed to fetch the CLI install script - {0}")]
    FetchInstallScript(ApiError),
    #[error("Failed to create tempfile to use during new version installation - {0}")]
    TempFileError(std::io::Error),
    #[error("Failed to populate contents of install script - {0}")]
    WriteError(#[from] std::io::Error),
    #[error("Failed to install the latest version of the CLI - {0}")]
    ScriptExec(std::io::Error),
}

impl CmdOutput for UpdateError {
    fn exitcode(&self) -> i32 {
        match self {
            Self::FetchLatestVersion(_) | Self::FetchInstallScript(_) => errors::SOFTWARE,
            Self::TempFileError(_) => errors::CANTCREAT,
            Self::WriteError(_) => errors::IOERR,
            Self::VersionError(e) => e.exitcode(),
            Self::ScriptExec(_) => errors::SOFTWARE,
        }
    }

    fn code(&self) -> String {
        match self {
            Self::FetchLatestVersion(_) => "update-fetch-version-error".to_string(),
            Self::FetchInstallScript(_) => "update-fetch-install-script-error".to_string(),
            Self::TempFileError(_) => "update-tempfile-error".to_string(),
            Self::WriteError(_) => "update-write-error".to_string(),
            Self::VersionError(e) => e.code(),
            Self::ScriptExec(_) => "update-script-exec-error".to_string(),
        }
    }
}

#[derive(strum_macros::Display)]
pub enum UpdateMessage {
    #[strum(to_string = "The CLI is already up to date. (Version {})")]
    AlreadyUpToDate(String),
    #[strum(to_string = "The CLI has been updated to the latest version")]
    Updated,
    #[strum(to_string = "The update was aborted")]
    Aborted,
}

impl CmdOutput for UpdateMessage {
    fn exitcode(&self) -> i32 {
        errors::OK
    }

    fn code(&self) -> String {
        match self {
            Self::AlreadyUpToDate(_) => "update-already-up-to-date".to_string(),
            Self::Updated => "update-complete".to_string(),
            Self::Aborted => "update-aborted".to_string(),
        }
    }
}

pub async fn run(args: UpdateArgs) -> Result<UpdateMessage, UpdateError> {
    let assets_client = api::assets::AssetsClient::new();
    let new_version = assets_client
        .get_latest_cli_version()
        .await
        .map_err(UpdateError::FetchLatestVersion)?;

    let current_version = env!("CARGO_PKG_VERSION");
    if new_version.as_str() == current_version {
        return Ok(UpdateMessage::AlreadyUpToDate(current_version.to_string()));
    }

    log::info!(
        "Current version: {}. Latest version is {}.",
        current_version,
        new_version.as_str()
    );
    if !args.force
        && !Confirm::new()
            .with_prompt("Would you like to update?")
            .default(true)
            .interact()
            .unwrap_or(false)
    {
        return Ok(UpdateMessage::Aborted);
    }

    let install_script = assets_client
        .get_cli_install_script()
        .await
        .map_err(UpdateError::FetchInstallScript)?;

    let tempfile = tempfile::Builder::new()
        .suffix(".sh")
        .tempfile()
        .map_err(UpdateError::TempFileError)?;

    tokio::fs::write(tempfile.path(), install_script.as_bytes())
        .await
        .map_err(UpdateError::WriteError)?;

    std::process::Command::new("sh")
        .arg(tempfile.path())
        .env("CLI_FORCE_INSTALL", "true")
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .status()
        .map_err(UpdateError::ScriptExec)?;

    Ok(UpdateMessage::Updated)
}
