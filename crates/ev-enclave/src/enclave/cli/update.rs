use crate::enclave::{api, common::CliError, version::check_version};
use clap::Parser;
use dialoguer::Confirm;

/// Check for new versions of the CLI and install them
#[derive(Debug, Parser)]
#[clap(name = "update", about)]
pub struct UpdateArgs {
    #[clap(short = 'f', long = "force")]
    force: bool,
}

pub async fn run(args: UpdateArgs) -> exitcode::ExitCode {
    if let Err(e) = check_version().await {
        log::error!("{}", e);
        return exitcode::SOFTWARE;
    }

    let assets_client = api::assets::AssetsClient::new();
    let new_version = match assets_client.get_latest_cli_version().await {
        Ok(version) => version,
        Err(e) => {
            log::error!("Failed to retrieve latest CLI version - {}", e);
            return e.exitcode();
        }
    };

    let current_version = env!("CARGO_PKG_VERSION");
    if new_version.as_str() == current_version {
        log::info!("Already on latest version ({})", current_version);
        return exitcode::OK;
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
        return exitcode::OK;
    }

    let install_script = match assets_client.get_cli_install_script().await {
        Ok(script) => script,
        Err(e) => {
            log::error!("Failed to pull CLI install script - {}", e);
            return e.exitcode();
        }
    };

    let tempfile = match tempfile::Builder::new().suffix(".sh").tempfile() {
        Ok(tmp_file) => tmp_file,
        Err(e) => {
            log::error!(
                "Failed to create tempfile to use during new version installation - {}",
                e
            );
            return exitcode::CANTCREAT;
        }
    };

    if let Err(e) = tokio::fs::write(tempfile.path(), install_script.as_bytes()).await {
        log::error!("Failed to populate contents of install script - {}", e);
        return exitcode::IOERR;
    }

    let result = std::process::Command::new("sh")
        .arg(tempfile.path())
        .env("CLI_FORCE_INSTALL", "true")
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .status();

    match result {
        Ok(output) => output.code().unwrap_or(exitcode::USAGE),
        Err(e) => {
            log::error!("Failed to install latest version of Enclaves CLI - {}", e);
            exitcode::SOFTWARE
        }
    }
}
