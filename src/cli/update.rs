use crate::{api, common::CliError};
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
    let assets_client = api::assets::AssetsClient::new();
    let new_version = match assets_client.get_latest_cli_version().await {
        Ok(version) => version,
        Err(e) => {
            eprintln!("Failed to retrieve latest CLI version - {}", e);
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
            eprintln!("Failed to pull CLI install script - {}", e);
            return e.exitcode();
        }
    };

    let tempfile = match tempfile::Builder::new().suffix(".sh").tempfile() {
        Ok(tmp_file) => tmp_file,
        Err(e) => {
            eprintln!(
                "Failed to create tempfile to use during new version installation - {}",
                e
            );
            return exitcode::CANTCREAT;
        }
    };

    if let Err(e) = tokio::fs::write(tempfile.path(), install_script.as_bytes()).await {
        eprintln!("Failed to populate contents of install script - {}", e);
        return exitcode::IOERR;
    }

    let result = std::process::Command::new("sh")
        .arg(tempfile.path())
        .env("CAGE_CLI_FORCE_INSTALL", "true")
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .status();

    match result {
        Ok(output) => output.code().unwrap_or_else(|| exitcode::USAGE),
        Err(e) => {
            eprintln!("Failed to install latest version of Cages CLI - {}", e);
            return exitcode::SOFTWARE;
        }
    }
}
