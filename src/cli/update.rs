use crate::{api, common::CliError};

pub async fn run() -> exitcode::ExitCode {
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
        .env("EV_FORCE_INSTALL", "true")
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
