use crate::{migrate::migrate_toml, version::check_version};
use clap::Parser;

/// Build an Enclave from a Dockerfile
#[derive(Parser, Debug)]
#[clap(name = "migrate", about)]
pub struct MigrateArgs {
    /// Path to the toml file containing the Enclave's config
    #[clap(short = 'c', long = "config", default_value = "./cage.toml")]
    pub config: String,
}

pub async fn run(args: MigrateArgs) -> exitcode::ExitCode {
    if let Err(e) = check_version().await {
        log::error!("{}", e);
        return exitcode::SOFTWARE;
    };

    let serialized_config = match migrate_toml(&args.config) {
        Ok(bytes) => bytes,
        Err(e) => {
            log::error!("{}", e);
            return exitcode::SOFTWARE;
        }
    };

    if let Err(e) = std::fs::write(&args.config, serialized_config) {
        log::error!("Error writing enclave.toml — {}", e);
        exitcode::IOERR
    } else {
        log::info!("Enclave.toml migrated successfully. You can now deploy a V1 Enclave using the deploy command");
        exitcode::OK
    }
}
