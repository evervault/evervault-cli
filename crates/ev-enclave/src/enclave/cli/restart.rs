use crate::enclave::{
    api::{enclave::EnclaveClient, AuthMode},
    common::CliError,
    deploy::{timed_operation, watch_deployment, DEPLOY_WATCH_TIMEOUT_SECONDS},
    progress::get_tracker,
    restart::restart_enclave,
    version::check_version,
};
use crate::get_api_key;
use clap::Parser;

/// Restart the Enclave deployment
#[derive(Debug, Parser)]
#[clap(name = "restart", about)]
pub struct RestartArgs {
    /// Path to enclave.toml config file
    #[clap(short = 'c', long = "config", default_value = "./enclave.toml")]
    pub config: String,

    /// Uuid of the Enclave who's deployment to restart
    #[clap(long = "enclave-uuid")]
    pub enclave_uuid: Option<String>,

    /// Perform the Enclave restart in the background
    #[clap(long)]
    pub background: bool,
}

pub async fn run(restart_args: RestartArgs) -> i32 {
    if let Err(e) = check_version().await {
        log::error!("{}", e);
        return exitcode::SOFTWARE;
    };

    let api_key = get_api_key!();

    let enclave_api = EnclaveClient::new(AuthMode::ApiKey(api_key.to_string()));

    let new_deployment = match restart_enclave(
        restart_args.config.as_str(),
        restart_args.enclave_uuid.as_deref(),
        &enclave_api,
        restart_args.background,
    )
    .await
    {
        Ok(depl) => depl,
        Err(e) => {
            log::error!("{}", e);
            return e.exitcode();
        }
    };

    if restart_args.background {
        println!(
            "Enclave restarting. You can observe the restart progress in the Enclaves Dashboard"
        );
        return exitcode::OK;
    }

    let progress_bar = get_tracker(
        "Deploying Enclave into a Trusted Execution Environment...",
        None,
    );

    match timed_operation(
        "Enclave Deployment",
        DEPLOY_WATCH_TIMEOUT_SECONDS,
        watch_deployment(
            enclave_api,
            new_deployment.enclave_uuid(),
            new_deployment.uuid(),
            progress_bar,
        ),
    )
    .await
    {
        Ok(_) => exitcode::OK,
        Err(e) => {
            log::error!("{}", e);
            e.exitcode()
        }
    }
}
