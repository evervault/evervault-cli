use clap::Parser;
use common::{
    api::{AuthMode, BasicAuth},
    CliError,
};
use ev_enclave::{
    api::enclave::EnclaveClient,
    deploy::{timed_operation, watch_deployment, DEPLOY_WATCH_TIMEOUT_SECONDS},
    progress::get_tracker,
    restart::restart_enclave,
};

/// Restart the Enclave deployment
#[derive(Debug, Parser)]
#[command(name = "restart", about)]
pub struct RestartArgs {
    /// Path to enclave.toml config file
    #[arg(short = 'c', long = "config", default_value = "./enclave.toml")]
    pub config: String,

    /// Uuid of the Enclave who's deployment to restart
    #[arg(long = "enclave-uuid")]
    pub enclave_uuid: Option<String>,

    /// Perform the Enclave restart in the background
    #[arg(long)]
    pub background: bool,
}

pub async fn run(restart_args: RestartArgs, (_, api_key): BasicAuth) -> i32 {
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
