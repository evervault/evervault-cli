use crate::{
    api::{cage::CagesClient, AuthMode},
    common::CliError,
    deploy::{timed_operation, watch_deployment, DEPLOY_WATCH_TIMEOUT_SECONDS},
    get_api_key,
    progress::get_tracker,
    restart::restart_cage,
};
use clap::Parser;

/// Restart the Cage deployment
#[derive(Debug, Parser)]
#[clap(name = "restart", about)]
pub struct RestartArgs {
    /// Path to cage.toml config file
    #[clap(short = 'c', long = "config", default_value = "./cage.toml")]
    pub config: String,

    /// Uuid of the Cage who's deployment to restart
    #[clap(long = "cage-uuid")]
    pub cage_uuid: Option<String>,

    /// Perform the Cage restart in the background
    #[clap(long)]
    pub background: bool,
}

pub async fn run(restart_args: RestartArgs) -> i32 {
    let api_key = get_api_key!();

    let cage_api = CagesClient::new(AuthMode::ApiKey(api_key.to_string()));

    let new_deployment = match restart_cage(
        restart_args.config.as_str(),
        restart_args.cage_uuid.as_deref(),
        &cage_api,
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

    let progress_bar = get_tracker(
        "Deploying Cage into a Trusted Execution Environment...",
        None,
    );

    match timed_operation(
        "Cage Deployment",
        DEPLOY_WATCH_TIMEOUT_SECONDS,
        watch_deployment(
            cage_api,
            new_deployment.cage_uuid(),
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
