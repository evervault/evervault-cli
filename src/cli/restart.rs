use crate::{get_api_key, restart::restart_cage};
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

    match restart_cage(
        restart_args.config.as_str(),
        restart_args.cage_uuid.as_deref(),
        api_key.as_str(),
        restart_args.background,
    )
    .await
    {
        Ok(_) => println!("Cage restart started"),
        Err(e) => {
            log::info!("{}", e);
            return e.exitcode();
        }
    };

    exitcode::OK
}
