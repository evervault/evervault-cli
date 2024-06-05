use clap::{Parser, Subcommand};

mod get;
mod set;

use crate::run_cmd;
use common::api::BasicAuth;
use get::GetEnvArgs;
use set::SetEnvArgs;

/// Manage Function environment variables
#[derive(Debug, Parser)]
#[command(name = "cert", about)]
pub struct EnvArgs {
    #[command(subcommand)]
    action: EnvCommands,
}

#[derive(Debug, Subcommand)]
pub enum EnvCommands {
    /// Get Function environment variables
    #[command()]
    Get(GetEnvArgs),
    /// Set Function environment variables
    #[command()]
    Set(SetEnvArgs),
}

pub async fn run(env_args: EnvArgs, auth: BasicAuth) {
    match env_args.action {
        EnvCommands::Get(get_args) => run_cmd(get::run(get_args, auth).await),
        EnvCommands::Set(set_args) => run_cmd(set::run(set_args, auth).await),
        // EnvCommands::Delete(delete_args) => delete::run(delete_args, api_key),
    }
}
