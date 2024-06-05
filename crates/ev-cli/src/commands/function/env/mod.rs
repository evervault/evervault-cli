use clap::{Parser, Subcommand};

mod get;

use common::api::BasicAuth;
use get::GetEnvArgs;

use crate::run_cmd;

/// Manage Enclave signing certificates
#[derive(Debug, Parser)]
#[command(name = "cert", about)]
pub struct EnvArgs {
    #[command(subcommand)]
    action: EnvCommands,
}

#[derive(Debug, Subcommand)]
pub enum EnvCommands {
    /// Create a new Enclave signing certificate
    #[command()]
    Get(GetEnvArgs),
}

pub async fn run(env_args: EnvArgs, auth: BasicAuth) {
    match env_args.action {
        EnvCommands::Get(get_args) => run_cmd(get::run(get_args, auth).await),
        // EnvCommands::Set(set_args) => set::run(set_args, api_key),
        // EnvCommands::Delete(delete_args) => delete::run(delete_args, api_key),
    }
}
