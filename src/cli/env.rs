use clap::{Parser, Subcommand};

use crate::{
    api::{cage::CagesClient, AuthMode},
    get_api_key,
};

use super::encrypt::CurveName;
use crate::env::env;

#[derive(Clone, Debug, clap::ArgEnum, Subcommand)]
pub enum EnvAction {
    Add,
    Delete,
    Get,
}

/// Manage Cage environment
#[derive(Debug, Parser)]
#[clap(name = "cert", about)]
pub struct EnvArgs {
    #[clap(subcommand)]
    action: EnvCommands,
}

#[derive(Debug, Subcommand)]
pub enum EnvCommands {
    /// Create a new Cage signing certificate
    #[clap()]
    Add(AddEnvArgs),
    Delete(DeleteEnvArgs),
    Get(GetEnvArgs),
}

/// Add secret to Cage env
#[derive(Debug, Parser)]
#[clap(name = "env", about)]
pub struct AddEnvArgs {
    /// Name of environment variable
    pub name: String,

    /// Environment variable value
    pub secret: String,

    /// Whether to encrypt env var, default is true
    #[clap(long = "egress")]
    pub skip_encryption: bool,

    /// The curve to use (nist or koblitz) default value is nist
    #[clap(value_enum, default_value = "nist")]
    pub curve: CurveName,

    /// Path to cage.toml config file
    #[clap(short = 'c', long = "config", default_value = "./cage.toml")]
    pub config: String,
}

/// Add delete secret from Cage env
#[derive(Debug, Parser)]
#[clap(name = "env", about)]
pub struct DeleteEnvArgs {
    /// Name of environment variable
    pub name: String,

    /// Path to cage.toml config file
    #[clap(short = 'c', long = "config", default_value = "./cage.toml")]
    pub config: String,
}

/// Get secrets from Cage env
#[derive(Debug, Parser)]
#[clap(name = "env", about)]
pub struct GetEnvArgs {
    /// Path to cage.toml config file
    #[clap(short = 'c', long = "config", default_value = "./cage.toml")]
    pub config: String,
}

pub async fn run(env_args: EnvArgs) -> exitcode::ExitCode {
    let api_key = get_api_key!();
    let cages_client = CagesClient::new(AuthMode::ApiKey(api_key));

    match env(cages_client, env_args.action).await {
        Ok(result) => match result {
            Some(env) => {
                let success_msg = serde_json::json!(env);
                log::info!("{}", serde_json::to_string(&success_msg).unwrap());
                exitcode::OK
            }
            None => {
                log::info!("Environment updated successfully");
                exitcode::OK
            }
        },
        Err(e) => {
            log::error!("Error updating environment {}", e);
            exitcode::SOFTWARE
        }
    }
}
