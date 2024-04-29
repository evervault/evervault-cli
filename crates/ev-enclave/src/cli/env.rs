use crate::version::check_version;
use clap::{Parser, Subcommand};

use crate::{
    api::{enclave::EnclaveClient, AuthMode},
    get_api_key,
};

use super::encrypt::CurveName;
use crate::env::env;

#[derive(Clone, Debug, Subcommand)]
pub enum EnvAction {
    Add,
    Delete,
    Get,
}

/// Manage Enclave environment
#[derive(Debug, Parser)]
#[command(name = "cert", about)]
pub struct EnvArgs {
    #[command(subcommand)]
    action: EnvCommands,
}

#[derive(Debug, Subcommand)]
pub enum EnvCommands {
    #[command()]
    /// Add Enclave environment variable
    Add(AddEnvArgs),
    /// Delete Enclave environment variable
    Delete(DeleteEnvArgs),
    /// Get Enclave environment variables
    Get(GetEnvArgs),
}

/// Add secret to Enclave env
#[derive(Debug, Parser)]
#[command(name = "env", about)]
pub struct AddEnvArgs {
    /// Name of environment variable
    #[arg(long = "key")]
    pub name: String,

    /// Environment variable value
    #[arg(long = "value")]
    pub value: String,

    /// Is the env var is a secret, it will be encrypted
    #[arg(long = "secret")]
    pub is_secret: bool,

    /// Curve to use, options are Secp256r1 (alias nist) or Secp256k1 (alias koblitz)
    #[arg(value_enum)]
    pub curve: CurveName,

    /// Path to enclave.toml config file
    #[arg(short = 'c', long = "config", default_value = "./enclave.toml")]
    pub config: String,
}

/// Add delete secret from Enclave env
#[derive(Debug, Parser)]
#[command(name = "env", about)]
pub struct DeleteEnvArgs {
    /// Name of environment variable
    #[arg(long = "key")]
    pub name: String,

    /// Path to enclave.toml config file
    #[arg(short = 'c', long = "config", default_value = "./enclave.toml")]
    pub config: String,
}

/// Get secrets from Enclave env
#[derive(Debug, Parser)]
#[command(name = "env", about)]
pub struct GetEnvArgs {
    /// Path to enclave.toml config file
    #[arg(short = 'c', long = "config", default_value = "./enclave.toml")]
    pub config: String,
}

pub async fn run(env_args: EnvArgs) -> exitcode::ExitCode {
    if let Err(e) = check_version().await {
        log::error!("{e}");
        return exitcode::SOFTWARE;
    };

    let api_key = get_api_key!();
    let enclave_client = EnclaveClient::new(AuthMode::ApiKey(api_key));

    match env(enclave_client, env_args.action).await {
        Ok(result) => match result {
            Some(env) => {
                let success_msg = serde_json::json!(env);
                println!("{}", serde_json::to_string_pretty(&success_msg).unwrap());
                exitcode::OK
            }
            None => {
                log::info!("Environment updated successfully");
                exitcode::OK
            }
        },
        Err(e) => {
            log::error!("Error updating environment {e}");
            exitcode::SOFTWARE
        }
    }
}
