use clap::{Parser, Subcommand};

use common::api::{papi::EvApiClient, AuthMode};

use ev_enclave::{api::enclave::EnclaveClient, env};

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
    #[command()]
    Delete(DeleteEnvArgs),
    /// Get Enclave environment variables
    #[command()]
    Get(GetEnvArgs),
}

/// Add secret to Enclave env
#[derive(Debug, Parser)]
#[clap(name = "env", about)]
pub struct AddEnvArgs {
    /// Name of environment variable
    #[clap(long = "key")]
    pub name: String,

    /// Environment variable value
    #[clap(long = "value")]
    pub value: String,

    /// If the env var is a secret, it will be encrypted
    #[clap(long = "secret")]
    pub is_secret: bool,

    /// Path to enclave.toml config file
    #[clap(short = 'c', long = "config", default_value = "./enclave.toml")]
    pub config: String,
}

/// Add delete secret from Enclave env
#[derive(Debug, Parser)]
#[clap(name = "env", about)]
pub struct DeleteEnvArgs {
    /// Name of environment variable
    #[clap(long = "key")]
    pub name: String,

    /// Path to enclave.toml config file
    #[clap(short = 'c', long = "config", default_value = "./enclave.toml")]
    pub config: String,
}

/// Get secrets from Enclave env
#[derive(Debug, Parser)]
#[clap(name = "env", about)]
pub struct GetEnvArgs {
    /// Path to enclave.toml config file
    #[clap(short = 'c', long = "config", default_value = "./enclave.toml")]
    pub config: String,
}

pub async fn run(env_args: EnvArgs, app_uuid: String, api_key: String) -> exitcode::ExitCode {
    let api_client = EvApiClient::new((app_uuid, api_key.clone()));
    let enclave_api = EnclaveClient::new(AuthMode::ApiKey(api_key));

    let result = match env_args.action {
        EnvCommands::Add(add_args) => {
            env::add_env_var(
                enclave_api,
                api_client,
                add_args.config,
                add_args.name,
                add_args.value,
                add_args.is_secret,
            )
            .await
        }
        EnvCommands::Delete(delete_args) => {
            env::delete_env_var(enclave_api, delete_args.config, delete_args.name).await
        }
        EnvCommands::Get(get_args) => env::get_env_vars(enclave_api, get_args.config).await,
    };

    match result {
        Ok(None) => {
            log::info!("Environment updated successfully");
            exitcode::OK
        }
        Ok(Some(env)) => {
            let success_msg = serde_json::json!(env);
            println!("{}", serde_json::to_string_pretty(&success_msg).unwrap());

            exitcode::OK
        }
        Err(err) => {
            log::error!("Error updating environment {err}");
            exitcode::SOFTWARE
        }
    }
}
