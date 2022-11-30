use clap::Parser;

use crate::{
    api::{cage::CagesClient, AuthMode},
    get_api_key,
};

use super::encrypt::CurveName;
use crate::env::env;

#[derive(Clone, Debug, clap::ArgEnum)]
pub enum Action {
    Add,
    Delete,
    Get
}

/// Add secret to Cage env
#[derive(Debug, Parser)]
#[clap(name = "env", about)]
pub struct EnvArgs {

    /// Enviroment action: add, get, delete
    #[clap(arg_enum)]
    pub action: Action,

    /// Name of environment variable
    pub name: String,

    /// Environment variable value
    pub secret: String,

    /// The curve to use (nist of koblitz) default value is nist
    #[clap(value_enum, default_value = "nist")]
    pub curve: CurveName,

    /// Path to cage.toml config file
    #[clap(short = 'c', long = "config", default_value = "./cage.toml")]
    pub config: String,
}

pub async fn run(env_args: EnvArgs) -> exitcode::ExitCode {
    let api_key = get_api_key!();
    let cages_client = CagesClient::new(AuthMode::ApiKey(api_key));

    match env(
        env_args.name,
        env_args.secret,
        env_args.config,
        env_args.curve,
        cages_client,
        env_args.action,
    )
    .await
    {
        Ok(result) => match result {
            Some(env) => {
                let success_msg = serde_json::json!(env);
                println!("{}", serde_json::to_string(&success_msg).unwrap());
            }
            None => log::info!("Environment updated successfully")
        },
        Err(e) => log::error!("Error updating environment {}", e),
    };

    exitcode::OK
}
