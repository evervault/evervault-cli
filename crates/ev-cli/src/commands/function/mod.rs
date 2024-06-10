use crate::run_cmd;
use clap::Parser;
use common::api::BasicAuth;

mod create_toml;
mod delete;
mod deploy;
mod env;
mod init;
mod run;
#[derive(Parser, Debug)]
#[command(name = "function")]
pub struct FunctionArgs {
    #[command(subcommand)]
    pub action: FunctionCommand,
}

#[derive(Parser, Debug)]
#[command(name = "function")]
pub enum FunctionCommand {
    Init(init::InitArgs),
    Deploy(deploy::DeployArgs),
    CreateToml(create_toml::CreateTomlArgs),
    Delete(delete::DeleteArgs),
    Env(env::EnvArgs),
    Run(run::RunArgs),
}

pub async fn run(args: FunctionArgs, auth: BasicAuth) {
    match args.action {
        FunctionCommand::Init(init_args) => run_cmd(init::run(init_args, auth).await),
        FunctionCommand::Deploy(deploy_args) => run_cmd(deploy::run(deploy_args, auth).await),
        FunctionCommand::CreateToml(create_toml_args) => {
            run_cmd(create_toml::run(create_toml_args).await)
        }
        FunctionCommand::Delete(delete_args) => run_cmd(delete::run(delete_args, auth).await),
        FunctionCommand::Env(env_args) => env::run(env_args, auth).await,
        FunctionCommand::Run(run_args) => run_cmd(run::run(run_args, auth).await),
    }
}
