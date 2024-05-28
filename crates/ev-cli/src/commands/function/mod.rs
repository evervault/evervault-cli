use crate::run_cmd;
use clap::Parser;

mod create_toml;
mod deploy;
mod init;

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
}

pub async fn run(args: FunctionArgs) {
    let auth = crate::get_auth();

    match args.action {
        FunctionCommand::Init(init_args) => run_cmd(init::run(init_args, auth).await),
        FunctionCommand::Deploy(deploy_args) => run_cmd(deploy::run(deploy_args, auth).await),
        FunctionCommand::CreateToml(create_toml_args) => {
            run_cmd(create_toml::run(create_toml_args).await)
        }
    }
}
