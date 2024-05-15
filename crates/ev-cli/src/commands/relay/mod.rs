use clap::Parser;

pub mod create;
pub mod deploy;
use crate::run_cmd;

#[derive(Parser, Debug)]
#[command(name = "relay")]
pub struct RelayArgs {
    #[command(subcommand)]
    pub action: RelayCommand,
}

#[derive(Parser, Debug)]
#[command(name = "relay")]
pub enum RelayCommand {
    Create(create::CreateArgs),
    Deploy(deploy::DeployArgs),
}

pub async fn run(args: RelayArgs) {
    let auth = crate::get_auth();

    match args.action {
        RelayCommand::Create(create_args) => run_cmd(create::run(create_args, auth).await),
        RelayCommand::Deploy(deploy_args) => run_cmd(deploy::run(deploy_args, auth).await),
    }
}
