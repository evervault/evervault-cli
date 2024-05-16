use clap::Parser;

use crate::run_cmd;

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
}

pub async fn run(args: FunctionArgs) {
    let auth = crate::get_auth();

    match args.action {
        FunctionCommand::Init(init_args) => run_cmd(init::run(init_args, auth).await),
    }
}
