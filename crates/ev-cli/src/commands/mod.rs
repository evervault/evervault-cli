use crate::BaseArgs;
use clap::Parser;

use self::{enclave::EnclaveArgs, relay::RelayArgs, function::FunctionArgs};

mod enclave;
mod function;
mod interact;
mod relay;

#[derive(Parser, Debug)]
pub enum Command {
    Enclave(EnclaveArgs),
    Relay(RelayArgs),
    Function(FunctionArgs)
}

pub async fn run_command(base_args: BaseArgs) {
    if let Err(e) = crate::version::check_version().await {
        log::error!("{}", e);
        std::process::exit(exitcode::SOFTWARE);
    };

    match base_args.command {
        Command::Enclave(enclave_args) => enclave::run(enclave_args).await,
        Command::Relay(relay_args) => relay::run(relay_args).await,
        Command::Function(function_args) => function::run(function_args).await,
    }
}
