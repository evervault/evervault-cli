use crate::{print_and_exit, BaseArgs};
use clap::Parser;

use self::{enclave::EnclaveArgs, function::FunctionArgs, relay::RelayArgs, update::UpdateArgs};

mod enclave;
mod function;
mod interact;
mod relay;
mod update;

#[derive(Parser, Debug)]
pub enum Command {
    Enclave(EnclaveArgs),
    Relay(RelayArgs),
    Function(FunctionArgs),
    Update(UpdateArgs),
}

pub async fn run(base_args: BaseArgs) {
    if let Ok(Some(version_msg)) = crate::version::check_version().await {
        print_and_exit(version_msg);
    };

    match base_args.command {
        Command::Enclave(enclave_args) => enclave::run(enclave_args).await,
        Command::Relay(relay_args) => relay::run(relay_args).await,
        Command::Function(function_args) => function::run(function_args).await,
    }
}
