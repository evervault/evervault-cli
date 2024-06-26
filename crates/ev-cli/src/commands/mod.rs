use self::{
    decrypt::DecryptArgs, enclave::EnclaveArgs, encrypt::EncryptArgs, function::FunctionArgs,
    relay::RelayArgs, update::UpdateArgs,
};
use super::run_cmd;
use crate::{print_and_exit, BaseArgs};
use clap::Parser;

mod decrypt;
mod enclave;
mod encrypt;
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
    Encrypt(EncryptArgs),
    Decrypt(DecryptArgs),
}

pub async fn run(base_args: BaseArgs) {
    if let Ok(Some(version_msg)) = crate::version::check_version().await {
        print_and_exit(version_msg, true);
    };

    match base_args.command {
        Command::Update(update_args) => run_cmd(update::run(update_args).await),
        _ => {}
    }

    let auth = crate::get_auth();

    match base_args.command {
        Command::Enclave(enclave_args) => enclave::run(enclave_args, auth).await,
        Command::Relay(relay_args) => relay::run(relay_args, auth).await,
        Command::Function(function_args) => function::run(function_args, auth).await,
        Command::Encrypt(encrypt_args) => run_cmd(encrypt::run(encrypt_args, auth).await),
        Command::Decrypt(decrypt_args) => run_cmd(decrypt::run(decrypt_args, auth).await),
        Command::Update(_) => unreachable!("infallible: matched previously"),
    }
}
