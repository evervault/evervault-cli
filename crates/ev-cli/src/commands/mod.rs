use clap::Parser;

use crate::BaseArgs;

use self::enclave::EnclaveArgs;

mod enclave;

#[derive(Parser, Debug)]
pub enum Command {
    Enclave(EnclaveArgs),
}

pub async fn run_command(base_args: BaseArgs) -> i32 {
    if let Err(e) = crate::version::check_version().await {
        log::error!("{}", e);
        return exitcode::SOFTWARE;
    };

    let exit_code = match base_args.command {
        Command::Enclave(enclave_args) => enclave::run(enclave_args).await,
    };

    exit_code
}
