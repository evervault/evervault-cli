use clap::{Parser, Subcommand};

use crate::BaseArgs;
mod enclave;

#[derive(Parser, Debug)]
pub enum Command {
    Enclave(EnclaveArgs),
}

#[derive(Parser, Debug)]
#[command(name = "enclave")]
pub struct EnclaveArgs {
    #[command(subcommand)]
    pub action: EnclaveCommand,
}

#[derive(Debug, Subcommand)]
pub enum EnclaveCommand {
    #[command()]
    Build(enclave::build::BuildArgs),
    Cert(enclave::cert::CertArgs),
    Delete(enclave::delete::DeleteArgs),
    Deploy(enclave::deploy::DeployArgs),
    Describe(enclave::describe::DescribeArgs),
    Init(enclave::init::InitArgs),
    List(enclave::list::List),
    Logs(enclave::logs::LogArgs),
    Update(enclave::update::UpdateArgs),
    #[cfg(not(target_os = "windows"))]
    Attest(enclave::attest::AttestArgs),
    Restart(enclave::restart::RestartArgs),
    Scale(enclave::scale::ScaleArgs),
    Migrate(enclave::migrate::MigrateArgs),
}

pub async fn run_command(base_args: BaseArgs) -> i32 {
    if let Err(e) = crate::version::check_version().await {
        log::error!("{}", e);
        return exitcode::SOFTWARE;
    };

    let exit_code = match base_args.command {
        Command::Enclave(enclave_args) => run_enclave(enclave_args).await,
    };

    exit_code
}

pub async fn run_enclave(args: EnclaveArgs) -> i32 {
    match args.action {
        EnclaveCommand::Build(build_args) => enclave::build::run(build_args).await,
        EnclaveCommand::Cert(cert_args) => enclave::cert::run(cert_args).await,
        EnclaveCommand::Delete(delete_args) => enclave::delete::run(delete_args).await,
        EnclaveCommand::Deploy(deploy_args) => enclave::deploy::run(deploy_args).await,
        EnclaveCommand::Describe(describe_args) => enclave::describe::run(describe_args).await,
        EnclaveCommand::Init(init_args) => enclave::init::run(init_args).await,
        EnclaveCommand::List(list_args) => enclave::list::run(list_args).await,
        EnclaveCommand::Logs(log_args) => enclave::logs::run(log_args).await,
        EnclaveCommand::Update(update_args) => enclave::update::run(update_args).await,
        #[cfg(not(target_os = "windows"))]
        EnclaveCommand::Attest(attest_args) => enclave::attest::run(attest_args).await,
        EnclaveCommand::Restart(restart_args) => enclave::restart::run(restart_args).await,
        EnclaveCommand::Scale(scale_args) => enclave::scale::run(scale_args).await,
        EnclaveCommand::Migrate(migrate_args) => enclave::migrate::run(migrate_args).await,
    }
}
