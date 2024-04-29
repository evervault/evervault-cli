use clap::{Parser, Subcommand};
use ev_enclave::cli;

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
    Build(ev_enclave::cli::build::BuildArgs),
    Cert(ev_enclave::cli::cert::CertArgs),
    Delete(ev_enclave::cli::delete::DeleteArgs),
    Deploy(ev_enclave::cli::deploy::DeployArgs),
    Describe(ev_enclave::cli::describe::DescribeArgs),
    Init(ev_enclave::cli::init::InitArgs),
    List(ev_enclave::cli::list::List),
    Logs(ev_enclave::cli::logs::LogArgs),
    Update(ev_enclave::cli::update::UpdateArgs),
    #[cfg(not(target_os = "windows"))]
    Attest(ev_enclave::cli::attest::AttestArgs),
    Restart(ev_enclave::cli::restart::RestartArgs),
    Scale(ev_enclave::cli::scale::ScaleArgs),
    Migrate(ev_enclave::cli::migrate::MigrateArgs),
}

pub async fn run_enclave(args: EnclaveArgs) -> i32 {
    match args.action {
        EnclaveCommand::Build(build_args) => cli::build::run(build_args).await,
        EnclaveCommand::Cert(cert_args) => cli::cert::run(cert_args).await,
        EnclaveCommand::Delete(delete_args) => cli::delete::run(delete_args).await,
        EnclaveCommand::Deploy(deploy_args) => cli::deploy::run(deploy_args).await,
        EnclaveCommand::Describe(describe_args) => cli::describe::run(describe_args).await,
        EnclaveCommand::Init(init_args) => cli::init::run(init_args).await,
        EnclaveCommand::List(list_args) => cli::list::run(list_args).await,
        EnclaveCommand::Logs(log_args) => cli::logs::run(log_args).await,
        EnclaveCommand::Update(update_args) => cli::update::run(update_args).await,
        #[cfg(not(target_os = "windows"))]
        EnclaveCommand::Attest(attest_args) => cli::attest::run(attest_args).await,
        EnclaveCommand::Restart(restart_args) => cli::restart::run(restart_args).await,
        EnclaveCommand::Scale(scale_args) => cli::scale::run(scale_args).await,
        EnclaveCommand::Migrate(migrate_args) => cli::migrate::run(migrate_args).await,
    }
}
