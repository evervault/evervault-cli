use clap::Parser;
use common::api::BasicAuth;
#[cfg(not(target_os = "windows"))]
pub mod attest;
pub mod build;
pub mod cert;
pub mod delete;
pub mod deploy;
pub mod describe;
pub mod env;
pub mod init;
pub mod list;
pub mod logs;
pub mod migrate;
pub mod restart;
pub mod scale;

#[derive(Parser, Debug)]
#[command(name = "enclave")]
pub struct EnclaveArgs {
    #[command(subcommand)]
    pub action: EnclaveCommand,
}

#[derive(Parser, Debug)]
pub enum EnclaveCommand {
    #[cfg(not(target_os = "windows"))]
    Attest(attest::AttestArgs),
    Build(build::BuildArgs),
    Describe(describe::DescribeArgs),
    Migrate(migrate::MigrateArgs),
    Cert(cert::CertArgs),
    Delete(delete::DeleteArgs),
    Deploy(deploy::DeployArgs),
    Init(init::InitArgs),
    List(list::List),
    Logs(logs::LogArgs),
    Restart(restart::RestartArgs),
    Scale(scale::ScaleArgs),
    Env(env::EnvArgs),
}

pub async fn run(enclave_args: EnclaveArgs, auth: BasicAuth) {
    let exitcode = match enclave_args.action {
        #[cfg(not(target_os = "windows"))]
        EnclaveCommand::Attest(attest_args) => attest::run(attest_args, auth).await,
        EnclaveCommand::Build(build_args) => build::run(build_args).await,
        EnclaveCommand::Describe(describe_args) => describe::run(describe_args).await,
        EnclaveCommand::Migrate(migrate_args) => migrate::run(migrate_args).await,
        EnclaveCommand::Cert(cert_args) => cert::run(cert_args, auth).await,
        EnclaveCommand::Delete(delete_args) => delete::run(delete_args, auth).await,
        EnclaveCommand::Deploy(deploy_args) => deploy::run(deploy_args, auth).await,
        EnclaveCommand::Init(init_args) => init::run(init_args, auth).await,
        EnclaveCommand::List(list_args) => list::run(list_args, auth).await,
        EnclaveCommand::Logs(log_args) => logs::run(log_args, auth).await,
        EnclaveCommand::Restart(restart_args) => restart::run(restart_args, auth).await,
        EnclaveCommand::Scale(scale_args) => scale::run(scale_args, auth).await,
        EnclaveCommand::Env(env_args) => env::run(env_args, auth).await,
    };

    std::process::exit(exitcode);
}
