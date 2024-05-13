use clap::Parser;
#[cfg(not(target_os = "windows"))]
pub mod attest;
pub mod build;
pub mod cert;
pub mod delete;
pub mod deploy;
pub mod describe;
pub mod init;
pub mod list;
pub mod logs;
pub mod migrate;
pub mod restart;
pub mod scale;
pub mod update;

#[derive(Parser, Debug)]
#[command(name = "enclave")]
pub struct EnclaveArgs {
    #[command(subcommand)]
    pub action: EnclaveCommand,
}

#[derive(Parser, Debug)]
#[command(name = "enclave")]
pub enum EnclaveCommand {
    #[cfg(not(target_os = "windows"))]
    Attest(attest::AttestArgs),
    Build(build::BuildArgs),
    Describe(describe::DescribeArgs),
    Migrate(migrate::MigrateArgs),
    Update(update::UpdateArgs),
    #[command(flatten)]
    Authenticated(AuthenticatedEnclaveCommand),
}

#[derive(Parser, Debug)]
pub enum AuthenticatedEnclaveCommand {
    Cert(cert::CertArgs),
    Delete(delete::DeleteArgs),
    Deploy(deploy::DeployArgs),
    Init(init::InitArgs),
    List(list::List),
    Logs(logs::LogArgs),
    Restart(restart::RestartArgs),
    Scale(scale::ScaleArgs),
}

pub async fn run(enclave_args: EnclaveArgs) -> i32 {
    match enclave_args.action {
        EnclaveCommand::Build(build_args) => build::run(build_args).await,
        EnclaveCommand::Describe(describe_args) => describe::run(describe_args).await,
        EnclaveCommand::Migrate(migrate_args) => migrate::run(migrate_args).await,
        #[cfg(not(target_os = "windows"))]
        EnclaveCommand::Attest(attest_args) => attest::run(attest_args).await,
        EnclaveCommand::Update(update_args) => update::run(update_args).await,
        EnclaveCommand::Authenticated(authenticated_command) => {
            let (api_key, _) = crate::get_auth!();

            match authenticated_command {
                AuthenticatedEnclaveCommand::Cert(cert_args) => cert::run(cert_args, api_key).await,
                AuthenticatedEnclaveCommand::Delete(delete_args) => {
                    delete::run(delete_args, api_key).await
                }
                AuthenticatedEnclaveCommand::Deploy(deploy_args) => {
                    deploy::run(deploy_args, api_key).await
                }
                AuthenticatedEnclaveCommand::Init(init_args) => init::run(init_args, api_key).await,
                AuthenticatedEnclaveCommand::List(list_args) => list::run(list_args, api_key).await,
                AuthenticatedEnclaveCommand::Logs(log_args) => logs::run(log_args, api_key).await,
                AuthenticatedEnclaveCommand::Restart(restart_args) => {
                    restart::run(restart_args, api_key).await
                }
                AuthenticatedEnclaveCommand::Scale(scale_args) => {
                    scale::run(scale_args, api_key).await
                }
            }
        }
    }
}
