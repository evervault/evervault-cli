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
pub enum EnclaveCommand {
    Build(build::BuildArgs),
    Cert(cert::CertArgs),
    Delete(delete::DeleteArgs),
    Describe(describe::DescribeArgs),
    Deploy(deploy::DeployArgs),
    Init(init::InitArgs),
    List(list::List),
    Logs(logs::LogArgs),
    Update(update::UpdateArgs),
    #[cfg(not(target_os = "windows"))]
    Attest(attest::AttestArgs),
    Restart(restart::RestartArgs),
    Scale(scale::ScaleArgs),
    Migrate(migrate::MigrateArgs),
}
