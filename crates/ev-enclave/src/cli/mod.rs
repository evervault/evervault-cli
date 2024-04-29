use clap::Parser;
#[cfg(not(target_os = "windows"))]
pub mod attest;
pub mod build;
pub mod cert;
pub mod delete;
pub mod deploy;
pub mod describe;
#[cfg(feature = "internal_dependency")]
pub mod dev;
#[cfg(feature = "internal_dependency")]
pub mod encrypt;
#[cfg(feature = "internal_dependency")]
pub mod env;
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
    #[cfg(feature = "internal_dependency")]
    Dev(dev::DevArgs),
    Init(init::InitArgs),
    List(list::List),
    Logs(logs::LogArgs),
    Update(update::UpdateArgs),
    #[cfg(not(target_os = "windows"))]
    Attest(attest::AttestArgs),
    #[cfg(feature = "internal_dependency")]
    Env(env::EnvArgs),
    #[cfg(feature = "internal_dependency")]
    Encrypt(encrypt::EncryptArgs),
    Restart(restart::RestartArgs),
    Scale(scale::ScaleArgs),
    Migrate(migrate::MigrateArgs),
}
