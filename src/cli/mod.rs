use clap::Subcommand;
#[cfg(not(target_os = "windows"))]
pub mod attest;
pub mod build;
pub mod cert;
pub mod delete;
pub mod deploy;
pub mod describe;
pub mod dev;
pub mod encrypt;
pub mod env;
pub mod init;
pub mod list;
pub mod logs;
pub mod restart;
pub mod scale;
pub mod update;

#[derive(Debug, Subcommand)]
pub enum Command {
    Build(build::BuildArgs),
    Cert(cert::CertArgs),
    Delete(delete::DeleteArgs),
    Describe(describe::DescribeArgs),
    Deploy(deploy::DeployArgs),
    Dev(dev::DevArgs),
    Init(init::InitArgs),
    List(list::List),
    Logs(logs::LogArgs),
    Update(update::UpdateArgs),
    #[cfg(not(target_os = "windows"))]
    Attest(attest::AttestArgs),
    Env(env::EnvArgs),
    Encrypt(encrypt::EncryptArgs),
    Restart(restart::RestartArgs),
    Scale(scale::ScaleArgs),
}
