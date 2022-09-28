use clap::Subcommand;
pub mod build;
pub mod cert;
pub mod delete;
pub mod deploy;
pub mod describe;
pub mod init;
pub mod list;
pub mod logs;
pub mod update;

#[derive(Debug, Subcommand)]
pub enum Command {
    Build(build::BuildArgs),
    Cert(cert::CertArgs),
    Delete(delete::DeleteArgs),
    Describe(describe::DescribeArgs),
    Deploy(deploy::DeployArgs),
    Init(init::InitArgs),
    List(list::List),
    Logs(logs::LogArgs),
    Update(update::UpdateArgs),
}
