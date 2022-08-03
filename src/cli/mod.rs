use clap::Subcommand;
pub mod build;
pub mod cert;
pub mod deploy;
pub mod init;

#[derive(Debug, Subcommand)]
pub enum Command {
    Build(build::BuildArgs),
    Cert(cert::CertArgs),
    Deploy(deploy::DeployArgs),
    Init(init::InitArgs),
}
