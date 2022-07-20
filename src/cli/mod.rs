use clap::Subcommand;
pub mod build;
pub mod cert;

#[derive(Debug, Subcommand)]
pub enum Command {
    Build(build::BuildArgs),
    Cert(cert::CertArgs),
}
