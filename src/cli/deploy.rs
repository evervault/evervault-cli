use clap::Parser;

/// Manage Cage signing certificates
#[derive(Debug, Parser)]
#[clap(name = "deploy", about)]
pub struct DeployArgs {
    /// Path to eif to deploy
    #[clap(long = "eif")]
    pub eif_path: String,

    /// Name of the Cage to deploy
    #[clap(long = "name")]
    pub name: String,
}

pub async fn run(_deploy_args: DeployArgs) {}
