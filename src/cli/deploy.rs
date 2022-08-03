use clap::Parser;

/// Deploy a Cage from a toml file.
#[derive(Debug, Parser)]
#[clap(name = "deploy", about)]
pub struct DeployArgs {
    /// Path to cage.toml config file
    #[clap(short = 'c', long = "config", default_value = "./cage.toml")]
    pub config: String,

    /// Path to Dockerfile for Cage. Will override any dockerfile specified in the .toml file.
    #[clap(short = 'f', long = "file", default_value = "./Dockerfile")]
    pub dockerfile: String,

    /// Path to use for docker context
    #[clap(default_value = ".")]
    pub context_path: String,
}

pub async fn run(_deploy_args: DeployArgs) {}
