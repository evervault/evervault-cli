use crate::{common::CliError, deploy::deploy_eif};
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

    /// Path to EIF for Cage. Will not build if EIF is provided.
    #[clap(long = "eif-path")]
    pub eif_path: Option<String>,

    /// Path to use for docker context
    #[clap(default_value = ".")]
    pub context_path: String,

    /// Certificate used to sign the enclave image file
    #[clap(long = "signing-cert")]
    pub certificate: Option<String>,

    /// Private key used to sign the enclave image file
    #[clap(long = "private-key")]
    pub private_key: Option<String>,

    /// Write latest attestation information to cage.toml config file
    #[clap(short = 'w', long = "write")]
    pub write: bool,

    /// API Key
    #[clap(long = "api-key")]
    pub api_key: String,

    /// Disable verbose output
    #[clap(long)]
    pub quiet: bool,
}

pub async fn run(deploy_args: DeployArgs) -> exitcode::ExitCode {
    match deploy_eif(deploy_args).await {
        Ok(_) => println!("Deployment was successful"),
        Err(e) => {
            print!("{}", e);
            return e.exitcode();
        }
    };

    exitcode::OK
}
