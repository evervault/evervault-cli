use crate::build::build_enclave_image_file;
use crate::config::{CageConfig, ValidatedCageBuildConfig};
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

    /// Certificate used to sign the enclave image file
    #[clap(long = "signing-cert")]
    pub certificate: Option<String>,

    /// Private key used to sign the enclave image file
    #[clap(long = "private-key")]
    pub private_key: Option<String>,
}

pub async fn run(deploy_args: DeployArgs) {
    let mut cage_config = match CageConfig::try_from_filepath(&deploy_args.config) {
        Ok(cage_config) => cage_config,
        Err(e) => {
            log::error!("An error occurred while reading the cage config — {:?}", e);
            return;
        }
    };

    merge_config_with_args(&deploy_args, &mut cage_config);
    let validated_config: ValidatedCageBuildConfig = match cage_config.try_into() {
        Ok(validated) => validated,
        Err(e) => {
            log::error!("Failed to validate cage config — {}", e);
            return;
        }
    };

    let _built_enclave =
        match build_enclave_image_file(validated_config, &deploy_args.context_path, None, false)
            .await
        {
            Ok(enclave_info) => enclave_info,
            Err(e) => {
                log::error!("Failed to build an enclave from your Dockerfile — {}", e);
                return;
            }
        };

    // TODO: implement deployment logic
}

fn merge_config_with_args(args: &DeployArgs, config: &mut CageConfig) {
    if config.dockerfile().is_none() {
        config.set_dockerfile(args.dockerfile.clone());
    }

    if args.certificate.is_some() && config.cert().is_none() {
        config.set_cert(args.certificate.clone().unwrap());
    }

    if args.private_key.is_some() && config.key().is_none() {
        config.set_key(args.private_key.clone().unwrap());
    }
}
