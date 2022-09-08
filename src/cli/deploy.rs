use crate::{deploy::{deploy_eif, get_eif}, config::{read_and_validate_config, ValidatedCageBuildConfig}, enclave::EIFMeasurements, common::OutputPath};
use crate::common::{CliError};
use crate::api::{self, client::ApiClient, AuthMode};
use crate::config::BuildTimeConfig;
use crate::build::build_enclave_image_file;
use clap::Parser;

/// Deploy a Cage from a toml file.
#[derive(Debug, Parser)]
#[clap(name = "deploy", about)]
pub struct DeployArgs {
    /// Path to cage.toml config file
    #[clap(short = 'c', long = "config", default_value = "./cage.toml")]
    pub config: String,

    /// Path to Dockerfile for Cage. Will override any dockerfile specified in the .toml file.
    #[clap(short = 'f', long = "file")]
    pub dockerfile: Option<String>,

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

impl BuildTimeConfig for DeployArgs {
    fn certificate(&self) -> Option<&str> {
        self.certificate.as_deref()    
    }

    fn dockerfile(&self) -> Option<&str> {
        self.dockerfile.as_deref()
    }

    fn private_key(&self) -> Option<&str> {
        self.private_key.as_deref()
    }
}

pub async fn run(deploy_args: DeployArgs) -> exitcode::ExitCode {
    let (mut cage_config, validated_config) = match read_and_validate_config(&deploy_args.config, &deploy_args) {
        Ok(configs) => configs,
        Err(e) => {
            log::error!("Failed to validate Cage config - {}", e);
            return e.exitcode();
        }
    };

    let (eif_measurements, output_path) = match resolve_eif(
        &validated_config, 
        &deploy_args.context_path, 
        deploy_args.eif_path.as_deref(), 
        !deploy_args.quiet
    ).await {
        Ok(eif_info) => eif_info,
        Err(e) => return e
    };

    if deploy_args.write {
        crate::common::update_cage_config_with_eif_measurements(
            &mut cage_config,
            &deploy_args.config,
            &eif_measurements,
        );
    }

    let cage_api = api::cage::CagesClient::new(AuthMode::ApiKey(deploy_args.api_key.clone()));

    let cage = match cage_api.get_cage(validated_config.cage_uuid()).await {
        Ok(cage) => cage,
        Err(e) => {
            log::error!("Failed to retrieve Cage details from Evervault API – {}", e);
            return e.exitcode();
        }
    };

    match deploy_eif(&validated_config, &cage_api, output_path, eif_measurements).await {
        Ok(_) => println!("Deployment was successful"),
        Err(e) => {
            print!("{}", e);
            return e.exitcode();
        }
    };

    println!("Cage deployed successfully. Your Cage is now available at {}", cage.domain());
    exitcode::OK
}

async fn resolve_eif(
    validated_config: &ValidatedCageBuildConfig, 
    context_path: &str, 
    eif_path: Option<&str>, 
    verbose: bool
) -> Result<(EIFMeasurements, OutputPath), exitcode::ExitCode> {
    if let Some(path) = eif_path {
        return get_eif(path).map_err(|e| {
            log::error!("Failed to access the EIF at {}", path);
            e.exitcode()
        });
    } else {
        build_enclave_image_file(
            validated_config,
            context_path,
            None,
            verbose
        )
        .await
        .map(|enclave_info| {
            let (built_enclave, output_path) = enclave_info;
            (built_enclave.measurements().clone(), output_path)
        }).map_err(|build_err| {
            log::error!("Failed to build EIF - {}", build_err);
            build_err.exitcode()
        })
    }
}