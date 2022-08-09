use crate::api;
use crate::api::{cage::CreateCageDeploymentIntentRequest, client::ApiClient, AuthMode};
use crate::build::build_enclave_image_file;
use crate::config::{CageConfig, ValidatedCageBuildConfig};
use atty::Stream;
use clap::Parser;
use std::io::Write;

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

    /// Write latest attestation information to cage.toml config file
    #[clap(short = 'w', long = "write")]
    pub write: bool,

    /// API Key
    #[clap(long = "api-key")]
    pub api_key: String,

    /// Enable verbose output
    #[clap(short, long, from_global)]
    pub verbose: bool,
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
    let validated_config: ValidatedCageBuildConfig = match cage_config.clone().try_into() {
        Ok(validated) => validated,
        Err(e) => {
            log::error!("Failed to validate cage config — {}", e);
            return;
        }
    };

    let cage_uuid = validated_config.cage_uuid().to_string();
    let (built_enclave, output_path) = match build_enclave_image_file(
        &validated_config,
        &deploy_args.context_path,
        None,
        deploy_args.verbose,
    )
    .await
    {
        Ok(enclave_info) => enclave_info,
        Err(e) => {
            log::error!("Failed to build an enclave from your Dockerfile — {}", e);
            return;
        }
    };

    if validated_config.debug {
        crate::common::log_debug_mode_attestation_warning();
    }

    if deploy_args.write {
        crate::common::update_cage_config_with_eif_measurements(
            &mut cage_config,
            &deploy_args.config,
            built_enclave.measurements(),
        );
    }

    let cage_api = api::cage::CagesClient::new(AuthMode::ApiKey(deploy_args.api_key.clone()));

    let zip_content = match create_zip_archive_for_eif(output_path.path()) {
        Ok(zip_content) => zip_content,
        Err(zip_err) => {
            log::error!("Error creating zip — {:?}", zip_err);
            return;
        }
    };

    let cage_deployment_intent_payload = CreateCageDeploymentIntentRequest::new(
        built_enclave.measurements().pcrs(),
        validated_config.debug,
        validated_config.egress().is_enabled(),
    );
    let deployment_intent = match cage_api
        .create_cage_deployment_intent(&cage_uuid, cage_deployment_intent_payload)
        .await
    {
        Ok(deployment_intent) => deployment_intent,
        Err(e) => {
            log::error!("Failed to create Cage deployment intent — {:?}", e);
            return;
        }
    };

    let s3_upload_url = deployment_intent.signed_url();
    let reqwest_client = api::Client::builder().build().unwrap();

    let s3_response = match reqwest_client
        .put(s3_upload_url)
        .header("Content-Type", "application/zip")
        .body(zip_content)
        .send()
        .await
    {
        Ok(response) => response,
        Err(upload_err) => {
            log::error!("An error occurred while uploading to S3 — {:?}", upload_err);
            return;
        }
    };

    let success_msg = if s3_response.status().is_success() {
        serde_json::json!({
            "status": "success",
            "message": "Cage deployment initiated",
            "deploymentInfo": {
                "cageUuid": deployment_intent.cage_uuid(),
                "deploymentUuid": deployment_intent.deployment_uuid(),
                "cageVersion": deployment_intent.version()
            }
        })
    } else {
        serde_json::json!({
            "status": "failed",
            "message": "Failed to upload your Cage zip",
            "error": {
                "status": s3_response.status().as_u16(),
                "message": s3_response.text().await.expect("Failed to serialize error message")
            }
        })
    };

    if atty::is(Stream::Stdout) {
        // nicely format the JSON when printing to a TTY
        println!("{}", serde_json::to_string_pretty(&success_msg).unwrap());
    } else {
        println!("{}", serde_json::to_string(&success_msg).unwrap());
    }
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

fn create_zip_archive_for_eif(output_path: &std::path::Path) -> zip::result::ZipResult<Vec<u8>> {
    let zip_path = output_path.join("enclave.zip");
    let zip_file = if !zip_path.exists() {
        std::fs::File::create(&zip_path)?
    } else {
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&zip_path)?
    };

    let mut zip = zip::ZipWriter::new(zip_file);

    let zip_opts =
        zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Stored);

    let eif_path = output_path.join("enclave.eif");
    zip.start_file("enclave.eif", zip_opts)?;
    let eif = std::fs::read(eif_path)?;
    zip.write_all(eif.as_slice())?;

    let _ = zip.finish()?;
    let zip_content = std::fs::read(&zip_path)?;
    if let Err(e) = std::fs::remove_file(zip_path) {
        log::error!(
            "An error occurred while trying to delete the enclave zip — {:?}",
            e
        );
    }

    Ok(zip_content)
}
