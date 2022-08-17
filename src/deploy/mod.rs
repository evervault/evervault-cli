use crate::api;
use crate::api::cage::CagesClient;
use crate::api::{cage::CreateCageDeploymentIntentRequest, client::ApiClient, AuthMode};
use crate::build::build_enclave_image_file;
use crate::cli::deploy::DeployArgs;
use crate::common::{resolve_output_path, OutputPath};
use crate::config::{CageConfig, ValidatedCageBuildConfig};
use crate::describe::describe_eif;
use crate::enclave::EIFMeasurements;
use std::fs;
use std::io::Write;
mod error;
use error::DeployError;
use indicatif::{ProgressBar, ProgressStyle};

pub async fn deploy_eif(deploy_args: DeployArgs) -> Result<(), DeployError> {
    let mut cage_config = CageConfig::try_from_filepath(&deploy_args.config)?;

    merge_config_with_args(&deploy_args, &mut cage_config);
    let validated_config: ValidatedCageBuildConfig = cage_config.clone().try_into()?;

    let cage_uuid = validated_config.cage_uuid().to_string();

    let (eif_measurements, output_path) = match deploy_args.eif_path {
        Some(eif_path) => get_eif(eif_path)?,
        None => build_enclave_image_file(
            &validated_config,
            &deploy_args.context_path,
            None,
            !deploy_args.quiet,
        )
        .await
        .map(|enclave_info| {
            let (built_enclave, output_path) = enclave_info;
            (built_enclave.measurements().clone(), output_path)
        })?,
    };

    if deploy_args.write {
        crate::common::update_cage_config_with_eif_measurements(
            &mut cage_config,
            &deploy_args.config,
            &eif_measurements,
        );
    }

    let cage_api = api::cage::CagesClient::new(AuthMode::ApiKey(deploy_args.api_key.clone()));

    let zip_content = create_zip_archive_for_eif(output_path.path())?;

    let cage_deployment_intent_payload = CreateCageDeploymentIntentRequest::new(
        eif_measurements.pcrs(),
        validated_config.debug,
        validated_config.egress().is_enabled(),
    );
    let deployment_intent = cage_api
        .create_cage_deployment_intent(&cage_uuid, cage_deployment_intent_payload)
        .await?;

    let s3_upload_url = deployment_intent.signed_url();
    let reqwest_client = api::Client::builder().build().unwrap();

    let get_progress_bar = |start_msg: &str| {
        let progress_bar = ProgressBar::new_spinner();
        progress_bar.enable_steady_tick(80);
        progress_bar.set_style(
            ProgressStyle::default_spinner()
                .tick_strings(&["⣾", "⣽", "⣻", "⢿", "⡿", "⣟", "⣯", "⣷", "[INFO]"])
                .template("{spinner:.green} {msg}"),
        );
        progress_bar.set_message(start_msg);
        progress_bar
    };

    let progress_bar = get_progress_bar("Uploading Cage to Evervault...");

    reqwest_client
        .put(s3_upload_url)
        .header("Content-Type", "application/zip")
        .body(zip_content)
        .send()
        .await
        .map(|_| progress_bar.finish_with_message("Cage uploaded to Evervault."))
        .map_err(|_| progress_bar.finish_with_message("Cage failed to upload."))
        .unwrap();

    let progress_bar = get_progress_bar("Deploying Cage into a Nitro Enclave...");

    watch_deployment(
        cage_api,
        deployment_intent.cage_uuid(),
        deployment_intent.deployment_uuid(),
        progress_bar,
    )
    .await;
    Ok(())
}

async fn watch_deployment(
    cage_api: CagesClient,
    cage_uuid: &str,
    deployment_uuid: &str,
    progress_bar: ProgressBar,
) {
    loop {
        match cage_api
            .get_cage_deployment_by_uuid(cage_uuid, deployment_uuid)
            .await
        {
            Ok(deployment_response) => {
                if deployment_response.is_finished() {
                    progress_bar.finish_with_message("Cage deployed!");
                    break;
                }
            }
            Err(e) => {
                progress_bar.finish();
                println!("Unable to retrieve deployment status. Error: {:?}", e);
                break;
            }
        };
        tokio::time::sleep(std::time::Duration::from_millis(6000)).await;
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

fn get_eif(eif_path: String) -> Result<(EIFMeasurements, OutputPath), DeployError> {
    let eif = describe_eif(&eif_path)?;
    let output_path = resolve_output_path(None::<&str>)?;
    let output_p = format!("{}/enclave.eif", output_path.path().to_str().unwrap());
    fs::copy(&eif_path, output_p)?;
    Ok((eif.measurements.measurements, output_path))
}
