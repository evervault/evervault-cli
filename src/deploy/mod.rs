use crate::api;
use crate::api::cage::CagesClient;
use crate::api::{cage::CreateCageDeploymentIntentRequest, client::ApiClient, AuthMode};
use crate::build::build_enclave_image_file;
use crate::cli::deploy::DeployArgs;
use crate::common::{resolve_output_path, OutputPath};
use crate::config::{CageConfig, ValidatedCageBuildConfig};
use crate::describe::describe_eif;
use crate::enclave::{EIFMeasurements, ENCLAVE_FILENAME};
use std::fs;
use std::io::Write;
mod error;
use error::DeployError;
use indicatif::{ProgressBar, ProgressStyle};
use reqwest::Body;
use std::path::PathBuf;
use tokio::fs::File;
use tokio_stream::StreamExt;
use tokio_util::codec::{BytesCodec, FramedRead};

const ENCLAVE_ZIP_FILENAME: &str = "enclave.zip";

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

    let progress_bar = get_progress_bar("Zipping Cage...");
    create_zip_archive_for_eif(output_path.path())?;
    progress_bar.finish_with_message("Cage zipped.");

    let zip_path = output_path.path().join(ENCLAVE_ZIP_FILENAME);
    let zip_file = File::open(&zip_path).await?;
    let zip_len_bytes = zip_file.metadata().await?.len();
    let zip_upload_stream = create_zip_upload_stream(zip_file, zip_len_bytes).await;

    let eif_size_bytes = get_eif_size_bytes(output_path.path()).await?;

    let cage_deployment_intent_payload = CreateCageDeploymentIntentRequest::new(
        eif_measurements.pcrs(),
        validated_config.debug,
        validated_config.egress().is_enabled(),
        eif_size_bytes,
    );
    let deployment_intent = cage_api
        .create_cage_deployment_intent(&cage_uuid, cage_deployment_intent_payload)
        .await?;

    let s3_upload_url = deployment_intent.signed_url();
    let reqwest_client = api::Client::builder().build().unwrap();
    let s3_response = reqwest_client
        .put(s3_upload_url)
        .header("Content-Type", "application/zip")
        .header("Content-Length", zip_len_bytes)
        .body(Body::wrap_stream(zip_upload_stream))
        .send()
        .await?;

    tokio::fs::remove_file(zip_path).await?;

    if s3_response.status().is_success() {
        log::info!("Cage uploaded to Evervault.");
    } else {
        return Err(DeployError::UploadError(s3_response.text().await?));
    };

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
                log::error!("Unable to retrieve deployment status. Error: {:?}", e);
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

fn create_zip_archive_for_eif(output_path: &std::path::Path) -> zip::result::ZipResult<()> {
    let zip_path = output_path.join(ENCLAVE_ZIP_FILENAME);
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

    let eif_path = output_path.join(ENCLAVE_FILENAME);
    zip.start_file(ENCLAVE_FILENAME, zip_opts)?;
    let eif = std::fs::read(eif_path)?;
    zip.write_all(eif.as_slice())?;

    let _ = zip.finish()?;

    Ok(())
}

async fn create_zip_upload_stream(
    zip_file: File,
    zip_len_bytes: u64,
) -> async_stream::AsyncStream<
    Result<bytes::BytesMut, std::io::Error>,
    impl core::future::Future<Output = ()>,
> {
    let mut stream = FramedRead::new(zip_file, BytesCodec::new());
    let progress_bar = ProgressBar::new(zip_len_bytes);
    progress_bar.set_style(ProgressStyle::default_bar()
        .template("Uploading Cage to Evervault {bar:40.green/blue} {bytes} ({percent}%) [{elapsed_precise}]")
        .progress_chars("##-"));
    async_stream::stream! {
        let mut bytes_sent = 0;
        while let Some(bytes) = stream.next().await {
            progress_bar.set_position(bytes_sent);
            if let Ok(bytes) = &bytes {
                bytes_sent += bytes.len() as u64;
            }
            yield bytes;
        }
    }
}

fn get_eif(eif_path: String) -> Result<(EIFMeasurements, OutputPath), DeployError> {
    let eif = describe_eif(&eif_path)?;
    let output_path = resolve_output_path(None::<&str>)?;
    let output_p = format!("{}/enclave.eif", output_path.path().to_str().unwrap());
    fs::copy(&eif_path, output_p)?;
    Ok((eif.measurements.measurements, output_path))
}

async fn get_eif_size_bytes(output_path: &PathBuf) -> Result<u64, DeployError> {
    match tokio::fs::metadata(output_path.join(ENCLAVE_FILENAME)).await {
        Ok(metadata) => Ok(metadata.len()),
        Err(err) => Err(DeployError::EifSizeReadError(err)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils;

    #[tokio::test]
    async fn test_get_eif_size() {
        let (_, output_path) = test_utils::build_test_cage(None).await.unwrap();
        let output_path_as_string = output_path.path().to_str().unwrap().to_string();
        let _eif_size_bytes = get_eif_size_bytes(output_path.path()).await.unwrap();
        // when we have fully reproducable builds, this test should check that the size of
        // the test EIF remains constant. Currently, it varies by a few bytes on each run.
        // e.g.
        // assert_eq!(eif_size_bytes, test_utils::TEST_EIF_SIZE_BYTES);

        // ensure temp output directory still exists after running function
        assert!(std::path::PathBuf::from(output_path_as_string).exists());
    }
}
