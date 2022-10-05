use crate::api;
use crate::api::{cage::CagesClient, cage::CreateCageDeploymentIntentRequest};
use crate::common::{get_progress_bar, resolve_output_path, OutputPath};
use crate::config::ValidatedCageBuildConfig;
use crate::describe::describe_eif;
use crate::enclave::{EIFMeasurements, ENCLAVE_FILENAME};
use std::io::Write;
mod error;
use error::DeployError;
use indicatif::{ProgressBar, ProgressStyle};
use reqwest::Body;
use std::path::PathBuf;
use tokio::fs::File;
use tokio::time::timeout;
use tokio_stream::StreamExt;
use tokio_util::codec::{BytesCodec, FramedRead};

const ENCLAVE_ZIP_FILENAME: &str = "enclave.zip";
const DEPLOY_WATCH_TIMEOUT_SECONDS: u64 = 600; //10 minutes

pub async fn deploy_eif(
    validated_config: &ValidatedCageBuildConfig,
    cage_api: &CagesClient,
    output_path: OutputPath,
    eif_measurements: EIFMeasurements,
) -> Result<(), DeployError> {
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
        .create_cage_deployment_intent(validated_config.cage_uuid(), cage_deployment_intent_payload)
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

    let progress_bar_for_build =
        get_progress_bar("Building Cage Docker Image on Evervault Infra...");
    watch_build(
        cage_api.clone(),
        deployment_intent.cage_uuid(),
        deployment_intent.deployment_uuid(),
        progress_bar_for_build,
    )
    .await;

    let progress_bar_for_deploy =
        get_progress_bar("Deploying Cage into a Trusted Execution Environment...");

    timed_operation(
        "Cage Deployment",
        DEPLOY_WATCH_TIMEOUT_SECONDS,
        watch_deployment(
            cage_api,
            deployment_intent.cage_uuid(),
            deployment_intent.deployment_uuid(),
            progress_bar_for_deploy,
        ),
    )
    .await?
}

async fn watch_build(
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
                if deployment_response.is_built() {
                    progress_bar.finish_with_message("Cage built on Evervault!");
                    break;
                }
            }
            Err(e) => {
                progress_bar.finish();
                log::error!("Unable to retrieve build status. Error: {:?}", e);
                break;
            }
        };
        tokio::time::sleep(std::time::Duration::from_millis(6000)).await;
    }
}

async fn watch_deployment(
    cage_api: &CagesClient,
    cage_uuid: &str,
    deployment_uuid: &str,
    progress_bar: ProgressBar,
) -> Result<(), DeployError> {
    loop {
        match cage_api
            .get_cage_deployment_by_uuid(cage_uuid, deployment_uuid)
            .await
        {
            Ok(deployment_response) => {
                if deployment_response.is_finished() {
                    progress_bar.finish_with_message("Cage deployed!");
                    break;
                } else if deployment_response.is_failed() {
                    progress_bar.finish();
                    log::error!("{}", &deployment_response.get_failure_reason());
                    return Err(DeployError::DeploymentError);
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
    Ok(())
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
        .expect("Failed to create progress bar template from hardcoded template")
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

pub fn get_eif<S: AsRef<str>>(
    eif_path: S,
    verbose: bool,
) -> Result<(EIFMeasurements, OutputPath), DeployError> {
    let eif = describe_eif(eif_path.as_ref(), verbose)?;
    let output_path = resolve_output_path(None::<&str>)?;
    let output_p = format!("{}/enclave.eif", output_path.path().to_str().unwrap());
    std::fs::copy(eif_path.as_ref(), output_p)?;
    Ok((eif.measurements.measurements, output_path))
}

async fn get_eif_size_bytes(output_path: &PathBuf) -> Result<u64, DeployError> {
    match tokio::fs::metadata(output_path.join(ENCLAVE_FILENAME)).await {
        Ok(metadata) => Ok(metadata.len()),
        Err(err) => Err(DeployError::EifSizeReadError(err)),
    }
}

pub async fn timed_operation<T: std::future::Future>(
    operation_name: &str,
    max_timeout_seconds: u64,
    operation: T,
) -> Result<<T as std::future::Future>::Output, DeployError> {
    let max_timeout = std::time::Duration::from_secs(max_timeout_seconds);
    let result = timeout(max_timeout, operation).await;
    if let Ok(r) = result {
        Ok(r)
    } else {
        Err(DeployError::TimeoutError(
            operation_name.to_string(),
            max_timeout.as_secs(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils;
    use std::thread::sleep;
    use std::time::Duration;

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

    async fn long_operation(duration: Duration) {
        tokio::time::sleep(duration).await;
    }

    #[tokio::test]
    async fn test_timed_operation_does_timeout() {
        let operation_name = "Long Operation";
        let result =
            timed_operation(operation_name, 1, long_operation(Duration::from_secs(10))).await;
        let correct_result = match result {
            Err(DeployError::TimeoutError(_, _)) => true,
            _ => false,
        };

        assert_eq!(correct_result, true);
    }

    #[tokio::test]
    async fn test_timed_operation_does_not_timeout() {
        let operation_name = "Long Operation";
        let result =
            timed_operation(operation_name, 4, long_operation(Duration::from_secs(2))).await;
        let correct_result = match result {
            Err(DeployError::TimeoutError(_, _)) => false,
            _ => true,
        };

        assert_eq!(correct_result, true);
    }
}
