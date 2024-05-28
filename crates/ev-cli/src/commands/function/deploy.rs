use std::collections::HashMap;

use crate::commands::interact;
use crate::commands::interact::validators::{self, validate_function_language};
use crate::fs::{get_current_function_language, get_current_function_name, zip_current_directory};
use crate::{BaseArgs, CmdOutput};
use chrono::{NaiveDate, Utc};
use clap::Parser;
use common::api::{
    client::ApiError,
    function,
    papi::{self, EvApi},
    BasicAuth,
};
use common::function::FunctionDeploymentStatus;
use tempfile::TempDir;
use thiserror::Error;

lazy_static::lazy_static! {
    pub static ref LANGUAGE_DEPRECATION_DATE_MAP:HashMap<String, NaiveDate> = HashMap::new();
}

/// Deploy a function
#[derive(Parser, Debug)]
pub struct DeployArgs {
    /// Don't track the Function deployment status
    #[arg(short, long, default_value_t = false)]
    pub background: bool,
}

#[derive(Error, Debug)]
pub enum DeployError {
    #[error("An error occurred while fetching the Functions for your app: {0}")]
    FetchAppFunctions(ApiError),
    #[error("No name field found in function.toml. Make sure the function.toml in the current directory contains a name field.")]
    MissingNameField,
    #[error(transparent)]
    ValidationError(#[from] validators::ValidationError),
    #[error(transparent)]
    FsError(#[from] crate::fs::FsError),
    #[error("{1} was deprecated on {0}. ")]
    VersionDeprecated(NaiveDate, String),
    #[error("{1} will be deprecated on {0}.")]
    VersionWillBeDeprecated(NaiveDate, String),
    #[error("An error occured creating your Function record: {0}")]
    RecordCreate(ApiError),
    #[error("The zipped Function source was not found.")]
    ZipNotFound,
    #[error("An error occurred uploading the zipped Function source: {0}")]
    FunctionUpload(ApiError),
    #[error("An error occured deploying your Function - {0}")]
    DeploymentFailed(String),
    #[error("An error occurred fetching the deployment status of your Function")]
    DeploymentStatusFetch(ApiError),
    #[error("An error occured deploying your Function. The deployment was found to be in a cancelled state.")]
    DeploymentCancelled,
}

impl CmdOutput for DeployError {
    fn code(&self) -> String {
        match self {
            DeployError::FetchAppFunctions(_) => "function-fetch-functions-error",
            DeployError::MissingNameField => "function-missing-name-error",
            DeployError::ValidationError(_) => "function-validation-error",
            DeployError::FsError(_) => "function-fs-error",
            DeployError::VersionDeprecated(_, _) => "function-version-deprecated-error",
            DeployError::VersionWillBeDeprecated(_, _) => {
                "function-version-will-be-deprecated-error"
            }
            DeployError::RecordCreate(_) => "function-record-create-error",
            DeployError::ZipNotFound => "function-zip-not-found-error",
            DeployError::FunctionUpload(_) => "function-upload-error",
            DeployError::DeploymentFailed(_) | DeployError::DeploymentCancelled => {
                "function-deployment-error"
            }
            DeployError::DeploymentStatusFetch(_) => "function-deployment-status-fetch-error",
        }
        .to_string()
    }

    fn exitcode(&self) -> crate::errors::ExitCode {
        crate::errors::GENERAL
    }
}

#[derive(strum_macros::Display, Debug)]
pub enum DeployMessage {
    #[strum(to_string = "Function ({uuid}) Deployed Succesfully")]
    Deployed { uuid: String },
    #[strum(
        to_string = "Function deployment initiated successfully. Deployment will continue in the background. You can check the status of your Function deployment in the Evervault Dashboard"
    )]
    BackgroundDeployment,
}

impl CmdOutput for DeployMessage {
    fn code(&self) -> String {
        match self {
            DeployMessage::Deployed { .. } => "function-deployed",
            DeployMessage::BackgroundDeployment => "function-background-deployment-started",
        }
        .to_string()
    }

    fn exitcode(&self) -> crate::errors::ExitCode {
        crate::errors::OK
    }
}

pub async fn run(args: DeployArgs, auth: BasicAuth) -> Result<DeployMessage, DeployError> {
    let api_client = papi::EvApiClient::new(auth);
    let base_args = BaseArgs::parse();

    crate::fs::validate_function_directory_structure()?;
    crate::fs::validate_function_toml()?;

    let name = get_current_function_name().map_err(|_| DeployError::MissingNameField)?;

    validators::validate_function_name(&name)?;

    let language = get_current_function_language()?;

    validate_function_language(&language)?;

    let current_date: NaiveDate = Utc::now().date_naive();

    if let Some(&deprecation_date) = LANGUAGE_DEPRECATION_DATE_MAP.get(&language) {
        if current_date > deprecation_date {
            return Err(DeployError::VersionDeprecated(deprecation_date, language));
        }
        if !base_args.json {
            println!(
                "{}",
                DeployError::VersionWillBeDeprecated(deprecation_date, language)
            );
        }
    }

    let tmp_dir = TempDir::new().unwrap();

    let progress = interact::start_spinner("Zipping current direction...", !base_args.json);

    let destination = match zip_current_directory(&name, tmp_dir.path()) {
        Ok(destination) => destination,
        Err(e) => {
            progress.finish_with_message(
                "An error occurred while zipping your Function source.".into(),
            );
            return Err(DeployError::FsError(e));
        }
    };

    progress.finish_with_message("Directory zipped succesfully".into());

    let progress = interact::start_spinner("Beginning Function deployment...", !base_args.json);

    let apps_functions = api_client
        .get_all_functions_for_app()
        .await
        .map_err(DeployError::FetchAppFunctions)?;
    let maybe_function = apps_functions.iter().find(|f| f.name == name);

    let (creds, is_update) = if let Some(_) = maybe_function {
        (
            api_client
                .get_function_update_credentials(name)
                .await
                .map_err(DeployError::RecordCreate)?,
            true,
        )
    } else {
        (
            api_client
                .create_function_record(name)
                .await
                .map_err(DeployError::RecordCreate)?,
            false,
        )
    };

    if is_update {
        progress.finish_with_message("Function update initiated.".into());
    } else {
        progress.finish_with_message("Function deployment initiated.".into());
    }

    let progress = interact::start_spinner("Uploading Function source...", !base_args.json);

    let zip_file = if !destination.is_file() {
        return Err(DeployError::ZipNotFound);
    } else {
        tokio::fs::File::open(destination)
            .await
            .map_err(|e| crate::fs::FsError::Io(e))?
    };

    function::upload_function_s3(&creds.signed_url, zip_file)
        .await
        .map_err(|e| {
            progress.finish_with_message(
                "An error occurred while uploading your Function source.".into(),
            );
            DeployError::FunctionUpload(e)
        })?;

    progress.finish_with_message("Function source uploaded successfully.".into());

    if args.background {
        return Ok(DeployMessage::BackgroundDeployment);
    }

    let progress = interact::start_spinner(
        "Checking your Function deployment's status...",
        !base_args.json,
    );

    loop {
        let deployment = api_client
            .get_function_deployment(creds.uuid.clone(), creds.deployment_id.clone())
            .await
            .map_err(DeployError::DeploymentStatusFetch)?;

        if deployment.status.is_in_terminal_state() {
            progress.finish();
        }

        match deployment.status {
            FunctionDeploymentStatus::Deployed => {
                progress.finish_with_message("Function deployed successfully.".into());
                return Ok(DeployMessage::Deployed { uuid: creds.uuid });
            }
            FunctionDeploymentStatus::Failed => {
                return Err(DeployError::DeploymentFailed(
                    deployment
                        .failure_reason
                        .unwrap_or("Unknown Error occurred".into()),
                ))
            }
            FunctionDeploymentStatus::Cancelled => return Err(DeployError::DeploymentCancelled),
            status => progress.set_message(format!(
                "Function deployment status: {}",
                status.get_progress_msg().to_string()
            )),
        }

        std::thread::sleep(std::time::Duration::from_secs(6));
    }
}
