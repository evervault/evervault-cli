use super::{DeployError, DeployMessage};
use crate::CmdOutput;

impl CmdOutput for DeployError {
    fn code(&self) -> String {
        match self {
            DeployError::Toml(_) => "functions/toml-error",
            DeployError::FetchAppFunctions(_) => "generic/api-error",
            DeployError::Validation(_) => "generic/validation-failed",
            DeployError::Io(_) => "generic/io-error",
            DeployError::VersionDeprecated(_, _) => "functions/version-deprecated",
            DeployError::VersionWillBeDeprecated(_, _) => "functions/version-will-be-deprecated",
            DeployError::RecordCreate(_) => "functions/api-error",
            DeployError::ZipNotFound => "functions/zip-not-found",
            DeployError::FunctionUpload(_) => "functions/upload-error",
            DeployError::DeploymentFailed(_) => "functions/deployment-failed",
            DeployError::DeploymentCancelled => "functions/deployment-cancelled",
            DeployError::DeploymentStatusFetch(_) => "functions/deployment-status-api-error",
        }
        .to_string()
    }

    fn exitcode(&self) -> crate::errors::ExitCode {
        match self {
            DeployError::Toml(_) => crate::errors::CONFIG,
            DeployError::Io(_) => crate::errors::IOERR,
            _ => crate::errors::GENERAL,
        }
    }

    fn data(&self) -> Option<serde_json::Value> {
        None
    }
}

impl CmdOutput for DeployMessage {
    fn code(&self) -> String {
        match self {
            DeployMessage::Deployed { .. } => "functions/deployed",
            DeployMessage::BackgroundDeployment => "functions/background-deployment-started",
        }
        .to_string()
    }

    fn exitcode(&self) -> crate::errors::ExitCode {
        crate::errors::OK
    }

    fn data(&self) -> Option<serde_json::Value> {
        match self {
            DeployMessage::Deployed { uuid } => Some(serde_json::json!({ "uuid": uuid })),
            _ => None,
        }
    }
}
