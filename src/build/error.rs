use crate::common::{CliError, OutputPathError};
use crate::config::SigningInfoError;
use crate::docker::error::DockerError;
use crate::enclave::error::EnclaveError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum BuildError {
    #[error("Context path does not exist")]
    ContextPathDoesNotExist,
    #[error("Failed to access output directory — {0}")]
    FailedToAccessOutputDir(#[from] OutputPathError),
    #[error("Invalid signing info provided. {0}")]
    InvalidSigningInfo(#[from] SigningInfoError),
    #[error(transparent)]
    DockerError(#[from] DockerError),
    #[error(
        "Failed to access dockerfile at {0}. You can specify the dockerfile using the -f flag."
    )]
    DockerfileAccessError(String),
    #[error("Failed to write the Enclave dockerfile to the file system - {0:?}")]
    FailedToWriteEnclaveDockerfile(std::io::Error),
    #[error("An error occurred while building your docker image — {0}")]
    DockerBuildError(String),
    #[error("An error occurred while converting your image to an Enclave — {0}")]
    EnclaveConversionError(String),
    #[error(transparent)]
    EnclaveError(#[from] EnclaveError),
    #[error(transparent)]
    Utf8Error(#[from] std::str::Utf8Error),
}

impl CliError for BuildError {
    fn exitcode(&self) -> exitcode::ExitCode {
        match self {
            Self::ContextPathDoesNotExist
            | Self::InvalidSigningInfo(_)
            | Self::DockerfileAccessError(_) => exitcode::NOINPUT,
            Self::FailedToAccessOutputDir(_) | Self::FailedToWriteEnclaveDockerfile(_) => {
                exitcode::IOERR
            }
            Self::DockerError(_) | Self::DockerBuildError(_) | Self::Utf8Error(_) => {
                exitcode::SOFTWARE
            }
            Self::EnclaveConversionError(_) => exitcode::SOFTWARE,
            Self::EnclaveError(e) => e.exitcode(),
        }
    }
}
