use crate::common::OutputPathError;
use crate::config::SigningInfoError;
use crate::docker::error::DockerError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum BuildError {
    #[error("Context directory ({0}) does not exist")]
    ContextDirectoryDoesNotExist(String),
    #[error("Failed to access output directory — {0:?}")]
    FailedToAccessOutputDir(#[from] OutputPathError),
    #[error("Invalid signing info provided. {0}")]
    InvalidSigningInfo(#[from] SigningInfoError),
    #[error("{0}")]
    DockerError(#[from] DockerError),
    #[error(
        "Failed to access dockerfile at {0}. You can specify the dockerfile using the -f flag."
    )]
    DockerfileAccessError(String),
    #[error("Failed to write the Cage dockerfile to the file system - {0:?}")]
    FailedToWriteCageDockerfile(std::io::Error),
    #[error("An error occurred while building your docker image — {0}")]
    DockerBuildError(String),
    #[error("An error occurred while converting your image to an enclave — {0}")]
    EnclaveConversionError(String),
}
