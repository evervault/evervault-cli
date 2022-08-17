use thiserror::Error;

use crate::common::OutputPathError;

#[derive(Debug, Error)]
pub enum DeployError {
    #[error("Could not describe eif {0}")]
    DescribeError(#[from] crate::describe::error::DescribeError),
    #[error("Could not build eif {0}")]
    BuildError(#[from] crate::build::error::BuildError),
    #[error("An error occurred while reading the cage config — {0}")]
    CageConfigError(#[from] crate::config::CageConfigError),
    #[error("Failed to access output directory — {0}")]
    FailedToAccessOutputDir(#[from] OutputPathError),
    #[error("An IO error occurred {0}")]
    IoError(#[from] std::io::Error),
    #[error("Error creating zip — {0}")]
    ZipError(#[from] zip::result::ZipError),
    #[error("An error occurred while uploading to S3 — {0}")]
    RequestError(#[from] reqwest::Error),
}
