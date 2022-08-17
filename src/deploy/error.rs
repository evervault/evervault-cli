use thiserror::Error;

use crate::common::OutputPathError;

#[derive(Debug, Error)]
pub enum DeployError {
    #[error("Could not describe eif {0}")]
    DescribeError(#[from] crate::describe::error::DescribeError),
    #[error("Failed to access output directory — {0:?}")]
    FailedToAccessOutputDir(#[from] OutputPathError),
    #[error("An IO error occurred {0}")] 
    IoError(#[from] std::io::Error)
}
