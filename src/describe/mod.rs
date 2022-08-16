mod error;

use crate::docker::{error::DockerError, utils::verify_docker_is_running};
use crate::enclave;
use error::DescribeError;

pub fn describe_eif(eif_path: &str) -> Result<enclave::DescribeEif, DescribeError> {
    let absolute_path = std::path::Path::new(eif_path).canonicalize().unwrap();
    if !absolute_path.exists() {
        return Err(DescribeError::EIFNotFound(absolute_path));
    }

    if !verify_docker_is_running()? {
        return Err(DockerError::DaemonNotRunning.into());
    }

    let description = enclave::describe_eif(&absolute_path).unwrap();

    Ok(description)
}
