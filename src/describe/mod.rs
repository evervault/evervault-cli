pub mod error;

use crate::common::{resolve_output_path, get_tracker};
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

    let describe_progress = get_tracker("Getting PCRs from existing EIF", false);

    let supplied_path: Option<&str> = None;
    let output_path = resolve_output_path(supplied_path).unwrap();
    enclave::build_nitro_cli_image(output_path.path(), None, false).unwrap();

    let description = enclave::describe_eif(&absolute_path).unwrap();
    describe_progress.finish_with_message("PCRs retrieved.");

    Ok(description)
}
