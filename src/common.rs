use std::ffi::OsStr;
use std::path::PathBuf;
use thiserror::Error;

use crate::config::CageConfig;

pub struct OutputPath {
    _tmp_dir: Option<tempfile::TempDir>,
    file_path: PathBuf,
}

impl OutputPath {
    pub fn path(&self) -> &PathBuf {
        &self.file_path
    }

    pub fn join(&self, path: &std::path::Path) -> PathBuf {
        self.file_path.join(path)
    }
}

impl std::convert::From<PathBuf> for OutputPath {
    fn from(value: PathBuf) -> Self {
        Self {
            _tmp_dir: None,
            file_path: value,
        }
    }
}

impl std::convert::From<tempfile::TempDir> for OutputPath {
    fn from(value: tempfile::TempDir) -> Self {
        let tmp_path = value.path().to_path_buf();
        Self {
            _tmp_dir: Some(value),
            file_path: tmp_path,
        }
    }
}

#[derive(Debug, Error)]
pub enum OutputPathError {
    #[error("The directory provided does not exist.")]
    PathDoesNotExist,
    #[error("Failed to get absolute path — {0:?}")]
    FailedToGetAbsolutePath(#[from] std::io::Error),
    #[error("Failed to create temp dir — {0:?}")]
    FailedToCreateTempDir(std::io::Error),
}

impl CliError for OutputPathError {
    fn exitcode(&self) -> exitcode::ExitCode {
        match self {
            Self::PathDoesNotExist => exitcode::NOINPUT,
            Self::FailedToGetAbsolutePath(_) => exitcode::IOERR,
            Self::FailedToCreateTempDir(_) => exitcode::CANTCREAT,
        }
    }
}

pub fn resolve_output_path(
    supplied_path: Option<impl AsRef<OsStr>>,
) -> Result<OutputPath, OutputPathError> {
    if let Some(output_dir) = supplied_path {
        let path = std::path::Path::new(&output_dir);
        let absolute_path = path.canonicalize().map(OutputPath::from)?;
        Ok(absolute_path)
    } else {
        let temp_dir = tempfile::TempDir::new().map_err(OutputPathError::FailedToCreateTempDir)?;
        Ok(OutputPath::from(temp_dir))
    }
}

pub fn update_cage_config_with_eif_measurements(
    cage_config: &mut CageConfig,
    config_path: &str,
    eif_measurements: &crate::enclave::EIFMeasurements,
) {
    cage_config.set_attestation(eif_measurements);

    if let Ok(serialized_config) = toml::ser::to_vec(&cage_config) {
        match std::fs::write(config_path, serialized_config) {
            Ok(_) => log::debug!("Cage config updated with enclave attestation measures"),
            Err(e) => log::error!(
                "Failed to write attestation measures to cage config — {:?}",
                e
            ),
        };
    } else {
        log::error!("Failed to serialize attestation measures in cage config");
    }
}

pub fn log_debug_mode_attestation_warning() {
    log::warn!("When running your Cage in debug mode, every value in the attestation document returned will be 0.");
    log::warn!("The measurements below will only be returned when running in non-debug mode.");
}

pub trait CliError {
    fn exitcode(&self) -> exitcode::ExitCode;
}

#[macro_export]
macro_rules! get_api_key {
    () => {
        match std::env::var("EV_API_KEY") {
            Ok(api_key) => api_key,
            Err(_) => {
                eprintln!(
                    "No API Key given. Set the EV_API_KEY environment variable to authenticate."
                );
                return exitcode::NOUSER;
            }
        }
    };
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_resolve_output_path_with_no_path_given() {
        let path: Option<&str> = None;
        let output_path = resolve_output_path(path).expect("Failed to generate temp file");
        assert!(output_path._tmp_dir.is_some());
    }

    #[test]
    fn test_resolve_output_path_with_path_given() {
        let output_path =
            resolve_output_path(Some("./src")).expect("Failed to resolve canonical path");
        assert!(output_path._tmp_dir.is_none());
        assert!(output_path.file_path.as_path().ends_with("src"));
    }
}
