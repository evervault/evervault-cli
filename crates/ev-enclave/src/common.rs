use crate::config::{EnclaveConfig, EnclaveConfigError};
use common::CliError;
use std::ffi::OsStr;
use std::path::PathBuf;
use thiserror::Error;

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

pub fn save_enclave_config(enclave_config: &EnclaveConfig, config_path: &str) {
    if let Ok(serialized_config) = toml::ser::to_vec(&enclave_config) {
        match std::fs::write(config_path, serialized_config) {
            Ok(_) => log::debug!("Enclave config updated"),
            Err(e) => log::error!("Failed to update Enclave config — {e:?}"),
        };
    } else {
        log::error!("Failed to serialize attestation measures in Enclave config");
    }
}

pub fn log_debug_mode_attestation_warning() {
    log::warn!("When running your Enclave in debug mode, every value in the attestation document returned will be 0.");
    log::warn!("The measurements below will only be returned when running in non-debug mode.");
}

pub fn prepare_build_args(build_args: &Vec<String>) -> Option<Vec<String>> {
    if build_args.is_empty() {
        return None;
    }

    let mut formatted_args: Vec<String> = Vec::with_capacity(build_args.len() * 2);
    build_args
        .iter()
        .fold(&mut formatted_args, |acc, build_arg| {
            acc.push("--build-arg".to_string());
            acc.push(build_arg.clone());
            acc
        });
    Some(formatted_args)
}

pub fn prepare_build_secrets(build_secrets: &Vec<String>) -> Option<Vec<String>> {
    if build_secrets.is_empty() {
        return None;
    }

    let mut formatted_secrets: Vec<String> = Vec::with_capacity(build_secrets.len() * 2);
    build_secrets
        .iter()
        .fold(&mut formatted_secrets, |acc, build_secret| {
            acc.push("--secret".to_string());
            acc.push(build_secret.clone());
            acc
        });

    Some(formatted_secrets)
}

pub fn resolve_enclave_uuid(
    given_uuid: Option<&str>,
    config_path: &str,
) -> Result<Option<String>, EnclaveConfigError> {
    if let Some(given_uuid) = given_uuid {
        return Ok(Some(given_uuid.to_string()));
    }
    let config = EnclaveConfig::try_from_filepath(config_path)?;
    Ok(config.uuid)
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

    #[test]
    fn test_build_args_prep_with_empty_list() {
        let args = vec![];
        let result = prepare_build_args(&args);
        assert_eq!(None, result);
    }

    #[test]
    fn test_build_args_prep_with_non_empty_list() {
        let args = vec!["DEBUG=true".into(), "API_KEY=secret".into()];
        let result = prepare_build_args(&args);
        assert!(result.is_some());
        let formatted = result.unwrap();
        let chunked_args = formatted.chunks(2);
        let combined_iter = args.iter().zip(chunked_args.into_iter());
        combined_iter.for_each(|(expected_arg, formatted_args)| {
            let flag = formatted_args[0].as_str();
            let value = formatted_args[1].as_str();
            assert_eq!(flag, "--build-arg");
            assert_eq!(value, expected_arg.as_str());
        });
    }

    #[test]
    fn test_build_secrets_prep_with_empty_list() {
        let secrets = vec![];
        let result = prepare_build_secrets(&secrets);
        assert_eq!(None, result);
    }

    #[test]
    fn test_build_secrets_prep_with_non_empty_list() {
        let secrets = vec![
            "id=aws,src=$HOME/.aws/credentials".into(),
            "id=ssh,src=$HOME/.ssh".into(),
        ];
        let result = prepare_build_secrets(&secrets);
        assert!(result.is_some());
        let formatted = result.unwrap();
        let chunked_secrets = formatted.chunks(2);
        let combined_iter = secrets.iter().zip(chunked_secrets.into_iter());
        combined_iter.for_each(|(expected_secret, formatted_secrets)| {
            let flag = formatted_secrets[0].as_str();
            let value = formatted_secrets[1].as_str();
            assert_eq!(flag, "--secret");
            assert_eq!(value, expected_secret.as_str());
        });
    }
}
