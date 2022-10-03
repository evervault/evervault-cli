use indicatif::{ProgressBar, ProgressStyle};
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

pub fn prepare_build_args(build_args: &Vec<String>) -> Option<Vec<String>> {
    if build_args.len() == 0 {
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

fn get_progress_bar(start_msg: &str, upload: bool) -> ProgressBar {
    let progress_bar = ProgressBar::new_spinner();
    progress_bar.enable_steady_tick(std::time::Duration::from_millis(80));
    if upload {
        progress_bar.set_style(ProgressStyle::default_bar()
        .template("Uploading Cage to Evervault {bar:40.green/blue} {bytes} ({percent}%) [{elapsed_precise}]")
        .expect("Failed to create progress bar template from hardcoded template")
        .progress_chars("##-"));
    } else {
        progress_bar.set_style(
            ProgressStyle::default_spinner()
                .tick_strings(&["⣾", "⣽", "⣻", "⢿", "⡿", "⣟", "⣯", "⣷", "[INFO]"])
                .template("{spinner:.green} {msg}")
                .expect("Failed to create progress bar template from hardcoded template"),
        );
    }
    progress_bar.set_message(start_msg.to_string());
    progress_bar
}

struct Tty { progress_bar: ProgressBar }
struct NonTty {}

impl<'a, W: ProgressLogger + ?Sized + 'a> ProgressLogger for Box<W> {
    fn update_progress(&self, message: &str) -> () {
        (**self).update_progress(message)
    }
    fn finish_with_message(&self, message: &'static str) -> () {
        (**self).finish_with_message(message) 
    }

    fn finish(&self) {
        (**self).finish() 
    }
}
pub trait ProgressLogger {
    fn update_progress(&self, message: &str) -> ();
    fn finish_with_message(&self, message: &'static str) -> ();
    fn finish(&self);
}

impl ProgressLogger for Tty {
    fn update_progress(&self, message: &str) {
        self.progress_bar.set_message(message.to_string());
    }
    fn finish_with_message(&self, message: & 'static str) -> () {
        self.progress_bar.finish_with_message(message) 
    }
    fn finish(&self) -> () {
        self.progress_bar.finish();
    }
}

impl ProgressLogger for NonTty {
    fn update_progress(&self, message: &str) {
        log::info!("{}", message.to_string())
    }
    fn finish_with_message(&self, message: &'static str) {
        log::info!("{}", message.to_string()) 
    }
    fn finish(&self) -> () {
        // no op
    }
}

pub fn get_tracker(first_message: &str, upload: bool) -> Box<dyn ProgressLogger> {
    if false {
        let progress_bar = get_progress_bar(first_message, upload);
        Box::new(Tty { progress_bar })
    } else {
        log::info!("{}", first_message);
        Box::new(NonTty {})
    }
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
}
