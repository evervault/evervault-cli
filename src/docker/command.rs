use std::ffi::OsStr;
use std::process::{Command, ExitStatus, Output, Stdio};
use thiserror::Error;

pub struct CommandConfig {
    verbose: bool,
}

impl CommandConfig {
    pub fn new(verbose: bool) -> Self {
        Self { verbose }
    }

    pub fn extra_build_args(&self) -> Vec<&OsStr> {
        vec!["--platform".as_ref(), "linux/amd64".as_ref()]
    }

    pub fn output_setting(&self) -> Stdio {
        if self.verbose {
            Stdio::inherit()
        } else {
            Stdio::null()
        }
    }
}

#[derive(Debug, Error)]
pub enum CommandError {
    #[error("An error occurred while executing a docker command — {0}")]
    IoError(#[from] std::io::Error),
}

pub fn build_image(
    dockerfile_path: &std::path::Path,
    tag_name: &str,
    command_line_args: Vec<&OsStr>,
    verbose: bool,
) -> Result<ExitStatus, CommandError> {
    let command_config = CommandConfig::new(verbose);
    let build_image_args: Vec<&OsStr> = [
        vec![
            "build".as_ref(),
            "-f".as_ref(),
            dockerfile_path.as_os_str(),
            "-t".as_ref(),
            tag_name.as_ref(),
        ],
        command_config.extra_build_args(),
        command_line_args,
    ]
    .concat();

    let command_status = Command::new("docker")
        .args(build_image_args)
        .stdout(command_config.output_setting())
        .stderr(command_config.output_setting())
        .status()?;

    Ok(command_status)
}

pub fn run_image(
    image_name: &str,
    volumes: Vec<&str>,
    command_line_args: Vec<&OsStr>,
    verbose: bool,
) -> Result<Output, CommandError> {
    let command_config = CommandConfig::new(verbose);

    let mut run_image_args: Vec<&OsStr> = vec!["run".as_ref(), "--rm".as_ref()];

    for &volume in volumes.iter() {
        run_image_args.push("-v".as_ref());
        run_image_args.push(volume.as_ref());
    }

    run_image_args.push(image_name.as_ref());

    let run_args = vec![run_image_args, command_line_args].concat();

    let command_output = Command::new("docker")
        .args(run_args)
        .stdout(Stdio::piped())
        .stderr(command_config.output_setting())
        .output()?;

    Ok(command_output)
}

pub fn docker_info() -> Result<ExitStatus, CommandError> {
    let status = std::process::Command::new("docker")
        .args(["info"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()?;

    Ok(status)
}
