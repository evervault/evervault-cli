use super::error::CommandError;
use std::ffi::OsStr;
use std::path::Path;
use std::process::{Command, ExitStatus, Output, Stdio};

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

pub fn build_image_using_kaniko(
    output_path: &Path,
    tar_destination: &Path,
    context_path: &Path,
    tag_name: &str,
    verbose: bool,
) -> Result<ExitStatus, CommandError> {
    let command_config = CommandConfig::new(verbose);
    let context_volume = format!("{}:/workspace", context_path.display());
    let output_volume = format!("{}:/output", output_path.display());
    let tar_destination_volume = format!("{}:/image", tar_destination.display());

    let build_image_args: Vec<&OsStr> = vec![
        "run".as_ref(),
        "--volume".as_ref(),
        context_volume.as_str().as_ref(),
        "--volume".as_ref(),
        output_volume.as_str().as_ref(),
        "--volume".as_ref(),
        tar_destination_volume.as_str().as_ref(),
        "--rm".as_ref(),
        "--network=host".as_ref(),
        "gcr.io/kaniko-project/executor:v1.7.0".as_ref(),
        "--context".as_ref(),
        "dir:///workspace/".as_ref(),
        "--tarPath".as_ref(),
        "/image/image.tar".as_ref(),
        "--no-push".as_ref(),
        "--destination".as_ref(),
        tag_name.as_ref(),
        "--dockerfile".as_ref(),
        "ev-user.Dockerfile".as_ref(),
        "--reproducible".as_ref(),
        "--single-snapshot".as_ref(),
        "--snapshotMode=redo".as_ref(),
        "--customPlatform=linux/amd64".as_ref(),
    ];

    // Kaniko pipes the output of RUN directives to stdout, which prevents programmatic use of the PCRs
    // If stdout is being piped, then set the stdout stream to null
    let is_stdout_piped = atty::isnt(atty::Stream::Stdout);
    let command_status = Command::new("docker")
        .args(build_image_args)
        .stdout(if is_stdout_piped {
            Stdio::null()
        } else {
            command_config.output_setting()
        })
        .stderr(command_config.output_setting())
        .output()?;

    Ok(command_status.status)
}

pub fn load_image_into_local_docker_registry(
    image_archive: &Path,
    verbose: bool,
) -> Result<ExitStatus, CommandError> {
    let command_config = CommandConfig::new(verbose);
    let is_stdout_piped = atty::isnt(atty::Stream::Stdout);
    let docker_load_result = Command::new("docker")
        .args(vec![
            "load".as_ref(),
            "--input".as_ref(),
            image_archive.as_os_str(),
        ])
        .stdout(if is_stdout_piped {
            Stdio::null()
        } else {
            command_config.output_setting()
        })
        .stderr(command_config.output_setting())
        .status()?;
    Ok(docker_load_result)
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
        .status();

    match status {
        Ok(status) => Ok(status),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            Err(CommandError::CommandNotFound("Docker".to_string()))
        }
        Err(e) => Err(e.into()),
    }
}
