use super::error::CommandError;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
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
    dockerfile_path: &Path,
    output_path: &Path,
    context_path: &Path,
    verbose: bool,
) -> Result<ExitStatus, CommandError> {
    let command_config = CommandConfig::new(verbose);
    let kaniko_volumes = format!("{}:/workspace", context_path.display());
    let output_volume = format!("{}:/output", output_path.display());
    let kaniko_dockerfile_path = Path::new("/workspace").join(dockerfile_path);
    let build_image_args: Vec<&OsStr> = [vec![
        "run".as_ref(),
        "--volume".as_ref(),
        output_volume.as_str().as_ref(),
        "--volume".as_ref(),
        kaniko_volumes.as_str().as_ref(),
        "--rm".as_ref(),
        "gcr.io/kaniko-project/executor:v1.7.0".as_ref(),
        "--context".as_ref(),
        "dir:///workspace/".as_ref(),
        "--tarPath".as_ref(),
        "/output/image.tar".as_ref(),
        "--no-push".as_ref(),
        "--destination".as_ref(),
        "cage-image:latest".as_ref(), // TODO: allow users to configure this
        "--dockerfile".as_ref(),
        kaniko_dockerfile_path.as_os_str(),
        // "--reproducible".as_ref(),
        "--single-snapshot".as_ref(),
        "--snapshotMode=redo".as_ref(),
        "--customPlatform=linux/amd64".as_ref(),
    ]]
    .concat();

    let command_status = Command::new("docker")
        .args(build_image_args)
        .stdout(command_config.output_setting())
        .stderr(command_config.output_setting())
        .output()?;

    Ok(command_status.status)
}

pub fn load_image_into_local_docker_registry(
    image_archive: &PathBuf,
    verbose: bool,
) -> Result<ExitStatus, CommandError> {
    let command_config = CommandConfig::new(verbose);
    let mut cat_cmd = Command::new("cat")
        .arg(image_archive.as_os_str())
        .stdout(Stdio::piped())
        .stderr(command_config.output_setting())
        .spawn()?;

    let cat_output = cat_cmd
        .stdout
        .take()
        .ok_or_else(|| CommandError::StdIoCaptureError)?;
    let docker_load_result = Command::new("docker")
        .arg("load")
        .stdin(cat_output)
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
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
        .status()?;

    Ok(status)
}
