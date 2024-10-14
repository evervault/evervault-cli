use super::error::CommandError;
use git2::Repository;
use std::ffi::OsStr;
use std::path::Path;
use std::process::{Command, ExitStatus, Output, Stdio};

pub struct CommandConfig {
    verbose: bool,
    no_cache: bool,
}

impl CommandConfig {
    pub fn new(verbose: bool, no_cache: bool) -> Self {
        Self { verbose, no_cache }
    }

    pub fn extra_build_args(&self) -> Vec<&OsStr> {
        let mut args = vec!["--platform".as_ref(), "linux/amd64".as_ref()];
        if self.no_cache {
            args.push("--no-cache".as_ref());
        }
        args
    }

    pub fn output_setting(&self) -> Stdio {
        if self.verbose {
            Stdio::inherit()
        } else {
            Stdio::null()
        }
    }
}

pub fn load_image_into_local_docker_registry(
    image_archive: &Path,
    verbose: bool,
) -> Result<ExitStatus, CommandError> {
    let command_config = CommandConfig::new(verbose, false);
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

fn docker_buildkit_enabled() -> Result<bool, CommandError> {
    use regex::Regex;
    use version_compare::Version;
    let args: Vec<&OsStr> = vec!["buildx".as_ref(), "version".as_ref()];
    let output = Command::new("docker").args(args).output()?;

    // If output returns an error code, assume that buildkit isn't available.
    if !output.status.success() {
        return Ok(false);
    }

    let version_output = String::from_utf8_lossy(&output.stdout).to_ascii_lowercase();
    let semver_regex = Regex::new(r"\d+\.\d+\.\d+")?;
    // If we can't find a valid semver string in the buildkit version output, assume it isn't available
    let Some(buildkit_version) = semver_regex.find(&version_output) else {
        return Ok(false);
    };

    let semver_match = buildkit_version.as_str();
    let min_version = Version::from("0.10.0").ok_or(CommandError::SemverParseError)?;
    let user_version = Version::from(semver_match).ok_or(CommandError::SemverParseError)?;
    Ok(user_version >= min_version)
}

pub fn get_git_hash() -> String {
    match try_get_git_hash() {
        Ok(info) => info,
        Err(_) => "no git info available".to_string(),
    }
}

pub fn try_get_git_hash() -> Result<String, CommandError> {
    let repo: Repository = Repository::open(".")?;
    let head = repo.head()?;
    let commit = head.peel_to_commit()?;
    Ok(commit.id().to_string())
}

pub fn get_source_date_epoch() -> String {
    match std::env::var("SOURCE_DATE_EPOCH") {
        Ok(epoch) => epoch,
        Err(_) => "0".to_string(),
    }
}

pub fn build_image(
    dockerfile_path: &std::path::Path,
    tag_name: &str,
    command_line_args: Vec<&OsStr>,
    verbose: bool,
    no_cache: bool,
) -> Result<ExitStatus, CommandError> {
    let command_config = CommandConfig::new(verbose, no_cache);
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

pub fn build_image_repro(
    dockerfile_path: &std::path::Path,
    tag_name: &str,
    command_line_args: Vec<&OsStr>,
    verbose: bool,
    timestamp: String,
    no_cache: bool,
) -> Result<ExitStatus, CommandError> {
    let command_config = CommandConfig::new(verbose, no_cache);
    let build_image_args = if docker_buildkit_enabled()? {
        log::info!("Docker version is reproducible build compatible");
        [
            vec![
                "buildx".as_ref(),
                "build".as_ref(),
                "-f".as_ref(),
                dockerfile_path.as_os_str(),
                "-t".as_ref(),
                tag_name.as_ref(),
                "--load".as_ref(),
            ],
            command_config.extra_build_args(),
            command_line_args,
        ]
        .concat()
    } else {
        log::warn!("Your docker version is too old for reproducible builds, attempting build without buildkit. Please upgrade docker for build reproducibility");
        [
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
        .concat()
    };

    let command_status = Command::new("docker")
        .env("SOURCE_DATE_EPOCH", timestamp)
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
    let command_config = CommandConfig::new(verbose, false);

    let mut run_image_args: Vec<&OsStr> = vec!["run".as_ref(), "--rm".as_ref()];

    for &volume in volumes.iter() {
        run_image_args.push("-v".as_ref());
        run_image_args.push(volume.as_ref());
    }

    run_image_args.push(image_name.as_ref());

    let run_args = [run_image_args, command_line_args].concat();

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
