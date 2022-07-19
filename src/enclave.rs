use serde::{Deserialize, Serialize};
use std::ffi::OsStr;
use std::path::PathBuf;
use std::process::{Command, Stdio};

const IN_CONTAINER_VOLUME_DIR: &str = "/output";
const EV_USER_IMAGE_NAME: &str = "ev-user-image";
const NITRO_CLI_IMAGE_NAME: &str = "nitro-cli-image";
pub const NITRO_CLI_IMAGE_FILENAME: &str = "nitro-cli-image.Dockerfile";
pub const ENCLAVE_FILENAME: &str = "enclave.eif";

pub struct CommandConfig {
    verbose: bool,
    architecture: &'static str,
}

impl CommandConfig {
    pub fn new(verbose: bool) -> Self {
        Self {
            verbose,
            architecture: std::env::consts::ARCH,
        }
    }

    pub fn extra_build_args(&self) -> Vec<&OsStr> {
        match self.architecture {
            "aarch64" | "arm" => vec!["--platform".as_ref(), "linux/amd64".as_ref()],
            _ => vec![],
        }
    }

    pub fn output_setting(&self) -> Stdio {
        if self.verbose {
            Stdio::inherit()
        } else {
            Stdio::null()
        }
    }
}

pub fn build_user_image(
    user_dockerfile_path: &std::path::PathBuf,
    user_context_path: &str,
    command_config: &CommandConfig,
) -> Result<(), String> {
    let build_image_args: Vec<&OsStr> = [
        vec![
            "build".as_ref(),
            "-f".as_ref(),
            user_dockerfile_path.as_os_str(),
            "-t".as_ref(),
            EV_USER_IMAGE_NAME.as_ref(),
        ],
        command_config.extra_build_args(),
        vec![user_context_path.as_ref()],
    ]
    .concat();

    let build_image_status = Command::new("docker")
        .args(build_image_args)
        .stdout(command_config.output_setting())
        .stderr(command_config.output_setting())
        .status()
        .expect("Failed to run docker command.");

    if build_image_status.success() {
        Ok(())
    } else {
        Err("Failed to build user image.".to_string())
    }
}

pub fn build_nitro_cli_image(
    command_config: &CommandConfig,
    output_dir: &std::path::PathBuf,
) -> Result<(), String> {
    let nitro_cli_dockerfile_contents = include_bytes!("nitro-cli-image.Dockerfile");
    let nitro_cli_dockerfile_path = output_dir.join(NITRO_CLI_IMAGE_FILENAME);
    std::fs::write(&nitro_cli_dockerfile_path, nitro_cli_dockerfile_contents).unwrap();

    let build_nitro_cli_image_args: Vec<&OsStr> = [
        vec![
            "build".as_ref(),
            "-f".as_ref(),
            nitro_cli_dockerfile_path.as_ref(),
            "-t".as_ref(),
            NITRO_CLI_IMAGE_NAME.as_ref(),
        ],
        command_config.extra_build_args(),
        vec![output_dir.as_ref()],
    ]
    .concat();

    let build_image_status = Command::new("docker")
        .args(build_nitro_cli_image_args)
        .stdout(command_config.output_setting())
        .stderr(command_config.output_setting())
        .status()
        .expect("Failed to run docker command for building Nitro CLI image.");

    if build_image_status.success() {
        Ok(())
    } else {
        Err("Failed to build Nitro CLI image.".to_string())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EIFMeasurements {
    #[serde(rename = "HashAlgorithm")]
    hash_algorithm: String,
    #[serde(rename = "PCR0")]
    pcr0: String,
    #[serde(rename = "PCR1")]
    pcr1: String,
    #[serde(rename = "PCR2")]
    pcr2: String,
    #[serde(rename = "PCR8")]
    pcr8: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct EnclaveBuildOutput {
    measurements: EIFMeasurements,
}

#[derive(Debug)]
pub struct BuiltEnclave {
    measurements: EIFMeasurements,
    location: PathBuf,
}

impl BuiltEnclave {
    pub fn measurements(&self) -> &EIFMeasurements {
        &self.measurements
    }

    pub fn location(&self) -> &PathBuf {
        &self.location
    }
}

pub fn run_conversion_to_enclave(
    command_config: &CommandConfig,
    output_dir: &PathBuf,
) -> Result<BuiltEnclave, String> {
    let mounted_volume = format!("{}:{}", output_dir.display(), IN_CONTAINER_VOLUME_DIR);
    let output_location = format!("{}/{}", IN_CONTAINER_VOLUME_DIR, ENCLAVE_FILENAME);
    let run_conversion_status = Command::new("docker")
        .args(vec![
            "run",
            "--rm",
            "-v",
            "/var/run/docker.sock:/var/run/docker.sock",
            "-v",
            mounted_volume.as_str(),
            NITRO_CLI_IMAGE_NAME,
            "--output-file",
            output_location.as_str(),
            "--docker-uri",
            EV_USER_IMAGE_NAME,
        ])
        .stdout(Stdio::piped()) // Write stdout to a buffer so we can parse the EIF meaasures
        .stderr(command_config.output_setting())
        .output()
        .expect("Failed to run Nitro CLI image");

    if run_conversion_status.status.success() {
        let build_output: EnclaveBuildOutput =
            serde_json::from_slice(run_conversion_status.stdout.as_slice()).unwrap();
        Ok(BuiltEnclave {
            measurements: build_output.measurements,
            location: output_dir.clone(),
        })
    } else {
        Err("Failed to Nitro CLI image.".to_string())
    }
}
