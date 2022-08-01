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
    user_dockerfile_path: &std::path::Path,
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

// Tracking which FS elements have been created during signing
#[derive(Debug, PartialEq)]
enum CleanUpMode {
    Directory,
    AllContents,
    Cert,
    Key,
    None,
}

impl CleanUpMode {
    fn enable_directory(&mut self) {
        *self = Self::Directory;
    }

    fn enable_cert(&mut self) {
        if !self.is_directory() {
            if self.is_key() {
                *self = Self::AllContents;
            } else {
                *self = Self::Cert;
            }
        }
    }

    fn enable_key(&mut self) {
        if !self.is_directory() {
            if self.is_cert() {
                *self = Self::AllContents;
            } else {
                *self = Self::Key;
            }
        }
    }

    fn is_directory(&self) -> bool {
        matches!(self, Self::Directory)
    }

    fn is_key(&self) -> bool {
        matches!(self, Self::Key)
    }

    fn is_cert(&self) -> bool {
        matches!(self, Self::Cert)
    }
}

pub fn build_nitro_cli_image(
    command_config: &CommandConfig,
    output_dir: &std::path::PathBuf,
    signing_info: &EnclaveSigningInfo,
) -> Result<(), String> {
    let nitro_cli_dockerfile_contents = include_bytes!("nitro-cli-image.Dockerfile");
    let nitro_cli_dockerfile_path = output_dir.join(NITRO_CLI_IMAGE_FILENAME);
    std::fs::write(&nitro_cli_dockerfile_path, nitro_cli_dockerfile_contents).unwrap();

    let mut required_clean_up = CleanUpMode::None;
    // This directory has to exist — docker has no support for conditional COPYs.
    // If signing credentials are not given, this will be an empty directory
    let signing_info_path = output_dir.join("ev_sign");
    if !signing_info_path.exists() {
        if let Err(e) = std::fs::create_dir(signing_info_path.as_path()) {
            return Err(format!(
                "Failed to create directory for signing cert — {:?}",
                e
            ));
        } else {
            required_clean_up.enable_directory();
        }
    }

    let cert_dest = output_dir.join("ev_sign/cert.pem");
    if cert_dest != signing_info.cert() {
        if let Err(e) = std::fs::copy(signing_info.cert(), cert_dest.as_path()) {
            return Err(format!(
                "An error occurred while attempting to give docker access to the signing cert — {:?}", e
            ));
        } else {
            required_clean_up.enable_cert();
        }
    }
    let key_dest = output_dir.join("ev_sign/key.pem");
    // TODO: use more distinct path name to avoid conflicts
    if key_dest != signing_info.key() {
        if let Err(e) = std::fs::copy(signing_info.key(), key_dest.as_path()) {
            return Err(format!(
                "An error occurred while attempting to give docker access to the signing key — {:?}", e
            ));
        } else {
            required_clean_up.enable_key();
        }
    }

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

    let build_result = if build_image_status.success() {
        Ok(())
    } else {
        Err("Failed to build Nitro CLI image.".to_string())
    };

    // clean up copied cert and key path
    let _ = match required_clean_up {
        CleanUpMode::Directory => std::fs::remove_dir(signing_info_path),
        CleanUpMode::AllContents => {
            let _ = std::fs::remove_file(cert_dest);
            std::fs::remove_file(key_dest)
        }
        CleanUpMode::Cert => std::fs::remove_file(cert_dest),
        CleanUpMode::Key => std::fs::remove_file(key_dest),
        CleanUpMode::None => return build_result,
    };

    build_result
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

    pub fn location(&self) -> &std::path::Path {
        &self.location
    }
}

pub fn run_conversion_to_enclave(
    command_config: &CommandConfig,
    output_dir: &std::path::Path,
) -> Result<BuiltEnclave, String> {
    let mounted_volume = format!("{}:{}", output_dir.display(), IN_CONTAINER_VOLUME_DIR);
    let output_location = format!("{}/{}", IN_CONTAINER_VOLUME_DIR, ENCLAVE_FILENAME);

    let nitro_build_args = vec![
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
        "--signing-certificate",
        "/sign/cert.pem",
        "--private-key",
        "/sign/key.pem",
    ];

    let run_conversion_status = Command::new("docker")
        .args(nitro_build_args)
        .stdout(Stdio::piped()) // Write stdout to a buffer so we can parse the EIF meaasures
        .stderr(command_config.output_setting())
        .output()
        .expect("Failed to run Nitro CLI image");

    if run_conversion_status.status.success() {
        let build_output: EnclaveBuildOutput =
            serde_json::from_slice(run_conversion_status.stdout.as_slice()).unwrap();
        Ok(BuiltEnclave {
            measurements: build_output.measurements,
            location: output_dir.to_path_buf(),
        })
    } else {
        Err("Failed to Nitro CLI image.".to_string())
    }
}

pub struct EnclaveSigningInfo {
    cert: PathBuf,
    key: PathBuf,
}

impl EnclaveSigningInfo {
    pub fn new(cert_path: PathBuf, key_path: PathBuf) -> Self {
        Self {
            cert: cert_path,
            key: key_path,
        }
    }

    pub fn cert(&self) -> &std::path::Path {
        self.cert.as_path()
    }

    pub fn key(&self) -> &std::path::Path {
        self.key.as_path()
    }
}
