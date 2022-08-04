use serde::{Deserialize, Serialize};

use super::docker::command;
use std::io::Write;
use std::path::PathBuf;

const IN_CONTAINER_VOLUME_DIR: &str = "/output";
const EV_USER_IMAGE_NAME: &str = "ev-user-image";
const NITRO_CLI_IMAGE_NAME: &str = "nitro-cli-image";
pub const NITRO_CLI_IMAGE_FILENAME: &str = "nitro-cli-image.Dockerfile";
pub const ENCLAVE_FILENAME: &str = "enclave.eif";

pub fn build_user_image(
    user_dockerfile_path: &std::path::Path,
    user_context_path: &str,
    verbose: bool,
) -> Result<(), String> {
    let build_image_status = command::build_image(
        user_dockerfile_path,
        EV_USER_IMAGE_NAME,
        vec![user_context_path.as_ref()],
        verbose,
    )
    .expect("Failed to execute docker command");

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

fn get_cert_dest(output_dir: &std::path::Path) -> PathBuf {
    output_dir.join("cert.pem")
}

fn get_key_dest(output_dir: &std::path::Path) -> PathBuf {
    output_dir.join("key.pem")
}

fn get_signing_info_path(output_dir: &std::path::Path) -> PathBuf {
    output_dir.join("ev_sign")
}

fn move_signing_info_into_scope(
    signing_info: &EnclaveSigningInfo,
    output_dir: &std::path::Path,
) -> Result<CleanUpMode, String> {
    let mut required_clean_up = CleanUpMode::None;
    // This directory has to exist — docker has no support for conditional COPYs.
    // If signing credentials are not given, this will be an empty directory
    let signing_info_path = get_signing_info_path(output_dir);
    if !signing_info_path.exists() {
        if let Err(e) = std::fs::create_dir(signing_info_path.as_path()) {
            return Err(format!(
                "Failed to create directory for signing cert — {}",
                e
            ));
        } else {
            required_clean_up.enable_directory();
        }
    }

    let cert_dest = get_cert_dest(&signing_info_path);
    if cert_dest != signing_info.cert() {
        if let Err(e) = std::fs::copy(signing_info.cert(), cert_dest.as_path()) {
            return Err(format!(
                "An error occurred while attempting to give docker access to the signing cert — {:?}", e
            ));
        } else {
            required_clean_up.enable_cert();
        }
    }
    let key_dest = get_key_dest(&signing_info_path);
    if key_dest != signing_info.key() {
        if let Err(e) = std::fs::copy(signing_info.key(), key_dest.as_path()) {
            return Err(format!(
                "An error occurred while attempting to give docker access to the signing key — {:?}", e
            ));
        } else {
            required_clean_up.enable_key();
        }
    }

    Ok(required_clean_up)
}

pub fn build_nitro_cli_image(
    output_dir: &std::path::PathBuf,
    signing_info: Option<&EnclaveSigningInfo>,
    verbose: bool,
) -> Result<(), String> {
    let mut nitro_cli_dockerfile_contents = include_bytes!("nitro-cli-image.Dockerfile").to_vec();

    if signing_info.is_some() {
        if let Err(e) = writeln!(&mut nitro_cli_dockerfile_contents, "\nCOPY ./ev_sign /sign") {
            return Err(format!(
                "Failed to write signing directives to dockerfile — {}",
                e
            ));
        }
    }

    let nitro_cli_dockerfile_path = output_dir.join(NITRO_CLI_IMAGE_FILENAME);
    std::fs::write(&nitro_cli_dockerfile_path, nitro_cli_dockerfile_contents).unwrap();

    let required_clean_up = if let Some(signing_info) = signing_info {
        move_signing_info_into_scope(signing_info, &output_dir)?
    } else {
        CleanUpMode::None
    };

    let build_image_status = command::build_image(
        nitro_cli_dockerfile_path.as_path(),
        NITRO_CLI_IMAGE_NAME,
        vec![output_dir.as_ref()],
        verbose,
    )
    .expect("Failed to run docker command for building Nitro CLI image.");

    let build_result = if build_image_status.success() {
        Ok(())
    } else {
        Err("Failed to build Nitro CLI image.".to_string())
    };

    // clean up copied cert and key path
    let remove_contents =
        |cert_dest: &std::path::Path, key_dest: &std::path::Path| -> Result<(), std::io::Error> {
            let _ = std::fs::remove_file(cert_dest);
            std::fs::remove_file(key_dest)
        };

    let signing_info_path = get_signing_info_path(output_dir);
    let _ = match required_clean_up {
        CleanUpMode::Directory => {
            let _ = remove_contents(
                &get_cert_dest(&signing_info_path),
                &get_key_dest(&signing_info_path),
            );
            std::fs::remove_dir(signing_info_path)
        }
        CleanUpMode::AllContents => remove_contents(
            &get_cert_dest(&signing_info_path),
            &get_key_dest(&signing_info_path),
        ),
        CleanUpMode::Cert => std::fs::remove_file(&get_cert_dest(&signing_info_path)),
        CleanUpMode::Key => std::fs::remove_file(&get_key_dest(&signing_info_path)),
        CleanUpMode::None => return build_result,
    };

    build_result
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EIFMeasurements {
    #[serde(rename = "HashAlgorithm")]
    hash_algorithm: String,
    #[serde(flatten)] // serialize as though these are attribtues on this struct
    pcrs: PCRs,
}

impl EIFMeasurements {
    pub fn pcrs(&self) -> &PCRs {
        &self.pcrs
    }
}

// Isolated PCRs from remainder of the measures to use in API requests
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PCRs {
    #[serde(rename = "PCR0")]
    pcr0: String,
    #[serde(rename = "PCR1")]
    pcr1: String,
    #[serde(rename = "PCR2")]
    pcr2: String,
    #[serde(rename = "PCR8")]
    pcr8: Option<String>,
}

// Struct for deserializing the output from the nitro cli
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
    output_dir: &std::path::Path,
    verbose: bool,
) -> Result<BuiltEnclave, String> {
    let mounted_volume = format!("{}:{}", output_dir.display(), IN_CONTAINER_VOLUME_DIR);
    let output_location = format!("{}/{}", IN_CONTAINER_VOLUME_DIR, ENCLAVE_FILENAME);
    let nitro_run_args = vec![
        "build-enclave".as_ref(),
        "--output-file".as_ref(),
        output_location.as_str().as_ref(),
        "--docker-uri".as_ref(),
        EV_USER_IMAGE_NAME.as_ref(),
        "--signing-certificate".as_ref(),
        "/sign/cert.pem".as_ref(),
        "--private-key".as_ref(),
        "/sign/key.pem".as_ref(),
    ];

    let run_conversion_status = command::run_image(
        NITRO_CLI_IMAGE_NAME,
        vec![
            "/var/run/docker.sock:/var/run/docker.sock",
            mounted_volume.as_str(),
        ],
        nitro_run_args,
        verbose,
    )
    .expect("Failed to run Nitro CLI image");

    if run_conversion_status.status.success() {
        let build_output: EnclaveBuildOutput =
            serde_json::from_slice(run_conversion_status.stdout.as_slice()).unwrap();
        Ok(BuiltEnclave {
            measurements: build_output.measurements,
            location: output_dir.to_path_buf(),
        })
    } else {
        Err("Failed to create Nitro CLI image.".to_string())
    }
}

pub fn describe_eif(eif_path: &std::path::Path) -> Result<EnclaveBuildOutput, String> {
    let eif_directory = eif_path.parent().unwrap();
    let eif_filename = eif_path.file_name().unwrap().to_string_lossy();
    let mounted_volume = format!("{}:{}", eif_directory.display(), IN_CONTAINER_VOLUME_DIR);
    let output_location = format!("{}/{}", IN_CONTAINER_VOLUME_DIR, eif_filename);
    let nitro_describe_args = vec![
        "describe-eif".as_ref(),
        "--eif-path".as_ref(),
        output_location.as_str().as_ref(),
    ];

    let run_conversion_status = command::run_image(
        NITRO_CLI_IMAGE_NAME,
        vec![
            "/var/run/docker.sock:/var/run/docker.sock",
            mounted_volume.as_str(),
        ],
        nitro_describe_args,
        false,
    )
    .expect("Failed to run Nitro CLI image");

    if run_conversion_status.status.success() {
        let output = run_conversion_status.stdout.as_slice();
        println!("{}", std::str::from_utf8(output).unwrap());
        let build_output: EnclaveBuildOutput =
            serde_json::from_slice(run_conversion_status.stdout.as_slice()).unwrap();
        Ok(build_output)
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
