use crate::{common, docker::command};
use std::io::Write;
use std::path::PathBuf;

pub mod error;
use error::EnclaveError;

mod types;
use types::CleanUpMode;
pub use types::{
    BuiltEnclave, DescribeEif, EIFMeasurements, EnclaveBuildOutput, EnclaveMetadata,
    EnclaveSigningCertificate, EnclaveSigningCertificateIssuer, PCRs,
};

const IN_CONTAINER_VOLUME_DIR: &str = "/output";
const EV_USER_IMAGE_NAME: &str = "ev-user-image";
const NITRO_CLI_BUILDER_IMAGE_NAME: &str = "nitro-cli-builder-image";
const NITRO_CLI_GENERIC_IMAGE_NAME: &str = "nitro-cli-generic-image";
pub const NITRO_CLI_IMAGE_FILENAME: &str = "nitro-cli-image.Dockerfile";
pub const ENCLAVE_FILENAME: &str = "enclave.eif";

pub fn build_user_image(
    user_dockerfile_path: &std::path::Path,
    user_context_path: &std::path::Path,
    verbose: bool,
    docker_build_args: Option<Vec<&str>>,
) -> Result<(), EnclaveError> {
    let mut command_line_args = vec![user_context_path.as_os_str()];

    if let Some(build_args) = docker_build_args.as_ref() {
        let mut docker_build_args = build_args.iter().map(AsRef::as_ref).collect();
        command_line_args.append(&mut docker_build_args);
    }

    let tag_name = format!("{EV_USER_IMAGE_NAME}:latest");
    let build_output = command::build_image(
        user_dockerfile_path,
        tag_name.as_str(),
        command_line_args,
        verbose,
    )?;

    if !build_output.success() {
        return Err(EnclaveError::new_build_error(build_output.code().unwrap()));
    }

    Ok(())
}

pub fn build_reproducible_user_image(
    user_context_path: &std::path::Path,
    output_path: &std::path::Path,
    verbose: bool,
) -> Result<(), EnclaveError> {
    let abs_context_path = std::env::current_dir()?
        .join(user_context_path)
        .canonicalize()?;

    let tar_output_dir = common::resolve_output_path(None::<&str>).map_err(|e| {
        let enclave_err = EnclaveError::new_fs_error();
        enclave_err.context(e.to_string())
    })?;

    let tag_name = format!("{EV_USER_IMAGE_NAME}:reproducible");
    let build_output = command::build_image_using_kaniko(
        output_path,
        tar_output_dir.path().as_path(),
        abs_context_path.as_path(),
        tag_name.as_str(),
        verbose,
    )?;

    if !build_output.success() {
        log::debug!(
            "Reproducible build failed with code: {:?}",
            build_output.code()
        );
        return Err(EnclaveError::new_build_error(build_output.code().unwrap()));
    }

    // Kaniko outputs an image archive directly, but we need to load it into local docker to use the nitro cli
    let image_archive = tar_output_dir.path().join("image.tar");
    let load_output = command::load_image_into_local_docker_registry(&image_archive, verbose)?;
    if load_output.success() {
        return Ok(());
    } else {
        log::debug!(
            "Failed to load image into local docker registry: {:?}",
            load_output.code()
        );
        return Err(EnclaveError::new_build_error(load_output.code().unwrap()));
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

use crate::add_context_and_exit;
fn move_signing_info_into_scope(
    signing_info: &EnclaveSigningInfo,
    output_dir: &std::path::Path,
) -> Result<CleanUpMode, EnclaveError> {
    let mut required_clean_up = CleanUpMode::None;
    // This directory has to exist — docker has no support for conditional COPYs.
    // If signing credentials are not given, this will be an empty directory
    let signing_info_path = get_signing_info_path(output_dir);
    if !signing_info_path.exists() {
        add_context_and_exit!(
            std::fs::create_dir(signing_info_path.as_path()),
            "Failed to create directory for signing info"
        );
        required_clean_up.enable_directory();
    }

    let cert_dest = get_cert_dest(&signing_info_path);
    if cert_dest != signing_info.cert() {
        add_context_and_exit!(
            std::fs::copy(signing_info.cert(), cert_dest.as_path()),
            "Failed to copy cert into temporary directory"
        );
        required_clean_up.enable_cert();
    }
    let key_dest = get_key_dest(&signing_info_path);
    if key_dest != signing_info.key() {
        add_context_and_exit!(
            std::fs::copy(signing_info.key(), key_dest.as_path()),
            "Failed to copy key into temporary directory"
        );
        required_clean_up.enable_key();
    }

    Ok(required_clean_up)
}

pub fn build_nitro_cli_image(
    output_dir: &std::path::PathBuf,
    signing_info: Option<&EnclaveSigningInfo>,
    verbose: bool,
) -> Result<(), EnclaveError> {
    let mut nitro_cli_dockerfile_contents = include_bytes!("nitro-cli-image.Dockerfile").to_vec();

    if signing_info.is_some() {
        add_context_and_exit!(
            writeln!(&mut nitro_cli_dockerfile_contents, "\nCOPY ./ev_sign /sign"),
            "Failed to write signing directives to dockerfile"
        );
    }

    let nitro_cli_dockerfile_path = output_dir.join(NITRO_CLI_IMAGE_FILENAME);
    add_context_and_exit!(
        std::fs::write(&nitro_cli_dockerfile_path, nitro_cli_dockerfile_contents),
        "Failed to create nitro cli Dockerfile"
    );

    let required_clean_up = if let Some(signing_info) = signing_info {
        move_signing_info_into_scope(signing_info, output_dir)?
    } else {
        CleanUpMode::None
    };

    let build_image_result = command::build_image(
        nitro_cli_dockerfile_path.as_path(),
        if signing_info.is_some() {
            NITRO_CLI_BUILDER_IMAGE_NAME
        } else {
            NITRO_CLI_GENERIC_IMAGE_NAME
        },
        vec![output_dir.as_ref()],
        verbose,
    );

    let build_image_status =
        add_context_and_exit!(build_image_result, "Failed to build Nitro CLI docker image");

    // clean up copied cert and key path
    let remove_contents =
        |cert_dest: &std::path::Path, key_dest: &std::path::Path| -> Result<(), std::io::Error> {
            let _ = std::fs::remove_file(cert_dest);
            std::fs::remove_file(key_dest)
        };

    let signing_info_path = get_signing_info_path(output_dir);
    match required_clean_up {
        CleanUpMode::Directory => {
            let _ = remove_contents(
                &get_cert_dest(&signing_info_path),
                &get_key_dest(&signing_info_path),
            );
            let _ = std::fs::remove_dir(signing_info_path);
        }
        CleanUpMode::AllContents => {
            let _ = remove_contents(
                &get_cert_dest(&signing_info_path),
                &get_key_dest(&signing_info_path),
            );
        }
        CleanUpMode::Cert => {
            let _ = std::fs::remove_file(get_cert_dest(&signing_info_path));
        }
        CleanUpMode::Key => {
            let _ = std::fs::remove_file(get_key_dest(&signing_info_path));
        }
        _ => {}
    };

    if build_image_status.success() {
        Ok(())
    } else {
        Err(EnclaveError::new_build_error(
            build_image_status.code().unwrap_or(exitcode::SOFTWARE),
        ))
    }
}

pub fn run_conversion_to_enclave(
    output_dir: &std::path::Path,
    verbose: bool,
    reproducible: bool,
) -> Result<BuiltEnclave, EnclaveError> {
    let mounted_volume = format!("{}:{}", output_dir.display(), IN_CONTAINER_VOLUME_DIR);
    let output_location = format!("{}/{}", IN_CONTAINER_VOLUME_DIR, ENCLAVE_FILENAME);
    let docker_uri = format!(
        "{EV_USER_IMAGE_NAME}:{}",
        if reproducible {
            "reproducible"
        } else {
            "latest"
        }
    );
    let nitro_run_args = vec![
        "build-enclave".as_ref(),
        "--output-file".as_ref(),
        output_location.as_str().as_ref(),
        "--docker-uri".as_ref(),
        docker_uri.as_str().as_ref(),
        "--signing-certificate".as_ref(),
        "/sign/cert.pem".as_ref(),
        "--private-key".as_ref(),
        "/sign/key.pem".as_ref(),
    ];

    let run_conversion_result = command::run_image(
        NITRO_CLI_BUILDER_IMAGE_NAME,
        vec![
            "/var/run/docker.sock:/var/run/docker.sock",
            mounted_volume.as_str(),
        ],
        nitro_run_args,
        verbose,
    );

    let run_conversion_status = add_context_and_exit!(
        run_conversion_result,
        "Failed to convert Docker image into Enclave compatible EIF"
    );

    if run_conversion_status.status.success() {
        let build_output: EnclaveBuildOutput = add_context_and_exit!(
            serde_json::from_slice(run_conversion_status.stdout.as_slice()),
            "Failed to parse EIF build output"
        );
        Ok(BuiltEnclave::new(
            build_output.measurements().to_owned(),
            output_dir.to_path_buf(),
        ))
    } else {
        Err(
          EnclaveError::new_build_error(run_conversion_status.status.code().unwrap())
          .context("Nitro CLI container exited with a non-zero code while attempting to convert the image to an EIF.")
        )
    }
}

pub fn describe_eif(
    eif_path: &std::path::Path,
    verbose: bool,
) -> Result<DescribeEif, EnclaveError> {
    if !eif_path.is_file() {
        return Err(
            EnclaveError::new_fs_error().context("Invalid path given for EIF. Expected a file.")
        );
    }
    let eif_directory = eif_path.parent().ok_or_else(|| {
        EnclaveError::new_fs_error().context("Failed to identify the EIF's parent directory.")
    })?;
    let eif_filename = eif_path
        .file_name()
        .ok_or_else(|| EnclaveError::new_fs_error().context("Invalid file path given."))?
        .to_string_lossy();
    let mounted_volume = format!("{}:{}", eif_directory.display(), IN_CONTAINER_VOLUME_DIR);
    let output_location = format!("{}/{}", IN_CONTAINER_VOLUME_DIR, eif_filename);
    let nitro_describe_args = vec![
        "describe-eif".as_ref(),
        "--eif-path".as_ref(),
        output_location.as_str().as_ref(),
    ];

    let run_conversion_result = command::run_image(
        NITRO_CLI_GENERIC_IMAGE_NAME,
        vec![
            "/var/run/docker.sock:/var/run/docker.sock",
            mounted_volume.as_str(),
        ],
        nitro_describe_args,
        verbose,
    );

    let run_conversion_status = add_context_and_exit!(
        run_conversion_result,
        "Failed to describe EIF using Nitro CLI."
    );

    if run_conversion_status.status.success() {
        let build_output: DescribeEif = add_context_and_exit!(
            serde_json::from_slice(run_conversion_status.stdout.as_slice()),
            "Failed to parse output from the Nitro CLI describe command"
        );
        Ok(build_output)
    } else {
        Err(
          EnclaveError::new_build_error(run_conversion_status.status.code().unwrap())
          .context("Nitro CLI container exited with a non-zero code while attempting to describe the given EIF.")
        )
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
