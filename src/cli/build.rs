use crate::build::build_enclave_image_file;
use crate::common::{prepare_build_args, CliError};
use crate::config::{read_and_validate_config, BuildTimeConfig};
use clap::Parser;

/// Build a Cage from a Dockerfile
#[derive(Parser, Debug)]
#[clap(name = "build", about)]
pub struct BuildArgs {
    /// Path to cage.toml config file. This can be generated using the init command
    #[clap(short = 'c', long = "config", default_value = "./cage.toml")]
    pub config: String,

    /// Path to Dockerfile for Cage. Will override any dockerfile specified in the .toml file.
    #[clap(short = 'f', long = "file")]
    pub dockerfile: Option<String>,

    /// Path to use for Docker context. Defaults to the current directory.
    #[clap(default_value = ".")]
    pub context_path: String,

    /// Certificate used to sign the enclave image file
    #[clap(long = "signing-cert")]
    pub certificate: Option<String>,

    /// Private key used to sign the enclave image file
    #[clap(long = "private-key")]
    pub private_key: Option<String>,

    /// Disable verbose logging
    #[clap(long)]
    pub quiet: bool,

    /// Enable JSON output
    #[clap(long, from_global)]
    pub json: bool,

    /// Path to directory where the processed dockerfile and enclave will be saved
    #[clap(short = 'o', long = "output", default_value = ".")]
    pub output_dir: String,

    /// Write latest attestation information to cage.toml config file
    #[clap(short = 'w', long = "write")]
    pub write: bool,

    /// Build time argumentss to provide to docker
    #[clap(long = "build-arg")]
    pub docker_build_args: Vec<String>,
}

impl BuildTimeConfig for BuildArgs {
    fn certificate(&self) -> Option<&str> {
        self.certificate.as_deref()
    }

    fn dockerfile(&self) -> Option<&str> {
        self.dockerfile.as_deref()
    }

    fn private_key(&self) -> Option<&str> {
        self.private_key.as_deref()
    }
}

pub async fn run(build_args: BuildArgs) -> exitcode::ExitCode {
    let (mut cage_config, validated_config) =
        match read_and_validate_config(&build_args.config, &build_args) {
            Ok(config) => config,
            Err(e) => {
                log::error!("Failed to read cage config from file system — {}", e);
                return e.exitcode();
            }
        };

    let formatted_args = prepare_build_args(&build_args.docker_build_args);
    let borrowed_args = formatted_args
        .as_ref()
        .map(|args| args.iter().map(AsRef::as_ref).collect());

    let built_enclave = match build_enclave_image_file(
        &validated_config,
        &build_args.context_path,
        Some(&build_args.output_dir),
        !build_args.quiet,
        borrowed_args,
    )
    .await
    {
        Ok((built_enclave, _)) => built_enclave,
        Err(e) => {
            log::error!("An error occurred while building your enclave — {0:?}", e);
            return e.exitcode();
        }
    };

    if build_args.write {
        crate::common::update_cage_config_with_eif_measurements(
            &mut cage_config,
            &build_args.config,
            built_enclave.measurements(),
        );
    }

    if cage_config.debug {
        crate::common::log_debug_mode_attestation_warning();
    }

    // Write enclave measures to stdout
    let success_msg = serde_json::json!({
        "status": "success",
        "message": "EIF built successfully",
        "enclaveMeasurements": built_enclave.measurements()
    });

    println!("{}", serde_json::to_string_pretty(&success_msg).unwrap());
    exitcode::OK
}
