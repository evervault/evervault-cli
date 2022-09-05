use crate::build::build_enclave_image_file;
use crate::common::CliError;
use crate::config::{CageConfig, ValidatedCageBuildConfig};
use clap::Parser;

/// Build a Cage from a Dockerfile
#[derive(Parser, Debug)]
#[clap(name = "build", about)]
pub struct BuildArgs {
    /// Path to cage.toml config file. This can be generated using the init command
    #[clap(short = 'c', long = "config", default_value = "./cage.toml")]
    pub config: String,

    /// Path to Dockerfile for Cage. Will override any dockerfile specified in the .toml file.
    #[clap(short = 'f', long = "file", default_value = "./Dockerfile")]
    pub dockerfile: String,

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
    #[clap(short = 'o', long = "output")]
    pub output_dir: Option<String>,

    /// Write latest attestation information to cage.toml config file
    #[clap(short = 'w', long = "write")]
    pub write: bool,
}

pub async fn run(build_args: BuildArgs) -> exitcode::ExitCode {
    let mut cage_config = match CageConfig::try_from_filepath(&build_args.config) {
        Ok(cage_config) => cage_config,
        Err(e) => {
            log::error!("An error occurred while reading the Cage config — {:?}", e);
            return e.exitcode();
        }
    };

    merge_config_with_args(&build_args, &mut cage_config);

    let validated_config: ValidatedCageBuildConfig = match cage_config.clone().try_into() {
        Ok(config) => config,
        Err(e) => {
            log::error!("{}", e);
            return e.exitcode();
        }
    };

    let built_enclave = match build_enclave_image_file(
        &validated_config,
        &build_args.context_path,
        build_args.output_dir.as_deref(),
        !build_args.quiet,
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

fn merge_config_with_args(args: &BuildArgs, config: &mut CageConfig) {
    if config.dockerfile().is_none() {
        config.set_dockerfile(args.dockerfile.clone());
    }

    if args.certificate.is_some() && config.cert().is_none() {
        config.set_cert(args.certificate.clone().unwrap());
    }

    if args.private_key.is_some() && config.key().is_none() {
        config.set_key(args.private_key.clone().unwrap());
    }
}
