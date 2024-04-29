use crate::build::build_enclave_image_file;
use crate::common::{prepare_build_args, CliError};
use crate::config::{read_and_validate_config, BuildTimeConfig};
use crate::docker::command::get_source_date_epoch;
use crate::version::check_version;
use crate::version::get_runtime_and_installer_version;
use clap::Parser;

/// Build an Enclave from a Dockerfile
#[derive(Parser, Debug)]
#[command(name = "build", about)]
pub struct BuildArgs {
    /// Path to enclave.toml config file. This can be generated using the init command
    #[arg(short = 'c', long = "config", default_value = "./enclave.toml")]
    pub config: String,

    /// Path to Dockerfile for Enclave. Will override any dockerfile specified in the .toml file.
    #[arg(short = 'f', long = "file")]
    pub dockerfile: Option<String>,

    /// Path to use for Docker context. Defaults to the current directory.
    #[arg(default_value = ".")]
    pub context_path: String,

    /// Certificate used to sign the Enclave image file
    #[arg(long = "signing-cert")]
    pub certificate: Option<String>,

    /// Private key used to sign the Enclave image file
    #[arg(long = "private-key")]
    pub private_key: Option<String>,

    /// Disable verbose logging
    #[arg(long)]
    pub quiet: bool,

    // TODO(Mark): check
    /// Enable JSON output
    // #[arg(long, from_global)]
    // pub json: bool,

    /// Path to directory where the processed dockerfile and Enclave will be saved
    #[arg(short = 'o', long = "output", default_value = ".")]
    pub output_dir: String,

    /// Build time arguments to provide to docker
    #[arg(long = "build-arg")]
    pub docker_build_args: Vec<String>,

    /// Path to an Enclave dockerfile to build from existing
    #[arg(long = "from-existing")]
    pub from_existing: Option<String>,

    /// Deterministic builds
    #[arg(long = "reproducible")]
    pub reproducible: bool,

    /// Enables forwarding proxy protocol when TLS Termination is disabled
    #[arg(long = "forward-proxy-protocol")]
    pub forward_proxy_protocol: bool,

    /// Disables the use of cache during the image builds
    #[arg(long = "no-cache")]
    pub no_cache: bool,
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
    if let Err(e) = check_version().await {
        log::error!("{e}");
        return exitcode::SOFTWARE;
    };

    let (mut enclave_config, validated_config) =
        match read_and_validate_config(&build_args.config, &build_args) {
            Ok(config) => config,
            Err(e) => {
                log::error!("Failed to read Enclave config from file system — {e}");
                return e.exitcode();
            }
        };

    let formatted_args = prepare_build_args(&build_args.docker_build_args);
    let borrowed_args = formatted_args
        .as_ref()
        .map(|args| args.iter().map(AsRef::as_ref).collect());

    let (data_plane_version, installer_version) =
        match get_runtime_and_installer_version(build_args.from_existing.clone()).await {
            Ok(versions) => versions,
            Err(e) => {
                log::error!(
                    "Failed to retrieve the latest data plane and installer versions - {e:?}"
                );
                return e.exitcode();
            }
        };

    let timestamp = get_source_date_epoch();

    let from_existing = build_args.from_existing;
    let built_enclave = match build_enclave_image_file(
        &validated_config,
        &build_args.context_path,
        Some(&build_args.output_dir),
        !build_args.quiet,
        borrowed_args,
        data_plane_version,
        installer_version,
        timestamp,
        from_existing,
        build_args.reproducible,
        build_args.no_cache,
    )
    .await
    {
        Ok((built_enclave, _)) => built_enclave,
        Err(e) => {
            log::error!("An error occurred while building your Enclave — {e}");
            return e.exitcode();
        }
    };

    enclave_config.set_attestation(built_enclave.measurements());
    crate::common::save_enclave_config(&enclave_config, &build_args.config);

    if enclave_config.debug {
        crate::common::log_debug_mode_attestation_warning();
    }

    // Write Enclave measures to stdout
    let success_msg = serde_json::json!({
        "status": "success",
        "message": "EIF built successfully",
        "enclaveMeasurements": built_enclave.measurements()
    });

    println!("{}", serde_json::to_string_pretty(&success_msg).unwrap());
    exitcode::OK
}
