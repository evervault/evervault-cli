use clap::Parser;
use common::{api::AuthMode, CliError};
use ev_enclave::{
    api::enclave::{EnclaveApi, EnclaveClient},
    config::EnclaveConfig,
    config::{self, ScalingSettings},
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ScaleError {
    #[error("No Enclave Uuid given. You can provide one by using either the --enclave-uuid flag, or using the --config flag to point to an Enclave.toml")]
    MissingUuid,
    #[error("An error occurred parsing the Enclave config - {0}")]
    ConfigError(#[from] config::EnclaveConfigError),
    #[error("An error occurred contacting the API — {0}")]
    ApiError(#[from] common::api::client::ApiError),
}

impl CliError for ScaleError {
    fn exitcode(&self) -> exitcode::ExitCode {
        match self {
            Self::MissingUuid => exitcode::CONFIG,
            Self::ConfigError(inner) => inner.exitcode(),
            Self::ApiError(inner) => inner.exitcode(),
        }
    }
}

/// Update your Enclave's Scaling config
#[derive(Debug, Parser)]
#[command(name = "scale", about)]
pub struct ScaleArgs {
    /// Path to enclave.toml config file
    #[arg(short = 'c', long = "config", default_value = "./enclave.toml")]
    pub config: String,

    /// Uuid of the Enclave to scale
    #[arg(long = "enclave-uuid")]
    pub enclave_uuid: Option<String>,

    /// Number of replicas to run for this Enclave. If unset, the command will read the current scaling config from the Evervault API.
    #[arg(long = "desired-replicas")]
    pub desired_replicas: Option<u32>,

    /// Sync the local Enclave.toml with the latest scaling config for an Enclave if they differ.
    #[arg(long = "sync")]
    pub sync: bool,
}

pub async fn run(args: ScaleArgs, api_key: String) -> i32 {
    let enclave_api = EnclaveClient::new(AuthMode::ApiKey(api_key.to_string()));

    let enclave_config = EnclaveConfig::try_from_filepath(&args.config);
    let enclave_uuid = match args.enclave_uuid.as_deref() {
        Some(enclave_uuid) => Ok(enclave_uuid),
        None => match enclave_config.as_ref() {
            Ok(enclave_config) => enclave_config
                .uuid
                .as_deref()
                .ok_or(ScaleError::MissingUuid),
            Err(e) => {
                log::error!("Failed to resolve Enclave config - {e:?}");
                return e.exitcode();
            }
        },
    };

    let enclave_uuid = match enclave_uuid {
        Ok(enclave_uuid) => enclave_uuid,
        Err(e) => {
            log::error!("{e:?}");
            return e.exitcode();
        }
    };

    let scaling_config_result = match args.desired_replicas {
        Some(new_desired_replicas) => {
            log::info!("Updating desired replicas to {new_desired_replicas}");
            enclave_api
                .update_scaling_config(enclave_uuid, new_desired_replicas.into())
                .await
        }
        None => enclave_api.get_scaling_config(enclave_uuid).await,
    };

    let scaling_config = match scaling_config_result {
        Ok(result) if args.desired_replicas.is_some() => {
            log::info!("Enclave scaling config updated successfully");
            result
        }
        Ok(result) => result,
        Err(e) => {
            let action = if args.desired_replicas.is_some() {
                "update"
            } else {
                "read"
            };
            log::error!("Failed to {action} the scaling config for {enclave_uuid} - {e:?}");
            return e.exitcode();
        }
    };

    if let Ok(mut config) = enclave_config {
        let has_scaling_drift = config
            .scaling
            .as_ref()
            .is_some_and(|config_scaling_settings| {
                config_scaling_settings.desired_replicas != scaling_config.desired_replicas()
            });

        if (args.sync || args.desired_replicas.is_some()) && has_scaling_drift {
            config.set_scaling_config(ScalingSettings {
                desired_replicas: scaling_config.desired_replicas(),
            });
            ev_enclave::common::save_enclave_config(&config, &args.config);
        }
    }

    if atty::is(atty::Stream::Stdout) {
        println!(
            "{}",
            serde_json::to_string_pretty(&scaling_config)
                .expect("Failed to serialize scaling config")
        );
    } else {
        println!(
            "{}",
            serde_json::to_string(&scaling_config).expect("Failed to serialize scaling config")
        );
    }

    exitcode::OK
}
