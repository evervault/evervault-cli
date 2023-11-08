use crate::config::{self, ScalingSettings};
use crate::version::check_version;
use crate::{
    api::{cage::CagesClient, AuthMode},
    common::CliError,
    config::CageConfig,
    get_api_key,
};
use clap::Parser;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ScaleError {
    #[error("No Cage Uuid given. You can provide one by using either the --cage-uuid flag, or using the --config flag to point to a Cage.toml")]
    MissingUuid,
    #[error("An error occurred parsing the Cage config - {0}")]
    ConfigError(#[from] config::CageConfigError),
    #[error("An error occurred contacting the API — {0}")]
    ApiError(#[from] crate::api::client::ApiError),
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

/// Update your Cage's Scaling config
#[derive(Debug, Parser)]
#[clap(name = "scale", about)]
pub struct ScaleArgs {
    /// Path to cage.toml config file
    #[clap(short = 'c', long = "config", default_value = "./cage.toml")]
    pub config: String,

    /// Uuid of the Cage to scale
    #[clap(long = "cage-uuid")]
    pub cage_uuid: Option<String>,

    /// Number of replicas to run for this Cage. If unset, the command will read the current scaling config from the Evervault API.
    #[clap(long = "desired-replicas")]
    pub desired_replicas: Option<u32>,

    /// Sync the local Cage.toml with the latest scaling config for a Cage if they differ.
    #[clap(long = "sync")]
    pub sync: bool,
}

pub async fn run(args: ScaleArgs) -> i32 {
    if let Err(e) = check_version().await {
        log::error!("{}", e);
        return exitcode::SOFTWARE;
    };

    let api_key = get_api_key!();

    let cage_api = CagesClient::new(AuthMode::ApiKey(api_key.to_string()));

    let cage_config = CageConfig::try_from_filepath(&args.config);
    let cage_uuid = match args.cage_uuid.as_deref() {
        Some(cage_uuid) => Ok(cage_uuid),
        None => match cage_config.as_ref() {
            Ok(cage_config) => cage_config.uuid.as_deref().ok_or(ScaleError::MissingUuid),
            Err(e) => {
                log::error!("Failed to resolve cage config - {e:?}");
                return e.exitcode();
            }
        },
    };

    let cage_uuid = match cage_uuid {
        Ok(cage_uuid) => cage_uuid,
        Err(e) => {
            log::error!("{e:?}");
            return e.exitcode();
        }
    };

    let scaling_config_result = match args.desired_replicas {
        Some(new_desired_replicas) => {
            log::info!("Updating desired replicas to {new_desired_replicas}");
            cage_api
                .update_scaling_config(&cage_uuid, new_desired_replicas.into())
                .await
        }
        None => cage_api.get_scaling_config(&cage_uuid).await,
    };

    let scaling_config = match scaling_config_result {
        Ok(result) if args.desired_replicas.is_some() => {
            log::info!("Cage scaling config updated successfully");
            result
        }
        Ok(result) => result,
        Err(e) => {
            let action = if args.desired_replicas.is_some() {
                "update"
            } else {
                "read"
            };
            log::error!("Failed to {action} the scaling config for {cage_uuid} - {e:?}");
            return e.exitcode();
        }
    };

    if let Ok(mut config) = cage_config {
        let has_scaling_drift = config
            .scaling
            .as_ref()
            .map(|config_scaling_settings| {
                config_scaling_settings
                    .desired_replicas
                    .map(|desired_replicas| desired_replicas != scaling_config.desired_replicas())
                    .unwrap_or(false) // desired_replicas is not set in the config
            })
            .unwrap_or(false); // scaling config not set in the config

        if (args.sync && args.desired_replicas.is_some()) && has_scaling_drift {
            config.set_scaling_config(ScalingSettings {
                desired_replicas: Some(scaling_config.desired_replicas()),
            });
            crate::common::save_cage_config(&config, &args.config);
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
