use crate::relay::RelayConfig;
use crate::CmdOutput;
use clap::Parser;
use common::api::{papi::EvApi, BasicAuth};
use strum::Display;
use thiserror::Error;

/// Deploy your Evervault Relay
#[derive(Parser, Debug)]
#[command(name = "deploy", about)]
pub struct DeployArgs {
    /// The file containing the relay config you want to use. Defaults to relay.json
    #[arg(short = 'f', long = "file", default_value = "relay.json")]
    file: String,
}

#[derive(Debug, Error)]
pub enum DeployError {
    #[error(transparent)]
    RelayConfigError(#[from] crate::relay::RelayConfigError),
    #[error("An unexpected API error occured when deploying your relay")]
    ApiError(#[from] common::api::client::ApiError),
}

impl CmdOutput for DeployError {
    fn code(&self) -> String {
        match self {
            DeployError::RelayConfigError(_) => "relay-config-error",
            DeployError::ApiError(_) => "relay-deploy-error",
        }
        .to_string()
    }

    fn exitcode(&self) -> crate::errors::ExitCode {
        match self {
            DeployError::RelayConfigError(_) => crate::errors::CONFIG,
            DeployError::ApiError(_) => crate::errors::GENERAL,
        }
    }
}

#[derive(Display)]
pub enum DeployMessage {
    #[strum(to_string = "Relay successfully deployed with destination {}")]
    Success(String),
    #[strum(to_string = "Relay successfully created with destination {}")]
    NewRelayCreated(String),
}

impl CmdOutput for DeployMessage {
    fn code(&self) -> String {
        match self {
            DeployMessage::Success(_) => "relay-deployed".to_string(),
            DeployMessage::NewRelayCreated(_) => "relay-created".to_string(),
        }
    }

    fn exitcode(&self) -> crate::errors::ExitCode {
        crate::errors::OK
    }
}

pub async fn run(args: DeployArgs, auth: BasicAuth) -> Result<DeployMessage, DeployError> {
    let relay_config = RelayConfig::try_from(&args.file.clone().into())?;
    let api_client = common::api::papi::EvApiClient::new(auth);

    let update = api_client.update_relay(&relay_config.relay).await;

    if update.is_err() {
        let relay = api_client.create_relay(&relay_config.relay).await?;
        return Ok(DeployMessage::NewRelayCreated(relay.destination_domain));
    } else {
        return Ok(DeployMessage::Success(
            update.expect("infallible").destination_domain,
        ));
    }
}
