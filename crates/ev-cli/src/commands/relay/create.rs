use crate::CmdOutput;
use clap::Parser;
use common::{
    api::{
        client::ApiError,
        papi::{self, EvApi},
        BasicAuth,
    },
    relay::Relay,
};
use std::path::PathBuf;
use thiserror::Error;

use crate::commands::interact::{self, validated_input};
/// Creates an Evervault Relay and generates its configuration file
#[derive(Parser, Debug)]
#[command(name = "create")]
pub struct CreateArgs {
    /// Path to write relay.json to. Defaults to relay.json
    #[arg(short = 'o', long = "out", default_value = "relay.json")]
    pub out: String,
    #[arg(short = 'f', long = "force", default_value = "false")]
    pub force: bool,
}

#[derive(Error, Debug)]
pub enum CreateError {
    #[error(
        "A Relay configuration file already exists at the path: {0}, use the --force parameter to overwrite the existing file"
    )]
    FileAlreadyExists(String),
    #[error("An IO error occurred: {0}")]
    Io(#[from] std::io::Error),
    #[error("An error occurred while creating the relay: {0}")]
    Api(#[from] ApiError),
    #[error("An error occured while parsing the relay configuration: {0}")]
    Parse(#[from] serde_json::Error),
}

impl CmdOutput for CreateError {
    fn code(&self) -> String {
        match self {
            CreateError::FileAlreadyExists(_) => "generic/already-exists",
            CreateError::Io(_) => "relay-write-error",
            CreateError::Api(_) => "relay-api-error",
            CreateError::Parse(_) => "relay-parse-error",
        }
        .to_string()
    }

    fn exitcode(&self) -> crate::errors::ExitCode {
        match self {
            CreateError::Io(_) => crate::errors::IOERR,
            _ => crate::errors::GENERAL,
        }
    }

    fn data(&self) -> Option<serde_json::Value> {
        None
    }
}

#[derive(strum_macros::Display, Debug)]
pub enum CreateMessage {
    #[strum(to_string = "Relay configuration saved to file {0}")]
    FileWritten(String),
}

impl CmdOutput for CreateMessage {
    fn code(&self) -> String {
        match self {
            CreateMessage::FileWritten(_) => "relay-file-written".to_string(),
        }
    }

    fn exitcode(&self) -> crate::errors::ExitCode {
        crate::errors::OK
    }

    fn data(&self) -> Option<serde_json::Value> {
        None
    }
}

#[derive(strum_macros::Display)]
pub enum CreatePrompt {
    #[strum(
        to_string = "Where should we forward requests to? This can be any domain that accepts HTTPS requests."
    )]
    WhichDomain,
}

pub async fn run(args: CreateArgs, auth: BasicAuth) -> Result<CreateMessage, CreateError> {
    let path = PathBuf::from(&args.out);

    if let Ok(exists) = path.try_exists() {
        if exists & !args.force {
            return Err(CreateError::FileAlreadyExists(args.out));
        }
    }

    let domain = validated_input(
        CreatePrompt::WhichDomain,
        false,
        Box::new(interact::validators::validate_destination_domain),
    )?;

    let relay_req_body = Relay {
        id: None,
        destination_domain: domain,
        routes: vec![],
        evervault_domain: None,
        encrypt_empty_strings: true,
        authentication: None,
        app: None,
    };

    let api_client = papi::EvApiClient::new(auth);

    let relay = api_client.create_relay(&relay_req_body).await?;
    let config_to_write = serde_json::to_string_pretty(&relay)?;

    std::fs::write(&path, config_to_write)?;

    Ok(CreateMessage::FileWritten(args.out))
}
