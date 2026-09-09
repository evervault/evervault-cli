use std::{path::PathBuf, str::FromStr};

use clap::Parser;
use thiserror::Error;

use crate::{
    commands::interact::{preset_input, select, validated_input, validators},
    function::{
        runtime::FunctionRuntime, write_toml, FunctionProps, FunctionToml, FunctionTomlError,
    },
    CmdOutput,
};

/// Generate a toml configuration file for your Function
#[derive(Parser, Debug)]
pub struct CreateTomlArgs {}

#[derive(strum_macros::Display, Debug)]
pub enum CreateTomlPrompt {
    #[strum(to_string = "Give your Function a name:")]
    Name,
    #[strum(to_string = "Select your Function's language:")]
    Language,
    #[strum(to_string = "What is the entry point to your function?:")]
    Handler,
}

#[derive(strum_macros::Display, Debug)]
pub enum CreateTomlMessage {
    #[strum(to_string = "Function configuration saved to function.toml.")]
    Success,
}

impl CmdOutput for CreateTomlMessage {
    fn exitcode(&self) -> crate::errors::ExitCode {
        crate::errors::OK
    }

    fn code(&self) -> String {
        match self {
            CreateTomlMessage::Success => "generic/success",
        }
        .to_string()
    }

    fn data(&self) -> Option<serde_json::Value> {
        None
    }
}

#[derive(Error, Debug)]
pub enum CreateTomlError {
    #[error("An IO error occurred: {0}")]
    Io(#[from] std::io::Error),
    #[error("A function.toml file already exists in the current directory")]
    AlreadyExists,
    #[error(transparent)]
    Toml(#[from] FunctionTomlError),
}

impl CmdOutput for CreateTomlError {
    fn exitcode(&self) -> crate::errors::ExitCode {
        match self {
            CreateTomlError::Io(_) => crate::errors::IOERR,
            CreateTomlError::AlreadyExists | CreateTomlError::Toml(_) => crate::errors::SOFTWARE,
        }
    }

    fn code(&self) -> String {
        match self {
            CreateTomlError::Io(_) => "generic/io-error",
            CreateTomlError::AlreadyExists => "generic/already-exists",
            CreateTomlError::Toml(_) => "functions/toml-error",
        }
        .to_string()
    }

    fn data(&self) -> Option<serde_json::Value> {
        None
    }
}

pub async fn run(_: CreateTomlArgs) -> Result<CreateTomlMessage, CreateTomlError> {
    if PathBuf::from_str("./function.toml")
        .expect("infallible")
        .exists()
    {
        return Err(CreateTomlError::AlreadyExists);
    }

    let name = validated_input(
        CreateTomlPrompt::Name,
        false,
        Box::new(validators::validate_function_name),
    )?;

    let runtimes: Vec<FunctionRuntime> = FunctionRuntime::supported().collect();
    let labels = runtimes
        .iter()
        .map(|runtime| runtime.to_string())
        .collect::<Vec<String>>();

    let selection = select(&labels, 0, CreateTomlPrompt::Language).unwrap();

    let handler = preset_input(CreateTomlPrompt::Handler, "index.handler".to_string()).unwrap();

    let config = FunctionToml {
        function: FunctionProps {
            name,
            language: runtimes[selection],
            handler,
        },
    };

    write_toml(&config, None)?;

    Ok(CreateTomlMessage::Success)
}
