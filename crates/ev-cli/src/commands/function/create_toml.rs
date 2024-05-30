use std::{fs, path::PathBuf, str::FromStr};

use clap::Parser;
use serde::Serialize;
use thiserror::Error;

use crate::{
    commands::interact::{input, preset_input, select, validated_input, validators},
    CmdOutput,
};

#[derive(Serialize)]
struct FunctionConfig {
    name: String,
    language: String,
    handler: String,
}

#[derive(Serialize)]
struct FunctionToml {
    function: FunctionConfig,
}

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
    Success,
}

impl CmdOutput for CreateTomlMessage {
    fn exitcode(&self) -> crate::errors::ExitCode {
        crate::errors::OK
    }

    fn code(&self) -> String {
        match self {
            CreateTomlMessage::Success => "function-create-toml-success",
        }
        .to_string()
    }
}

#[derive(Error, Debug)]
pub enum CreateTomlError {
    #[error("An IO error occurred: {0}")]
    Io(#[from] std::io::Error),
    #[error("A function.toml file already exists in the current directory")]
    AlreadyExists,
}

impl CmdOutput for CreateTomlError {
    fn exitcode(&self) -> crate::errors::ExitCode {
        match self {
            CreateTomlError::Io(_) => crate::errors::IOERR,
            CreateTomlError::AlreadyExists => crate::errors::SOFTWARE,
        }
    }

    fn code(&self) -> String {
        match self {
            CreateTomlError::Io(_) => "function-create-toml-io-error",
            CreateTomlError::AlreadyExists => "function-create-toml-already-exists",
        }
        .to_string()
    }
}

pub async fn run(_: CreateTomlArgs) -> Result<CreateTomlMessage, CreateTomlError> {
    if PathBuf::from_str("./function.toml")
        .expect("infallible")
        .exists()
    {
        return Err(CreateTomlError::AlreadyExists);
    }

    let valid_languages: [&str; 5] = [
        "node@18",
        "node@20",
        "python@3.9",
        "python@3.10",
        "python@3.11",
    ];

    let name = validated_input(
        CreateTomlPrompt::Name,
        false,
        Box::new(validators::validate_function_name),
    )?;

    let langs = valid_languages
        .iter()
        .map(|lang| lang.to_string())
        .collect::<Vec<String>>();

    let language = select(&langs, 0, CreateTomlPrompt::Language).unwrap();

    let handler = preset_input(CreateTomlPrompt::Handler, "index.handler".to_string()).unwrap();

    let config = FunctionToml {
        function: FunctionConfig {
            name,
            language: valid_languages[language].to_string(),
            handler: handler.to_string(),
        },
    };

    let toml = toml::to_string(&config).unwrap();
    fs::write("function.toml", toml)?;

    return Ok(CreateTomlMessage::Success);
}
