use std::fs;

use clap::Parser;
use serde::Serialize;
use thiserror::Error;

use crate::commands::interact::{input, preset_input, select};

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

#[derive(Error, Debug)]
pub enum CreateTomlError {
    #[error("An IO error occurred: {0}")]
    Io(#[from] std::io::Error),
}

pub async fn run(_: CreateTomlArgs) -> Result<CreateTomlMessage, CreateTomlError> {
    let valid_languages: [&str; 5] = [
        "node@18",
        "node@20",
        "python@3.9",
        "python@3.10",
        "python@3.11",
    ];

    // Set name
    let name = input(CreateTomlPrompt::Name, false);

    // Set language
    let langs = valid_languages
        .iter()
        .map(|lang| lang.to_string())
        .collect::<Vec<String>>();

    let language = select(&langs, 0, CreateTomlPrompt::Language).unwrap();

    // Set handler
    let handler = preset_input(
        CreateTomlPrompt::Handler.to_string(),
        "index.handler".to_string(),
    )
    .unwrap();

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
