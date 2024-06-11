use std::path::PathBuf;

use crate::commands::interact::validators;
use crate::fs::copy_folder;
use crate::function::{write_toml, FunctionProps, FunctionToml};
use crate::CmdOutput;
use crate::{commands::interact, fs::extract_zip};
use clap::Parser;
use common::api::{
    client::ApiError,
    papi::{self, EvApi},
    BasicAuth,
};
use thiserror::Error;
use zip::result::ZipError;
/// Initialize a function
#[derive(Parser, Debug)]
#[command(name = "init")]
pub struct InitArgs {
    #[arg(long = "dir")]
    pub directory: Option<String>,
    #[arg(short, default_value_t = false)]
    pub force: bool,
}

#[derive(Error, Debug)]
pub enum InitError {
    #[error("An error occurred while fetching the function template: {0}")]
    TemplateFetch(#[from] ApiError),
    #[error("An error occurred trying to unzip the function template: {0}")]
    Unzip(#[from] ZipError),
    #[error("Something already exists in the target directory ({0}), use --force if you want to overwrite it")]
    TargetExists(PathBuf),
    #[error(transparent)]
    Validation(#[from] validators::ValidationError),
    #[error("An IO error occurred: {0}")]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Toml(#[from] crate::function::FunctionTomlError),
}

impl CmdOutput for InitError {
    fn code(&self) -> String {
        match self {
            InitError::TemplateFetch(_) => "functions/template-fetch-error",
            InitError::Unzip(_) => "functions/unzip-error",
            InitError::Io(_) => "generic/io-error",
            InitError::TargetExists(_) => "functions/not-found-error",
            InitError::Validation(_) => "generic/validation-failed",
            InitError::Toml(_) => "functions/toml-error",
        }
        .to_string()
    }

    fn exitcode(&self) -> crate::errors::ExitCode {
        crate::errors::GENERAL
    }

    fn data(&self) -> Option<serde_json::Value> {
        None
    }
}

#[derive(strum_macros::Display, Debug)]
pub enum InitMessage {
    #[strum(to_string = "Function: {name}, initialized at {dir}")]
    Initialized { name: String, dir: String },
}

impl CmdOutput for InitMessage {
    fn code(&self) -> String {
        match self {
            InitMessage::Initialized { .. } => "generic/success".to_string(),
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
pub enum InitPrompt {
    #[strum(to_string = "Give your function a name:")]
    Name,
    #[strum(to_string = "Select your function's language:")]
    Language,
}

pub async fn run(args: InitArgs, auth: BasicAuth) -> Result<InitMessage, InitError> {
    let api_client = papi::EvApiClient::new(auth);
    let base_args = crate::commands::BaseArgs::parse();

    let valid_languages: [&str; 2] = ["node", "python"];
    let name = interact::input(InitPrompt::Name, false);

    validators::validate_function_name(&name)?;

    let langs = valid_languages
        .iter()
        .map(|lang| lang.to_string())
        .collect::<Vec<String>>();
    let language = interact::select(&langs, 0, InitPrompt::Language).unwrap();
    let lang = valid_languages[language].to_string();

    let progress = interact::start_spinner("Downloading function template...", !base_args.json);
    let file = api_client.get_hello_function_template(lang.clone()).await?;
    progress.finish();

    let tmp_target_dir = PathBuf::from("/tmp/hello-function-template");
    extract_zip(file, &tmp_target_dir)?;

    let current_dir = std::env::current_dir()?;
    let target_dir: PathBuf = args
        .directory
        .map(|dir| PathBuf::from(dir))
        .unwrap_or_else(|| current_dir.join(&name));

    if target_dir.exists() && !args.force {
        return Err(InitError::TargetExists(target_dir));
    }

    let tmp_src_dir = tmp_target_dir.join(format!("template-{}-hello-function-master", lang));

    let toml: FunctionToml = tmp_src_dir.join("function.toml").try_into()?;

    let updated_toml = FunctionToml {
        function: FunctionProps {
            name: name.clone(),
            ..toml.function
        },
    };
    write_toml(&updated_toml, Some(tmp_src_dir.join("function.toml")))?;

    let location = copy_folder(&tmp_src_dir, &target_dir)?;

    Ok(InitMessage::Initialized {
        name,
        dir: location,
    })
}
