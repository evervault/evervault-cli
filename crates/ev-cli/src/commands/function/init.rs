use std::{fs::File, path::PathBuf};

use crate::fs::{copy_folder, get_current_dir, set_function_name};
use crate::CmdOutput;
use crate::{commands::interact, fs::extract_zip};
use atty::Stream;
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
    #[arg(short, long)]
    pub directory: Option<String>,
    #[arg(short, default_value_t = false)]
    pub force: bool,
}

#[derive(Error, Debug)]
pub enum InitError {
    #[error("An error occurred while reading input")]
    InputError,
    #[error("An error occurred while fetching the function template: {0}")]
    TemplateFetch(#[from] ApiError),
    #[error("An error occurred trying to unzip the function template: {0}")]
    Unzip(#[from] ZipError),
    #[error("An error occured during a file system operation: {0}")]
    FsError(#[from] crate::fs::FsError),
    #[error("Something already exists in the target directory ({0}), use --force if you want to overwrite it")]
    TargetExists(PathBuf),
    #[error("An occurred updating the function name in the function toml")]
    TomlUpdate,
}

impl CmdOutput for InitError {
    fn code(&self) -> String {
        "init-error".to_string()
    }

    fn exitcode(&self) -> crate::errors::ExitCode {
        crate::errors::GENERAL
    }
}

#[derive(strum_macros::Display, Debug)]
pub enum InitMessage {
    #[strum(to_string = "Creating function: {name}")]
    Created { name: String },
    #[strum(to_string = "Function: {name}, initialized at {dir}")]
    Initialized { name: String, dir: String },
}

impl CmdOutput for InitMessage {
    fn code(&self) -> String {
        "init-created".to_string()
    }

    fn exitcode(&self) -> crate::errors::ExitCode {
        crate::errors::OK
    }
}

#[derive(strum_macros::Display)]
pub enum InitPrompt {
    #[strum(to_string = "Give your function a name:")]
    Name,
}

pub async fn run(args: InitArgs, auth: BasicAuth) -> Result<InitMessage, InitError> {
    let api_client = papi::EvApiClient::new(auth);
    let valid_languages: [&str; 2] = ["node", "python"];
    let name = interact::input(InitPrompt::Name, false);

    let langs = valid_languages
        .iter()
        .map(|lang| lang.to_string())
        .collect::<Vec<String>>();
    let language = interact::select(
        &langs,
        0,
        Some("Select your Function's language:".to_string()),
    )
    .unwrap();
    let lang = valid_languages[language].to_string();

    let file = api_client.get_hello_function_template(lang.clone()).await?;

    let target_dir = PathBuf::from("/tmp/hello-function-template".to_string());

    extract_zip(file, target_dir)?;

    let current_dir = get_current_dir()?;

    let target = match args.directory {
        Some(dir) => PathBuf::from(dir),
        None => current_dir.join(&name),
    };

    if target.exists() && !args.force {
        return Err(InitError::TargetExists(target));
    }

    let folder = format!(
        "/tmp/hello-function-template/template-{}-hello-function-master",
        lang
    );

    let location = copy_folder(folder.as_str(), target)?;

    set_function_name(&name, Some(&location)).map_err(|_| InitError::TomlUpdate)?;

    Ok(InitMessage::Initialized {
        name,
        dir: location,
    })
}
