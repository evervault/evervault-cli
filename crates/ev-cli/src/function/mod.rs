use common::{
    api::{
        client::ApiError,
        papi::{EvApi, EvApiClient},
    },
    function::Function,
};
use serde::{Deserialize, Serialize};
use std::{
    fs::File,
    io::{self, BufReader, Read},
    path::PathBuf,
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum FunctionTomlError {
    #[error("A function.toml could not be found at {0}")]
    ConfigNotFound(String),
    #[error("Error reading function.toml file: {0}")]
    Io(#[from] io::Error),
    #[error("Error parsing function.toml file: {0}")]
    De(#[from] toml::de::Error),
    #[error("Error serializing function.toml file: {0}")]
    Ser(#[from] toml::ser::Error),
}

#[derive(Debug, Deserialize, Serialize)]
pub struct FunctionToml {
    pub function: FunctionProps,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct FunctionProps {
    pub name: String,
    pub language: String,
    #[serde(default = "default_handler")]
    pub handler: String,
}

fn default_handler() -> String {
    "index.handler".to_string()
}

impl TryFrom<std::path::PathBuf> for FunctionToml {
    type Error = FunctionTomlError;

    fn try_from(path: std::path::PathBuf) -> Result<Self, Self::Error> {
        if !path.try_exists()? {
            return Err(FunctionTomlError::ConfigNotFound(
                path.to_string_lossy().into(),
            ));
        }

        let file = File::open(&path)?;
        let mut buf_reader = BufReader::new(file);
        let mut contents = String::new();
        buf_reader.read_to_string(&mut contents)?;

        Ok(toml::from_str(&contents)?)
    }
}

pub fn write_toml(toml: &FunctionToml, path: Option<PathBuf>) -> Result<(), FunctionTomlError> {
    let current_dir = std::env::current_dir()?;
    let path = path.unwrap_or_else(|| current_dir.join("function.toml"));

    std::fs::write(&path, toml::to_string(&toml)?)?;
    Ok(())
}

#[derive(Debug, Error)]
pub enum ResolveFunctionError {
    #[error("An error occurred while resolving the Function: {0}")]
    ApiError(#[from] ApiError),
    #[error(transparent)]
    FunctionTomlError(#[from] FunctionTomlError),
    #[error(
        "The specified Function could not be found. Please check the Function name and try again"
    )]
    NamedNotFound,
    #[error("The Function \"{0}\" specificed in the function.toml doesn't exist. Please make sure the Function exists in your app. Function that have been initialized locally must be deployed before you can manage them using the Evervault CLI")]
    Unknown(String),
    #[error("Function could not be resolved. Either specify a Function with the --name flag, or run the command from the directory containing your function.toml file")]
    NoToml,
    #[error("An IO error occurred: {0}")]
    Io(#[from] std::io::Error),
}

pub async fn resolve_function_by_name_or_pwd(
    maybe_name: Option<String>,
    client: &EvApiClient,
) -> Result<Function, ResolveFunctionError> {
    let functions = client.get_all_functions_for_app().await?;

    if let Some(name) = maybe_name {
        return functions
            .iter()
            .find(|f| f.name == name)
            .map(|f| f.to_owned())
            .ok_or(ResolveFunctionError::NamedNotFound);
    }

    let path = std::env::current_dir()?.join("function.toml");
    let function_toml: FunctionToml = path.try_into().map_err(|err| match err {
        FunctionTomlError::ConfigNotFound(_) => ResolveFunctionError::NoToml,
        _ => ResolveFunctionError::FunctionTomlError(err),
    })?;

    functions
        .iter()
        .find(|f| f.name == function_toml.function.name)
        .cloned()
        .ok_or(ResolveFunctionError::Unknown(function_toml.function.name))
}
