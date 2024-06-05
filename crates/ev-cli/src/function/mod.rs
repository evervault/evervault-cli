use serde::{Deserialize, Serialize};
use std::{
    fs::File,
    io::{self, BufReader, Read},
    path::PathBuf,
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum FunctionTomlError {
    #[error(
        "A function.toml could not be found at {0}, specify a function.toml file \
        with the --file flag. Or create a Function with ev function init."
    )]
    ConfigNotFound(String),
    #[error("Error reading function.toml file: {0}")]
    Io(#[from] io::Error),
    #[error("Couldn't find a function.toml file in the current directory.")]
    NotFoundHere,
    #[error("Error parsing function.toml file: {0}")]
    Parse(#[from] toml::de::Error),
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

pub fn get_toml_from_pwd() -> Result<FunctionToml, FunctionTomlError> {
    let path = std::env::current_dir()?.join("function.toml");
    path.try_into()
}

pub fn write_toml(toml: &FunctionToml, path: Option<PathBuf>) -> Result<(), FunctionTomlError> {
    let current_dir = std::env::current_dir()?;
    let path = path.unwrap_or_else(|| current_dir.join("function.toml"));

    std::fs::write(&path, toml::to_string(&toml)?)?;
    Ok(())
}
