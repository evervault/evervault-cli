use serde::{Deserialize, Serialize};
use std::{
    fs::File,
    io::{self, BufReader, Read},
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum FunctionTomlError {
    #[error(
        "Relay configuration could not be found at {0}, specify a relay config file \
        with the --file flag. Or create a relay with ev relay create."
    )]
    ConfigNotFound(String),
    #[error("Error reading relay config file: {0}")]
    IoError(#[from] io::Error),
    #[error("Error parsing relay config file: {0}")]
    ParseError(#[from] toml::de::Error),
}

#[derive(Debug, Deserialize, Serialize)]
struct FunctionToml {
    function: FunctionProps,
}

#[derive(Debug, Deserialize, Serialize)]
struct FunctionProps {
    name: String,
    language: String,
    #[serde(default = "default_handler")]
    handler: String,
}

fn default_handler() -> String {
    "index.handler".to_string()
}

impl TryFrom<&std::path::PathBuf> for FunctionToml {
    type Error = FunctionTomlError;

    fn try_from(path: &std::path::PathBuf) -> Result<Self, Self::Error> {
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
