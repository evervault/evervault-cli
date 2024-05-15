use common::relay::Relay;
use std::{fs, io};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum RelayConfigError {
    #[error(
        "No relay.json file found in this directory, specify a relay config file \
        with the --file flag. Or create a relay with ev relay create."
    )]
    ConfigNotFound(String),
    #[error("Error reading relay config file: {0}")]
    IoError(#[from] io::Error),
    #[error("Error parsing relay config file: {0}")]
    ParseError(#[from] serde_json::Error),
}

pub struct RelayConfig {
    pub relay: Relay,
}

impl TryFrom<&std::path::PathBuf> for RelayConfig {
    type Error = RelayConfigError;

    fn try_from(path: &std::path::PathBuf) -> Result<Self, Self::Error> {
        if !path.try_exists()? {
            return Err(RelayConfigError::ConfigNotFound(
                path.to_string_lossy().to_string(),
            ));
        }

        let relay_config_str = fs::read_to_string(path)?;
        Ok(RelayConfig {
            relay: serde_json::from_str::<Relay>(&relay_config_str)?,
        })
    }
}
