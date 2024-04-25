use thiserror::Error;

use crate::enclave::config::{
    EnclaveConfig, EnclaveConfigError, EnclaveConfigV0, ValidatedEnclaveBuildConfig,
};

#[derive(Debug, Error)]
pub enum MigrateError {
    #[error("Could not get config at path - {0}")]
    MissingConfigFile(String),
    #[error("IO error - {0}")]
    IOError(#[from] std::io::Error),
    #[error("Error deserializing existing enclave toml - {0}")]
    TomlDeError(#[from] toml::de::Error),
    #[error("Error serializing enclave toml - {0}")]
    TomlSerError(#[from] toml::ser::Error),
    #[error("Config is not valid - {0}")]
    InvalidConfigError(#[from] EnclaveConfigError),
}

pub fn migrate_toml(config_path: &str) -> Result<Vec<u8>, MigrateError> {
    let path = std::path::Path::new(config_path);
    if !path.exists() {
        return Err(MigrateError::MissingConfigFile(path.display().to_string()));
    }

    let enclave_config_content = std::fs::read(config_path)?;
    let v0_config: EnclaveConfigV0 = toml::de::from_slice(enclave_config_content.as_slice())?;
    let v1_config: EnclaveConfig = v0_config.into();
    let _: ValidatedEnclaveBuildConfig = v1_config.as_ref().try_into()?;
    Ok(toml::ser::to_vec(&v1_config)?)
}
