use super::enclave::{EIFMeasurements, EnclaveSigningInfo};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EgressSettings {
    pub enabled: bool,
    pub destinations: Option<Vec<String>>,
}

impl EgressSettings {
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct SigningInfo {
    #[serde(rename = "certPath")]
    pub cert: Option<String>,
    #[serde(rename = "keyPath")]
    pub key: Option<String>,
}

impl SigningInfo {
    pub fn is_valid(&self) -> bool {
        self.cert.is_some() && self.key.is_some()
    }
}

#[derive(Clone, Debug, Error)]
pub enum SigningInfoError {
    #[error("No signing info given.")]
    NoSigningInfoGiven,
    #[error("No signing cert given.")]
    EmptySigningCert,
    #[error("No signing key given.")]
    EmptySigningKey,
    #[error("Could not find signing cert file at {0}")]
    SigningCertNotFound(String),
    #[error("Could not find signing key file at {0}")]
    SigningKeyNotFound(String),
}

#[derive(Clone, Debug)]
pub struct ValidatedSigningInfo {
    pub cert: String,
    pub key: String,
}

impl ValidatedSigningInfo {
    pub fn cert(&self) -> &str {
        self.cert.as_str()
    }

    pub fn key(&self) -> &str {
        self.key.as_str()
    }
}

impl std::convert::TryInto<ValidatedSigningInfo> for SigningInfo {
    type Error = SigningInfoError;

    fn try_into(self) -> Result<ValidatedSigningInfo, Self::Error> {
        Ok(ValidatedSigningInfo {
            cert: self.cert.ok_or(Self::Error::EmptySigningCert)?,
            key: self.key.ok_or(Self::Error::EmptySigningKey)?,
        })
    }
}

impl std::convert::TryFrom<&ValidatedSigningInfo> for EnclaveSigningInfo {
    type Error = SigningInfoError;

    fn try_from(signing_info: &ValidatedSigningInfo) -> Result<Self, Self::Error> {
        let cert_path = std::path::Path::new(signing_info.cert());
        let cert_path_buf = cert_path
            .canonicalize()
            .map_err(|_| SigningInfoError::SigningCertNotFound(signing_info.cert().to_string()))?
            .to_path_buf();

        let key_path = std::path::Path::new(signing_info.key());
        let key_path_buf = key_path
            .canonicalize()
            .map_err(|_| SigningInfoError::SigningKeyNotFound(signing_info.key().to_string()))?
            .to_path_buf();

        Ok(Self::new(cert_path_buf, key_path_buf))
    }
}

#[derive(Debug, Error)]
pub enum CageConfigError {
    #[error("Failed to find config file at {0}")]
    MissingConfigFile(String),
    #[error("Failed to read config file — {0:?}")]
    FailedToAccessConfig(#[from] std::io::Error),
    #[error("Failed to parse Cage config")]
    FailedToParseCageConfig(#[from] toml::de::Error),
    #[error("{0}. Signing credentials can be generated using the cert new command.")]
    MissingSigningInfo(#[from] SigningInfoError),
    #[error("Dockerfile is required and was not given.")]
    MissingDockerfile,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CageConfig {
    pub name: String,
    pub debug: bool,
    pub dockerfile: Option<String>,
    pub egress: EgressSettings,
    pub signing: Option<SigningInfo>,
    pub attestation: Option<EIFMeasurements>,
}

// Helper type to guarantee the presence of fields when combining multiple config sources
#[derive(Clone, Debug)]
pub struct ValidatedCageBuildConfig {
    pub debug: bool,
    pub dockerfile: String,
    pub egress: EgressSettings,
    pub signing: ValidatedSigningInfo,
    pub attestation: Option<EIFMeasurements>,
}

impl ValidatedCageBuildConfig {
    pub fn signing_info(&self) -> &ValidatedSigningInfo {
        &self.signing
    }

    pub fn dockerfile(&self) -> &str {
        &self.dockerfile
    }

    pub fn egress(&self) -> &EgressSettings {
        &self.egress
    }
}

impl std::convert::TryInto<ValidatedCageBuildConfig> for CageConfig {
    type Error = CageConfigError;

    fn try_into(self) -> Result<ValidatedCageBuildConfig, Self::Error> {
        let signing_info = self.signing.ok_or(SigningInfoError::NoSigningInfoGiven)?;

        let dockerfile = self.dockerfile.ok_or(CageConfigError::MissingDockerfile)?;

        Ok(ValidatedCageBuildConfig {
            debug: self.debug,
            dockerfile,
            egress: self.egress,
            signing: signing_info.try_into()?,
            attestation: self.attestation,
        })
    }
}

impl CageConfig {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn set_dockerfile(&mut self, dockerfile: String) {
        self.dockerfile = Some(dockerfile);
    }

    pub fn dockerfile(&self) -> Option<&str> {
        self.dockerfile.as_deref()
    }

    pub fn cert(&self) -> Option<&str> {
        self.signing
            .as_ref()
            .and_then(|signing_info| signing_info.cert.as_deref())
    }

    pub fn set_cert(&mut self, cert: String) {
        let mut info = self.signing.clone().unwrap_or(SigningInfo::default());
        info.cert = Some(cert);
        self.signing = Some(info);
    }

    pub fn key(&self) -> Option<&str> {
        self.signing
            .as_ref()
            .and_then(|signing_info| signing_info.key.as_deref())
    }

    pub fn set_key(&mut self, key: String) {
        let mut info = self.signing.clone().unwrap_or(SigningInfo::default());
        info.key = Some(key);
        self.signing = Some(info);
    }

    pub fn set_attestation(&mut self, measurements: &EIFMeasurements) {
        self.attestation = Some(measurements.clone());
    }

    pub fn try_from_filepath(path: &str) -> Result<Self, CageConfigError> {
        let config_path = std::path::Path::new(path);
        if !config_path.exists() {
            return Err(CageConfigError::MissingConfigFile(path.to_string()));
        }

        let cage_config_content = std::fs::read(config_path)?;
        Ok(toml::de::from_slice(cage_config_content.as_slice())?)
    }
}
