use super::common::CliError;
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

impl CliError for SigningInfoError {
    fn exitcode(&self) -> exitcode::ExitCode {
        match self {
            Self::NoSigningInfoGiven | Self::EmptySigningCert | Self::EmptySigningKey => {
                exitcode::DATAERR
            }
            Self::SigningCertNotFound(_) | Self::SigningKeyNotFound(_) => exitcode::NOINPUT,
        }
    }
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

impl std::convert::TryFrom<&SigningInfo> for ValidatedSigningInfo {
    type Error = SigningInfoError;

    fn try_from(signing_info: &SigningInfo) -> Result<ValidatedSigningInfo, Self::Error> {
        Ok(ValidatedSigningInfo {
            cert: signing_info
                .cert
                .as_deref()
                .ok_or(Self::Error::EmptySigningCert)?
                .to_string(),
            key: signing_info
                .key
                .as_deref()
                .ok_or(Self::Error::EmptySigningKey)?
                .to_string(),
        })
    }
}

impl<'a> std::convert::TryFrom<&ValidatedSigningInfo> for EnclaveSigningInfo {
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
    #[error("{0} was not set in the toml.")]
    MissingField(String),
}

impl CliError for CageConfigError {
    fn exitcode(&self) -> exitcode::ExitCode {
        match self {
            Self::MissingConfigFile(_) | Self::FailedToAccessConfig(_) => exitcode::NOINPUT,
            Self::FailedToParseCageConfig(_) | Self::MissingDockerfile | Self::MissingField(_) => {
                exitcode::DATAERR
            }
            Self::MissingSigningInfo(signing_err) => signing_err.exitcode(),
        }
    }
}

pub fn default_dockerfile() -> String {
    "./Dockerfile".to_string()
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CageConfig {
    pub name: String,
    pub uuid: Option<String>,
    pub app_uuid: Option<String>,
    pub team_uuid: Option<String>,
    pub debug: bool,
    #[serde(default = "default_dockerfile")]
    pub dockerfile: String,
    pub egress: EgressSettings,
    pub signing: Option<SigningInfo>,
    pub attestation: Option<EIFMeasurements>,
    pub disable_tls_termination: bool,
}

impl CageConfig {
    pub fn annotate(&mut self, cage: crate::api::cage::Cage) {
        self.uuid = Some(cage.uuid().into());
        self.app_uuid = Some(cage.app_uuid().into());
        self.team_uuid = Some(cage.team_uuid().into());
    }
}

impl std::convert::AsRef<CageConfig> for CageConfig {
    fn as_ref(&self) -> &Self {
        self
    }
}

// Helper type to guarantee the presence of fields when combining multiple config sources
#[derive(Clone, Debug)]
pub struct ValidatedCageBuildConfig {
    pub cage_name: String,
    pub cage_uuid: String,
    pub app_uuid: String,
    pub team_uuid: String,
    pub debug: bool,
    pub dockerfile: String,
    pub egress: EgressSettings,
    pub signing: ValidatedSigningInfo,
    pub attestation: Option<EIFMeasurements>,
    pub disable_tls_termination: bool,
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

    pub fn cage_name(&self) -> &str {
        &self.cage_name
    }

    pub fn cage_uuid(&self) -> &str {
        &self.cage_uuid
    }

    pub fn app_uuid(&self) -> &str {
        &self.app_uuid
    }

    pub fn team_uuid(&self) -> &str {
        &self.team_uuid
    }

    pub fn disable_tls_termination(&self) -> bool {
        self.disable_tls_termination
    }

    pub fn get_dataplane_feature_label(&self) -> String {
        let egress_label = if self.egress.is_enabled() {
            "egress-enabled"
        } else {
            "egress-disabled"
        };
        let tls_label = if self.disable_tls_termination {
            "tls-termination-disabled"
        } else {
            "tls-termination-enabled"
        };
        format!("{egress_label}/{tls_label}")
    }
}

impl CageConfig {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn set_dockerfile(&mut self, dockerfile: String) {
        self.dockerfile = dockerfile;
    }

    pub fn dockerfile(&self) -> &str {
        self.dockerfile.as_ref()
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

impl std::convert::TryFrom<&CageConfig> for ValidatedCageBuildConfig {
    type Error = CageConfigError;

    fn try_from(config: &CageConfig) -> Result<Self, Self::Error> {
        let signing_info = config
            .signing
            .as_ref()
            .ok_or(SigningInfoError::NoSigningInfoGiven)?;

        let app_uuid = config
            .app_uuid
            .clone()
            .ok_or(CageConfigError::MissingField("App uuid".into()))?;
        let cage_uuid = config
            .uuid
            .clone()
            .ok_or(CageConfigError::MissingField("Cage uuid".into()))?;
        let team_uuid = config
            .team_uuid
            .clone()
            .ok_or(CageConfigError::MissingField("Team uuid".into()))?;

        Ok(ValidatedCageBuildConfig {
            cage_uuid,
            app_uuid,
            team_uuid,
            cage_name: config.name.clone(),
            debug: config.debug,
            dockerfile: config.dockerfile.clone(),
            egress: config.egress.clone(),
            signing: signing_info.try_into()?,
            attestation: config.attestation.clone(),
            disable_tls_termination: config.disable_tls_termination,
        })
    }
}

/// Helper trait for allowing command line args to override a deserialized config
pub trait BuildTimeConfig {
    fn certificate(&self) -> Option<&str>;
    fn dockerfile(&self) -> Option<&str>;
    fn private_key(&self) -> Option<&str>;

    // Return new copy of config to prevent args being written to toml file in err
    fn merge_with_config(&self, config: &CageConfig) -> CageConfig {
        let mut merged_config = config.clone();

        if let Some(cert) = self.certificate() {
            merged_config.set_cert(cert.to_string());
        }

        if let Some(dockerfile) = self.dockerfile() {
            merged_config.set_dockerfile(dockerfile.to_string());
        }

        if let Some(private_key) = self.private_key() {
            merged_config.set_key(private_key.to_string());
        }

        merged_config
    }
}

// Return both config read directly from FS as well as merged & validated config
pub fn read_and_validate_config<B: BuildTimeConfig>(
    config_path: &str,
    args: &B,
) -> Result<(CageConfig, ValidatedCageBuildConfig), CageConfigError> {
    let cage_config = CageConfig::try_from_filepath(&config_path)?;
    let merged_config = args.merge_with_config(&cage_config);

    let validated_config: ValidatedCageBuildConfig = merged_config.as_ref().try_into()?;

    Ok((cage_config, validated_config))
}
