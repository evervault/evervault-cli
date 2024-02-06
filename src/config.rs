use std::path::Path;

use crate::cert::{get_cert_validity_period, CertValidityPeriod};

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
    pub fn new(destinations: Option<Vec<String>>, enabled: bool) -> EgressSettings {
        let enabled = enabled || destinations.is_some();
        let destinations = if enabled && destinations.is_none() {
            Some(vec!["*".to_string()])
        } else {
            destinations.clone()
        };
        EgressSettings {
            enabled,
            destinations,
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }
    pub fn get_destinations(self) -> String {
        self.destinations
            .map(|destination| destination.join(","))
            .unwrap_or("*".to_string())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ScalingSettings {
    pub desired_replicas: u32,
}

impl Default for ScalingSettings {
    fn default() -> Self {
        ScalingSettings {
            desired_replicas: 2,
        }
    }
}

impl ScalingSettings {
    pub fn new(desired_replicas: u32) -> ScalingSettings {
        ScalingSettings { desired_replicas }
    }

    pub fn get_desired_replicas(self) -> u32 {
        self.desired_replicas
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
    #[error("Invalid signing cert given.")]
    InvalidSigningCert,
    #[error("Could not find signing cert file at {0}")]
    SigningCertNotFound(String),
    #[error("Could not find signing key file at {0}")]
    SigningKeyNotFound(String),
}

impl CliError for SigningInfoError {
    fn exitcode(&self) -> exitcode::ExitCode {
        match self {
            Self::NoSigningInfoGiven
            | Self::EmptySigningCert
            | Self::EmptySigningKey
            | Self::InvalidSigningCert => exitcode::DATAERR,
            Self::SigningCertNotFound(_) | Self::SigningKeyNotFound(_) => exitcode::NOINPUT,
        }
    }
}


#[derive(Clone, Debug)]
pub struct ValidatedSigningInfo {
    pub cert: String,
    pub key: String,
    pub cert_validity_period: CertValidityPeriod,
}

impl ValidatedSigningInfo {
    pub fn cert(&self) -> &str {
        self.cert.as_str()
    }

    pub fn key(&self) -> &str {
        self.key.as_str()
    }

    pub fn not_before(&self) -> String {
        self.cert_validity_period.not_before.clone()
    }

    pub fn not_after(&self) -> String {
        self.cert_validity_period.not_after.clone()
    }
}

impl std::convert::TryFrom<&SigningInfo> for ValidatedSigningInfo {
    type Error = SigningInfoError;

    fn try_from(signing_info: &SigningInfo) -> Result<ValidatedSigningInfo, Self::Error> {
        let cert_path = signing_info
            .cert
            .as_deref()
            .ok_or(Self::Error::EmptySigningCert)?
            .to_string();

        let key_path = signing_info
            .key
            .as_deref()
            .ok_or(Self::Error::EmptySigningKey)?
            .to_string();

        let cert_validity_period = get_cert_validity_period(Path::new(&cert_path))
            .map_err(|_| Self::Error::EmptySigningCert)?;

        Ok(ValidatedSigningInfo {
            cert: cert_path,
            key: key_path,
            cert_validity_period,
        })
    }
}

impl std::convert::TryFrom<&ValidatedSigningInfo> for EnclaveSigningInfo {
    type Error = SigningInfoError;

    fn try_from(signing_info: &ValidatedSigningInfo) -> Result<Self, Self::Error> {
        let cert_path = std::path::Path::new(signing_info.cert());
        let cert_path_buf = cert_path
            .canonicalize()
            .map_err(|_| SigningInfoError::SigningCertNotFound(signing_info.cert().to_string()))?;

        let key_path = std::path::Path::new(signing_info.key());
        let key_path_buf = key_path
            .canonicalize()
            .map_err(|_| SigningInfoError::SigningKeyNotFound(signing_info.key().to_string()))?;

        Ok(Self::new(cert_path_buf, key_path_buf))
    }
}

#[derive(Debug, Error)]
pub enum EnclaveConfigError {
    #[error("Failed to find config file at {0}")]
    MissingConfigFile(String),
    #[error("Failed to read config file — {0:?}")]
    FailedToAccessConfig(#[from] std::io::Error),
    #[error("Failed to parse Enclave config")]
    FailedToParseEnclaveConfig(#[from] toml::de::Error),
    #[error("{0}. Signing credentials can be generated using the cert new command.")]
    MissingSigningInfo(#[from] SigningInfoError),
    #[error("Dockerfile is required and was not given.")]
    MissingDockerfile,
    #[error("{0} was not set in the toml.")]
    MissingField(String),
    #[error("TLS Termination must be enabled to enable Enclave logging.")]
    LoggingEnabledWithoutTLSTermination(),
}

impl CliError for EnclaveConfigError {
    fn exitcode(&self) -> exitcode::ExitCode {
        match self {
            Self::MissingConfigFile(_) | Self::FailedToAccessConfig(_) => exitcode::NOINPUT,
            Self::FailedToParseEnclaveConfig(_)
            | Self::MissingDockerfile
            | Self::MissingField(_)
            | Self::LoggingEnabledWithoutTLSTermination() => exitcode::DATAERR,
            Self::MissingSigningInfo(signing_err) => signing_err.exitcode(),
        }
    }
}

pub fn default_dockerfile() -> String {
    "./Dockerfile".to_string()
}

pub fn default_true() -> bool {
    true
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EnclaveConfig {
    pub version: u8,
    pub name: String,
    pub uuid: Option<String>,
    pub app_uuid: Option<String>,
    pub team_uuid: Option<String>,
    pub debug: bool,
    #[serde(default = "default_dockerfile")]
    pub dockerfile: String,
    #[serde(default = "default_true")]
    pub api_key_auth: bool,
    #[serde(default = "default_true")]
    pub trx_logging: bool,
    #[serde(default = "default_true")]
    pub tls_termination: bool,
    #[serde(default)]
    pub forward_proxy_protocol: bool,
    #[serde(default)]
    pub trusted_headers: Vec<String>,
    #[serde(default)]
    pub healthcheck: Option<String>,
    // Table configs
    pub egress: EgressSettings,
    pub scaling: Option<ScalingSettings>,
    pub signing: Option<SigningInfo>,
    pub attestation: Option<EIFMeasurements>,
}

// This type exists only to read V0 tomls and migrate to V1
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EnclaveConfigV0 {
    pub name: String,
    pub uuid: Option<String>,
    pub app_uuid: Option<String>,
    pub team_uuid: Option<String>,
    pub debug: bool,
    pub dockerfile: String,
    pub api_key_auth: bool,
    pub trx_logging: bool,
    pub disable_tls_termination: bool,
    #[serde(default)]
    pub forward_proxy_protocol: bool,
    #[serde(default)]
    pub trusted_headers: Vec<String>,
    #[serde(default)]
    pub healthcheck: Option<String>,
    // Table configs
    pub egress: EgressSettings,
    pub scaling: Option<ScalingSettings>,
    pub signing: Option<SigningInfo>,
    pub attestation: Option<EIFMeasurements>,
}

impl std::convert::From<EnclaveConfigV0> for EnclaveConfig {
    fn from(value: EnclaveConfigV0) -> Self {
        EnclaveConfig {
            name: value.name,
            uuid: value.uuid,
            app_uuid: value.app_uuid,
            version: 1,
            team_uuid: value.team_uuid,
            debug: value.debug,
            dockerfile: value.dockerfile,
            api_key_auth: value.api_key_auth,
            trx_logging: value.trx_logging,
            tls_termination: !value.disable_tls_termination,
            forward_proxy_protocol: value.forward_proxy_protocol,
            trusted_headers: value.trusted_headers,
            healthcheck: value.healthcheck,
            egress: value.egress,
            scaling: value.scaling,
            signing: value.signing,
            attestation: value.attestation,
        }
    }
}

impl EnclaveConfig {
    pub fn annotate(&mut self, enclave: crate::api::enclave::Enclave) {
        self.uuid = Some(enclave.uuid().into());
        self.app_uuid = Some(enclave.app_uuid().into());
        self.team_uuid = Some(enclave.team_uuid().into());
    }
}

impl std::convert::AsRef<EnclaveConfig> for EnclaveConfig {
    fn as_ref(&self) -> &Self {
        self
    }
}

// Helper type to guarantee the presence of fields when combining multiple config sources
#[derive(Clone, Debug)]
pub struct ValidatedEnclaveBuildConfig {
    pub version: u8,
    pub enclave_name: String,
    pub enclave_uuid: String,
    pub app_uuid: String,
    pub team_uuid: String,
    pub debug: bool,
    pub dockerfile: String,
    pub egress: EgressSettings,
    pub scaling: Option<ScalingSettings>,
    pub signing: ValidatedSigningInfo,
    pub attestation: Option<EIFMeasurements>,
    pub tls_termination: bool,
    pub api_key_auth: bool,
    pub trx_logging_enabled: bool,
    pub forward_proxy_protocol: bool,
    pub trusted_headers: Vec<String>,
    pub healthcheck: Option<String>,
}

impl ValidatedEnclaveBuildConfig {
    pub fn signing_info(&self) -> &ValidatedSigningInfo {
        &self.signing
    }

    pub fn dockerfile(&self) -> &str {
        &self.dockerfile
    }

    pub fn egress(&self) -> &EgressSettings {
        &self.egress
    }

    pub fn enclave_name(&self) -> &str {
        &self.enclave_name
    }

    pub fn enclave_uuid(&self) -> &str {
        &self.enclave_uuid
    }

    pub fn app_uuid(&self) -> &str {
        &self.app_uuid
    }

    pub fn team_uuid(&self) -> &str {
        &self.team_uuid
    }

    pub fn tls_termination(&self) -> bool {
        self.tls_termination
    }

    pub fn get_dataplane_feature_label(&self) -> String {
        let egress_label = if self.egress.is_enabled() {
            "egress-enabled"
        } else {
            "egress-disabled"
        };
        let tls_label = if self.tls_termination {
            "tls-termination-enabled"
        } else {
            "tls-termination-disabled"
        };
        format!("{egress_label}/{tls_label}")
    }

    pub fn api_key_auth(&self) -> bool {
        self.api_key_auth
    }

    pub fn trx_logging_enabled(&self) -> bool {
        self.trx_logging_enabled
    }

    pub fn forward_proxy_protocol(&self) -> bool {
        self.forward_proxy_protocol
    }

    pub fn trusted_headers(&self) -> &[String] {
        &self.trusted_headers
    }

    pub fn healthcheck(&self) -> Option<&str> {
        self.healthcheck.as_deref()
    }
}

impl EnclaveConfig {
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
        let mut info = self.signing.clone().unwrap_or_default();
        info.cert = Some(cert);
        self.signing = Some(info);
    }

    pub fn key(&self) -> Option<&str> {
        self.signing
            .as_ref()
            .and_then(|signing_info| signing_info.key.as_deref())
    }

    pub fn set_key(&mut self, key: String) {
        let mut info = self.signing.clone().unwrap_or_default();
        info.key = Some(key);
        self.signing = Some(info);
    }

    pub fn set_attestation(&mut self, measurements: &EIFMeasurements) {
        self.attestation = Some(measurements.clone());
    }

    pub fn set_scaling_config(&mut self, scaling_info: ScalingSettings) {
        self.scaling = Some(scaling_info);
    }

    pub fn try_from_filepath(path: &str) -> Result<Self, EnclaveConfigError> {
        let config_path = std::path::Path::new(path);
        if !config_path.exists() {
            return Err(EnclaveConfigError::MissingConfigFile(path.to_string()));
        }

        let enclave_config_content = std::fs::read(config_path)?;
        Ok(toml::de::from_slice(enclave_config_content.as_slice())?)
    }

    pub fn get_enclave_domain(&self) -> Result<String, EnclaveConfigError> {
        if self.uuid.is_none() {
            return Err(EnclaveConfigError::MissingField("enclave_uuid".to_string()));
        }
        let base_domain = if std::env::var("EV_DOMAIN")
            .unwrap_or_else(|_| String::from("evervault.com"))
            == "evervault.io"
        {
            "evervault.dev"
        } else {
            "evervault.com"
        };

        Ok(format!(
            "{}.{}.enclave.{}",
            self.name(),
            self.app_uuid
                .as_ref()
                .map(|uuid| uuid.replace('_', "-"))
                .ok_or_else(|| EnclaveConfigError::MissingField("app_uuid".to_string()))?,
            base_domain
        ))
    }

    pub fn get_attestation(&self) -> Result<&EIFMeasurements, EnclaveConfigError> {
        self.attestation
            .as_ref()
            .ok_or_else(|| EnclaveConfigError::MissingField("attestation".to_string()))
    }
}

impl std::convert::TryFrom<&EnclaveConfig> for ValidatedEnclaveBuildConfig {
    type Error = EnclaveConfigError;

    fn try_from(config: &EnclaveConfig) -> Result<Self, Self::Error> {
        let signing_info = config
            .signing
            .as_ref()
            .ok_or(SigningInfoError::NoSigningInfoGiven)?;

        let app_uuid = config
            .app_uuid
            .clone()
            .ok_or_else(|| EnclaveConfigError::MissingField("App uuid".into()))?;
        let enclave_uuid = config
            .uuid
            .clone()
            .ok_or_else(|| EnclaveConfigError::MissingField("Enclave uuid".into()))?;
        let team_uuid = config
            .team_uuid
            .clone()
            .ok_or_else(|| EnclaveConfigError::MissingField("Team uuid".into()))?;

        let trx_logging_enabled = match (config.trx_logging, config.tls_termination) {
            (false, _) => Ok(false), // (logging disabled, _) = logging disabled
            (true, false) => Err(EnclaveConfigError::LoggingEnabledWithoutTLSTermination()), // (logging enabled, tls_termination disabled) = config error (Tls termination needed for logging)
            (true, true) => Ok(true), // (logging enabled, tls_termination enabled) = logging enabled
        }?;

        let scaling_settings = config.scaling.clone();

        Ok(ValidatedEnclaveBuildConfig {
            version: config.version,
            enclave_uuid,
            app_uuid,
            team_uuid,
            enclave_name: config.name.clone(),
            debug: config.debug,
            dockerfile: config.dockerfile.clone(),
            egress: config.egress.clone(),
            signing: signing_info.try_into()?,
            scaling: scaling_settings,
            attestation: config.attestation.clone(),
            tls_termination: config.tls_termination,
            api_key_auth: config.api_key_auth,
            trx_logging_enabled,
            forward_proxy_protocol: config.forward_proxy_protocol,
            trusted_headers: config.trusted_headers.clone(),
            healthcheck: config.healthcheck.clone(),
        })
    }
}

/// Helper trait for allowing command line args to override a deserialized config
pub trait BuildTimeConfig {
    fn certificate(&self) -> Option<&str> {
        None
    }
    fn dockerfile(&self) -> Option<&str> {
        None
    }
    fn private_key(&self) -> Option<&str> {
        None
    }

    // Return new copy of config to prevent args being written to toml file in err
    fn merge_with_config(&self, config: &EnclaveConfig) -> EnclaveConfig {
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

impl BuildTimeConfig for () {}

// Return both config read directly from FS as well as merged & validated config
pub fn read_and_validate_config<B: BuildTimeConfig>(
    config_path: &str,
    args: &B,
) -> Result<(EnclaveConfig, ValidatedEnclaveBuildConfig), EnclaveConfigError> {
    let enclave_config = EnclaveConfig::try_from_filepath(config_path)?;
    let merged_config = args.merge_with_config(&enclave_config);
    let validated_config: ValidatedEnclaveBuildConfig = merged_config.as_ref().try_into()?;

    Ok((enclave_config, validated_config))
}

#[cfg(test)]
mod test {
    use super::{BuildTimeConfig, EnclaveConfig};

    struct ExampleArgs {
        cert: String,
        dockerfile: String,
        pk: String,
    }

    impl BuildTimeConfig for ExampleArgs {
        fn certificate(&self) -> Option<&str> {
            Some(self.cert.as_str())
        }

        fn dockerfile(&self) -> Option<&str> {
            Some(self.dockerfile.as_str())
        }

        fn private_key(&self) -> Option<&str> {
            Some(self.pk.as_str())
        }
    }

    #[test]
    fn merge_args_with_config() {
        let config = EnclaveConfig {
            version: 1,
            name: "Enclave123".to_string(),
            uuid: Some("abcdef123".to_string()),
            app_uuid: Some("abcdef321".to_string()),
            team_uuid: Some("team_abcdef456".to_string()),
            debug: false,
            dockerfile: "./Dockerfile.config".to_string(),
            tls_termination: true,
            egress: super::EgressSettings {
                enabled: false,
                destinations: None,
            },
            scaling: Some(super::ScalingSettings {
                desired_replicas: 2,
            }),
            signing: None,
            attestation: None,
            api_key_auth: true,
            trx_logging: true,
            forward_proxy_protocol: false,
            runtime: None,
            trusted_headers: vec![],
            healthcheck: Some("/health".to_string()),
        };

        let test_args = ExampleArgs {
            cert: "args-cert.pem".to_string(),
            dockerfile: "./Dockerfile.args".to_string(),
            pk: "pk.pem".to_string(),
        };

        let merged = test_args.merge_with_config(&config);
        assert!(merged.signing.is_some());
        assert_eq!(merged.dockerfile(), test_args.dockerfile().unwrap());
        assert_eq!(merged.cert().unwrap(), test_args.certificate().unwrap());
        assert_eq!(merged.key().unwrap(), test_args.private_key().unwrap());
    }
}
