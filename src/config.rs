use super::enclave::EIFMeasurements;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EgressSettings {
    pub enabled: bool,
    pub destinations: Option<Vec<String>>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SigningInfo {
    #[serde(rename = "certPath")]
    pub cert: Option<String>,
    #[serde(rename = "keyPath")]
    pub key: Option<String>,
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
