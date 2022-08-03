use super::enclave::EIFMeasurements;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EgressSettings {
    pub enabled: bool,
    pub destinations: Option<Vec<String>>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CageConfig {
    pub name: String,
    pub debug: bool,
    pub egress: EgressSettings,
    pub attestation: Option<EIFMeasurements>,
}
