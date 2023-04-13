use serde::{Deserialize, Serialize};
use std::path::PathBuf;

// Tracking which FS elements have been created during signing
#[derive(Debug, PartialEq)]
pub(super) enum CleanUpMode {
    Directory,
    AllContents,
    Cert,
    Key,
    None,
}

impl CleanUpMode {
    pub(super) fn enable_directory(&mut self) {
        *self = Self::Directory;
    }

    pub(super) fn enable_cert(&mut self) {
        if !self.is_directory() {
            if self.is_key() {
                *self = Self::AllContents;
            } else {
                *self = Self::Cert;
            }
        }
    }

    pub(super) fn enable_key(&mut self) {
        if !self.is_directory() {
            if self.is_cert() {
                *self = Self::AllContents;
            } else {
                *self = Self::Key;
            }
        }
    }

    pub(super) fn is_directory(&self) -> bool {
        matches!(self, Self::Directory)
    }

    pub(super) fn is_key(&self) -> bool {
        matches!(self, Self::Key)
    }

    pub(super) fn is_cert(&self) -> bool {
        matches!(self, Self::Cert)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EIFMeasurements {
    #[serde(rename = "HashAlgorithm")]
    hash_algorithm: String,
    #[serde(flatten)] // serialize as though these are attribtues on this struct
    pcrs: PCRs,
}

impl EIFMeasurements {
    pub fn pcrs(&self) -> &PCRs {
        &self.pcrs
    }
}

// Isolated PCRs from remainder of the measures to use in API requests
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct PCRs {
    #[serde(rename = "PCR0")]
    pub pcr0: String,
    #[serde(rename = "PCR1")]
    pub pcr1: String,
    #[serde(rename = "PCR2")]
    pub pcr2: String,
    #[serde(rename = "PCR8")]
    pub pcr8: Option<String>,
}

// Struct for deserializing the output from the nitro cli
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct EnclaveBuildOutput {
    pub measurements: EIFMeasurements,
}

impl EnclaveBuildOutput {
    pub fn measurements(&self) -> &EIFMeasurements {
        &self.measurements
    }
}

#[derive(Debug)]
pub struct BuiltEnclave {
    measurements: EIFMeasurements,
    location: PathBuf,
}

impl BuiltEnclave {
    pub fn new(measurements: EIFMeasurements, location: std::path::PathBuf) -> Self {
        Self {
            measurements,
            location,
        }
    }

    pub fn measurements(&self) -> &EIFMeasurements {
        &self.measurements
    }

    pub fn location(&self) -> &std::path::Path {
        &self.location
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct DescribeEif {
    #[serde(flatten)]
    pub measurements: EnclaveBuildOutput,
    is_signed: bool,
    signing_certificate: EnclaveSigningCertificate,
    signature_check: bool,
    metadata: EnclaveMetadata,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CertPCR {
    #[serde(rename = "PCR8")]
    pub pcr8: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct EnclaveSigningCertificate {
    issuer_name: EnclaveSigningCertificateIssuer,
    algorithm: String,
    not_before: String,
    not_after: String,
    signature: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EnclaveSigningCertificateIssuer {
    common_name: String,
    country_name: String,
    locality_name: String,
    organization_name: String,
    organizational_unit_name: String,
    state_or_province_name: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct EnclaveMetadata {
    build_time: String,
}
