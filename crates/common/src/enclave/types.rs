use serde::{Deserialize, Serialize};
use std::path::PathBuf;

// Tracking which FS elements have been created during signing
#[derive(Debug, PartialEq)]
pub enum CleanUpMode {
    Directory,
    AllContents,
    Cert,
    Key,
    None,
}

impl CleanUpMode {
    pub fn enable_directory(&mut self) {
        *self = Self::Directory;
    }

    pub fn enable_cert(&mut self) {
        if !self.is_directory() {
            if self.is_key() {
                *self = Self::AllContents;
            } else {
                *self = Self::Cert;
            }
        }
    }

    pub fn enable_key(&mut self) {
        if !self.is_directory() {
            if self.is_cert() {
                *self = Self::AllContents;
            } else {
                *self = Self::Key;
            }
        }
    }

    pub fn is_directory(&self) -> bool {
        matches!(self, Self::Directory)
    }

    pub fn is_key(&self) -> bool {
        matches!(self, Self::Key)
    }

    pub fn is_cert(&self) -> bool {
        matches!(self, Self::Cert)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AttestationCors {
    pub origin: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EIFMeasurements {
    #[serde(rename = "HashAlgorithm")]
    hash_algorithm: String,
    #[serde(flatten)] // serialize as though these are attribtues on this struct
    pcrs: PCRs,
    #[serde(skip_serializing_if = "Option::is_none")] // custom signature field
    signature: Option<String>,
}

impl EIFMeasurements {
    pub fn pcrs(&self) -> &PCRs {
        &self.pcrs
    }

    pub fn set_signature(&mut self, signature: String) {
        self.signature = Some(signature);
    }

    pub fn signature(&self) -> Option<&str> {
        self.signature.as_deref()
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

#[cfg(feature = "pcr_signature")]
impl pcr_sign::PCRProvider for PCRs {
    fn pcr0(&self) -> &str {
        &self.pcr0
    }

    fn pcr1(&self) -> &str {
        &self.pcr1
    }

    fn pcr2(&self) -> &str {
        &self.pcr2
    }

    fn pcr8(&self) -> &str {
        self.pcr8
            .as_deref()
            .expect("Failed to access PCR8 on built enclave. Required for PCRs to be signed.")
    }
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

    pub fn measurements_mut(&mut self) -> &mut EIFMeasurements {
        &mut self.measurements
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
