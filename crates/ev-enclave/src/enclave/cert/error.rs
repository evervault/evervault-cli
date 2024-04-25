use crate::enclave::common::CliError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CertError {
    #[error("The specified output path does not exist.")]
    OutputPathDoesNotExist,
    #[error("An error occurred while writing your cert to the file system - {0:?}")]
    FileWriteError(#[from] std::io::Error),
    #[error("An error occurred while serializing your cert - {0:?}")]
    CertSerializationError(#[from] rcgen::RcgenError),
    #[error("Failed to parse the subject provided")]
    InvalidCertSubjectProvided,
    #[error("Failed to parse the PEM file")]
    PEMError(#[from] x509_parser::nom::Err<x509_parser::prelude::PEMError>),
    #[error("Failed to parse the X509 certificate")]
    X509Error(#[from] x509_parser::nom::Err<x509_parser::prelude::X509Error>),
    #[error("The cert has expired")]
    CertHasExpired,
    #[error("The cert is not yet valid")]
    CertNotYetValid,
    #[error("Invalid date")]
    InvalidDate,
    #[error("The specificied cert path does not exist: {0:?}")]
    CertPathDoesNotExist(std::path::PathBuf),
    #[error("An error occurred contacting the API — {0}")]
    ApiError(#[from] crate::enclave::api::client::ApiError),
    #[error("An error occurred calculating the hash of the cert — {0}")]
    HashError(String),
    #[error("Failed to parse timestamp")]
    TimstampParseError(#[from] chrono::ParseError),
    #[error("No certs found for the current Enclave.")]
    NoCertsFound,
}

impl CliError for CertError {
    fn exitcode(&self) -> exitcode::ExitCode {
        match self {
            Self::OutputPathDoesNotExist => exitcode::NOINPUT,
            Self::FileWriteError(_) => exitcode::IOERR,
            Self::CertSerializationError(_) | Self::HashError(_) => exitcode::SOFTWARE,
            Self::InvalidCertSubjectProvided
            | Self::PEMError(_)
            | Self::X509Error(_)
            | Self::CertHasExpired
            | Self::CertNotYetValid
            | Self::InvalidDate
            | Self::CertPathDoesNotExist(_)
            | Self::TimstampParseError(_) => exitcode::DATAERR,
            Self::ApiError(inner) => inner.exitcode(),
            Self::NoCertsFound => exitcode::USAGE,
        }
    }
}
