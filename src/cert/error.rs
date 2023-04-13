use crate::{common::CliError, docker::error::DockerError, enclave::error::EnclaveError};
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
    #[error("Failed to generate PCR8 from signing cert — {0}")]
    DockerError(#[from] DockerError),
    #[error(transparent)]
    EnclaveError(#[from] EnclaveError),
    #[error("An error contacting the API — {0}")]
    ApiError(#[from] crate::api::client::ApiError),
}

impl CliError for CertError {
    fn exitcode(&self) -> exitcode::ExitCode {
        match self {
            Self::OutputPathDoesNotExist => exitcode::NOINPUT,
            Self::FileWriteError(_) => exitcode::IOERR,
            Self::CertSerializationError(_) => exitcode::SOFTWARE,
            Self::InvalidCertSubjectProvided
            | Self::PEMError(_)
            | Self::X509Error(_)
            | Self::CertHasExpired
            | Self::CertNotYetValid
            | Self::InvalidDate
            | Self::CertPathDoesNotExist(_) => exitcode::DATAERR,
            Self::DockerError(_) => exitcode::UNAVAILABLE,
            Self::EnclaveError(inner) => inner.exitcode(),
            Self::ApiError(inner) => inner.exitcode(),
        }
    }
}
