use crate::common::CliError;
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
}

impl CliError for CertError {
    fn exitcode(&self) -> exitcode::ExitCode {
        match self {
            Self::OutputPathDoesNotExist => exitcode::NOINPUT,
            Self::FileWriteError(_) => exitcode::IOERR,
            Self::CertSerializationError(_) => exitcode::SOFTWARE,
            Self::InvalidCertSubjectProvided => exitcode::DATAERR,
        }
    }
}
