use crate::enclave::{common::CliError, docker::error::CommandError};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ErrorKind {
    #[error("Docker exited with code {0}")]
    BuildError(i32),
    #[error("An error occurred while deserializing.")]
    DeserializeError(serde_json::error::Error),
    #[error(transparent)]
    DockerError(CommandError),
    #[error("An error occurred while interacting with the file system")]
    FsError(Option<std::io::Error>),
}

impl CliError for ErrorKind {
    fn exitcode(&self) -> exitcode::ExitCode {
        match self {
            Self::BuildError(inner) => *inner,
            Self::DeserializeError(_) => exitcode::IOERR,
            Self::DockerError(inner) => inner.exitcode(),
            Self::FsError(_) => exitcode::IOERR,
        }
    }
}

#[derive(Debug, Error)]
pub struct EnclaveError {
    #[source]
    kind: ErrorKind,
    context: Option<String>,
}

impl EnclaveError {
    pub fn context(mut self, context_msg: impl Into<String>) -> Self {
        self.context = Some(context_msg.into());
        self
    }

    pub fn new_build_error(code: i32) -> Self {
        Self {
            kind: ErrorKind::BuildError(code),
            context: None,
        }
    }

    pub fn new_fs_error() -> Self {
        Self {
            kind: ErrorKind::FsError(None),
            context: None,
        }
    }
}

impl std::fmt::Display for EnclaveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let error_msg = self.kind.to_string();
        write!(
            f,
            "{}",
            match self.context.as_deref() {
                Some(context) => format!("{context}\n{error_msg}"),
                None => error_msg,
            }
        )
    }
}

impl CliError for EnclaveError {
    fn exitcode(&self) -> exitcode::ExitCode {
        self.kind.exitcode()
    }
}

impl std::convert::From<std::io::Error> for EnclaveError {
    fn from(err: std::io::Error) -> Self {
        Self {
            kind: ErrorKind::FsError(Some(err)),
            context: None,
        }
    }
}

impl std::convert::From<CommandError> for EnclaveError {
    fn from(cmd_err: CommandError) -> Self {
        Self {
            kind: ErrorKind::DockerError(cmd_err),
            context: None,
        }
    }
}

impl std::convert::From<serde_json::error::Error> for EnclaveError {
    fn from(serde_err: serde_json::error::Error) -> Self {
        Self {
            kind: ErrorKind::DeserializeError(serde_err),
            context: None,
        }
    }
}

#[macro_export]
macro_rules! add_context_and_exit {
    ($result_expr:expr, $context:literal) => {
        match $result_expr {
            Ok(result) => result,
            Err(e) => return Err(EnclaveError::from(e).context($context)),
        }
    };
    ($result_ident:ident, $context:literal) => {
        match $result_ident {
            Ok(result) => result,
            Err(e) => return Err(EnclaveError::from(e).context($context)),
        }
    };
}
