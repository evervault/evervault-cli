use super::parse::DecodeError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum DockerError {
    #[error("{0}")]
    ParserDecodeError(#[from] DecodeError),
    #[error("Failed to access the docker daemon — {0:?}")]
    DaemonAccessError(#[from] std::io::Error),
    #[error("Docker daemon is not running")]
    DaemonNotRunning,
    #[error("Restricted port exposed. Cannot forward traffic to :{0}, address is already in use.")]
    RestrictedPortExposed(u16),
}
