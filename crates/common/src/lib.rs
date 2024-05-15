pub mod api;
pub mod enclave;
pub mod relay;
pub trait CliError {
    fn exitcode(&self) -> exitcode::ExitCode;
}
