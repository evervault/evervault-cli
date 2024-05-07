pub mod api;
pub mod enclave;

pub trait CliError {
    fn exitcode(&self) -> exitcode::ExitCode;
}
