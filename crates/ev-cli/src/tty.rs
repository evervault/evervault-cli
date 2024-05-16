use atty::Stream;

#[derive(Debug)]
pub struct AttyReport {
    pub stdout: bool,
    pub stderr: bool,
    pub stdin: bool,
}

impl AttyReport {
    fn is_stdout_atty() -> bool {
        atty::is(Stream::Stdout)
    }

    fn is_stderr_atty() -> bool {
        atty::is(Stream::Stderr)
    }

    fn is_stdin_atty() -> bool {
        atty::is(Stream::Stdin)
    }
}

impl Default for AttyReport {
    fn default() -> Self {
        Self {
            stdout: Self::is_stdout_atty(),
            stderr: Self::is_stderr_atty(),
            stdin: Self::is_stdin_atty(),
        }
    }
}
