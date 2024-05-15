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

// pub fn get_sentry_client() -> Option<sentry::ClientInitGuard> {
//     if cfg!(not(debug_assertions)) {
//         let sentry_client = sentry::init((
//             "https://7930c2e61c1642bca8518bdadf37b78b@o359326.ingest.sentry.io/5799012",
//             sentry::ClientOptions {
//                 release: sentry::release_name!(),
//                 ..Default::default()
//             },
//         ));
//         Some(sentry_client)
//     } else {
//         None
//     }
// }
