use atty::Stream;
use indicatif::{ProgressBar, ProgressStyle};

use crate::api::cage::CagesClient;
use crate::common::CliError;

fn get_progress_bar(start_msg: &str, upload_len: Option<u64>) -> ProgressBar {
     match upload_len {
        Some(len) => {
            let progress_bar = ProgressBar::new(len);
            progress_bar.set_style(ProgressStyle::default_bar()
            .template("Uploading Cage to Evervault {bar:40.green/blue} {bytes} ({percent}%) [{elapsed_precise}]")
            .expect("Failed to create progress bar template from hardcoded template")
            .progress_chars("##-"));
            progress_bar
        }
        None => {
            let progress_bar = ProgressBar::new_spinner();
            progress_bar.enable_steady_tick(std::time::Duration::from_millis(80));
            progress_bar.set_style(
                ProgressStyle::default_spinner()
                    .tick_strings(&["⣾", "⣽", "⣻", "⢿", "⡿", "⣟", "⣯", "⣷"])
                    .template("{spinner:.green} {msg}")
                    .expect("Failed to create progress bar template from hardcoded template"),
            );
            progress_bar.set_message(start_msg.to_string());
            progress_bar
        }
    }
}

#[derive(Clone)]
struct Tty {
    progress_bar: ProgressBar,
}
#[derive(Clone)]
struct NonTty {}

impl<'a, W: ProgressLogger + ?Sized + 'a> ProgressLogger for Box<W> {
    fn set_message(&self, message: &str) {
        (**self).set_message(message)
    }
    fn finish_with_message(&self, message: &str) {
        (**self).finish_with_message(message)
    }

    fn finish(&self) {
        (**self).finish()
    }

    fn set_position(&self, bytes: u64) {
        (**self).set_position(bytes)
    }
}
pub trait ProgressLogger {
    fn set_message(&self, message: &str);
    fn finish_with_message(&self, message: &str);
    fn set_position(&self, bytes: u64);
    fn finish(&self);
}

impl ProgressLogger for Tty {
    fn set_message(&self, message: &str) {
        self.progress_bar.set_message(message.to_string());
    }
    fn finish_with_message(&self, message: &str) {
        self.progress_bar.finish_and_clear();
        log::info!("{message}");
    }
    fn finish(&self) {
        self.progress_bar.finish();
    }

    fn set_position(&self, bytes: u64) {
        self.progress_bar.set_position(bytes);
    }
}

impl ProgressLogger for NonTty {
    fn set_message(&self, message: &str) {
        log::info!("{message}")
    }
    fn finish_with_message(&self, message: &str) {
        log::info!("{message}")
    }
    fn finish(&self) {
        // no op
    }

    fn set_position(&self, _bytes: u64) {
        // no op
    }
}

pub fn get_tracker(
    first_message: &str,
    upload_len: Option<u64>,
) -> Box<dyn ProgressLogger + Send + Sync> {
    if atty::is(Stream::Stdout) {
        let progress_bar = get_progress_bar(first_message, upload_len);
        Box::new(Tty { progress_bar })
    } else {
        log::info!("{}", first_message);
        Box::new(NonTty {})
    }
}

#[derive(Clone, Debug, PartialEq, PartialOrd)]
pub enum StatusReport {
    Update(String),
    Complete(String),
    NoOp,
    Failed,
}

impl StatusReport {
    pub fn update(msg: String) -> Self {
        Self::Update(msg)
    }

    pub fn complete(msg: String) -> Self {
        Self::Complete(msg)
    }

    pub fn no_op() -> Self {
        Self::NoOp
    }

    pub fn get_msg(&self) -> Option<String> {
        match self {
            Self::Update(msg) | Self::Complete(msg) => Some(msg.clone()),
            _ => None,
        }
    }
}

// It should be possible to resolve the lifetimes to allow this work over borrows for every value instead of cloning/heap allocating
pub async fn poll_fn_and_report_status<E, F, Fut>(
    api_client: CagesClient,
    poll_args: Vec<String>,
    poll_fn: F,
    progress_bar: impl ProgressLogger,
) -> Result<(), E>
where
    E: CliError,
    F: Fn(CagesClient, Vec<String>) -> Fut,
    Fut: std::future::Future<Output = Result<StatusReport, E>>,
{
    let mut most_recent_update: Option<String> = None;
    let is_new_update = |current_status: Option<&str>, new_msg: &str| -> bool {
        current_status
            .map(|given_msg| given_msg != new_msg)
            .unwrap_or(true)
    };
    loop {
        match poll_fn(api_client.clone(), poll_args.clone()).await {
            Ok(StatusReport::Update(msg)) => {
                if is_new_update(most_recent_update.as_deref(), msg.as_str()) {
                    progress_bar.set_message(&msg);
                    most_recent_update = Some(msg);
                }
            }
            Ok(StatusReport::Complete(msg)) => {
                progress_bar.finish_with_message(&msg);
                return Ok(());
            }
            Ok(StatusReport::Failed) => {
                progress_bar.finish();
                return Ok(());
            }
            Ok(StatusReport::NoOp) => {}
            Err(e) => {
                progress_bar.finish();
                return Err(e);
            }
        };
        tokio::time::sleep(std::time::Duration::from_millis(6000)).await;
    }
}
