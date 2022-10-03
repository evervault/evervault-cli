use atty::Stream;
use indicatif::{ProgressBar, ProgressStyle};

fn get_progress_bar(start_msg: &str, upload_len: Option<u64>) -> ProgressBar {
    let bar = match upload_len {
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
                    .tick_strings(&["⣾", "⣽", "⣻", "⢿", "⡿", "⣟", "⣯", "⣷", "[INFO]"])
                    .template("{spinner:.green} {msg}")
                    .expect("Failed to create progress bar template from hardcoded template"),
            );
            progress_bar.set_message(start_msg.to_string());
            progress_bar
        }
    };
    bar
}

struct Tty {
    progress_bar: ProgressBar,
}
struct NonTty {}

impl<'a, W: ProgressLogger + ?Sized + 'a> ProgressLogger for Box<W> {
    fn update_progress(&self, message: &str) -> () {
        (**self).update_progress(message)
    }
    fn finish_with_message(&self, message: &'static str) -> () {
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
    fn update_progress(&self, message: &str);
    fn finish_with_message(&self, message: &'static str);
    fn set_position(&self, bytes: u64);
    fn finish(&self);
}

impl ProgressLogger for Tty {
    fn update_progress(&self, message: &str) {
        self.progress_bar.set_message(message.to_string());
    }
    fn finish_with_message(&self, message: &'static str) -> () {
        self.progress_bar.finish_with_message(message)
    }
    fn finish(&self) -> () {
        self.progress_bar.finish();
    }

    fn set_position(&self, bytes: u64) {
        self.progress_bar.set_position(bytes);
    }
}

impl ProgressLogger for NonTty {
    fn update_progress(&self, message: &str) {
        log::info!("{}", message.to_string())
    }
    fn finish_with_message(&self, message: &'static str) {
        log::info!("{}", message.to_string())
    }
    fn finish(&self) -> () {
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
