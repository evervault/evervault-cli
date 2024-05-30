use crate::theme::CliTheme;
use dialoguer::{Input, Select};
use indicatif::{ProgressBar, ProgressStyle};

use self::validators::ValidationError;

pub mod validators {
    use lazy_static;
    use regex::Regex;
    use std::fmt::Debug;
    use thiserror::Error;

    #[derive(Debug, Error)]
    pub enum ValidationError {
        #[error("Value must be a valid HTTPS domain")]
        InvalidHostname,
        #[error("Invalid custom domain. You should not use a top-level domain name, or include a protocol or path")]
        InvalidCustomDomain,
        #[error("Destination Domain must be a valid hostname and not contain a protocol or path.")]
        InvalidDestinationDomain,
        #[error("Invalid function name. Must be between 2 and 40 characters, and contain only alphanumeric characters, dashes, and underscores")]
        InvalidFunctionName,
        #[error("Invalid function language. Must be one of: (node|python)@version. eg node@18, python@3.11. See https://docs.evervault.com/primitives/functions#function.toml for supported language versions.")]
        InvalidFunctionLanguage,
    }

    pub type GenericValidator = dyn Fn(&String) -> Result<(), ValidationError>;
    pub fn validate_hostname(input: &String) -> Result<(), ValidationError> {
        lazy_static::lazy_static!(
            static ref VALID_HOST_REGEX: Regex = Regex::new(
                r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$|^(https://)?(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)+([A-Za-z]|[A-Za-z][A-Za-z0-9\-]*[A-Za-z0-9])$"
            ).unwrap();
        );
        match VALID_HOST_REGEX.is_match(input) {
            true => Ok(()),
            _ => Err(ValidationError::InvalidHostname),
        }
    }

    pub fn validate_custom_domain(input: &String) -> Result<(), ValidationError> {
        lazy_static::lazy_static!(
            static ref VALID_CUSTOM_DOMAIN_REGEX: Regex = Regex::new(
                // top-level domains not supported
                r"(?i)^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$|^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9])\.){2,}([A-Za-z]|[A-Za-z][A-Za-z0-9-]*[A-Za-z0-9])$"
            ).unwrap();
        );
        match VALID_CUSTOM_DOMAIN_REGEX.is_match(input) {
            true => Ok(()),
            _ => Err(ValidationError::InvalidCustomDomain),
        }
    }

    pub fn validate_destination_domain(input: &String) -> Result<(), ValidationError> {
        lazy_static::lazy_static!(
            static ref VALID_DESTINATION_DOMAIN_REGEX: Regex = Regex::new(
              r"/^(?:(?:\*?(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|\*\*?)\.){3}(?:\*?(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|\*\*?)$|^(?:(?:\*?(?:[a-z0-9]|[a-z0-9][a-z0-9\-]*[a-z0-9])|\*\*?)\.)+(?:\*?(?:[a-z]|[a-z][a-z0-9\-]*[a-z0-9])|\*\*?)$|^\*\*?$/i"
            ).unwrap();
        );

        match VALID_DESTINATION_DOMAIN_REGEX.is_match(input) {
            true => Ok(()),
            _ => Err(ValidationError::InvalidDestinationDomain),
        }
    }

    pub fn validate_function_name(name: &String) -> Result<(), ValidationError> {
        lazy_static::lazy_static!(
            static ref NAME_REGEX: Regex = Regex::new(r"^[A-Za-z0-9]([-_]?[A-Za-z0-9])*$").unwrap();
        );
        let length = name.len();
        let regex_result = NAME_REGEX.is_match(name);
        if !((length >= 2) & (length <= 40) & regex_result) {
            return Err(ValidationError::InvalidFunctionName);
        }
        Ok(())
    }

    pub fn validate_function_language(language: &String) -> Result<(), ValidationError> {
        lazy_static::lazy_static!(
            static ref LANGUAGE_REGEX: Regex = Regex::new(r"\b(?:node|python)@\d+(\.\d+)?\b").unwrap();
        );
        let regex_result = LANGUAGE_REGEX.is_match(language);
        if !regex_result {
            return Err(ValidationError::InvalidFunctionLanguage);
        }

        Ok(())
    }
}

pub fn input<T>(prompt: T, allow_empty: bool) -> String
where
    T: std::fmt::Display,
{
    let theme = CliTheme::default();
    let mut input: Input<String> = Input::with_theme(&theme);

    match input
        .with_prompt(prompt.to_string())
        .allow_empty(allow_empty)
        .interact()
    {
        Ok(input) => input,
        Err(e) => {
            eprintln!("Error reading user input : {}", e);
            std::process::exit(1);
        }
    }
}

pub fn validated_input<T>(
    prompt: T,
    allow_empty: bool,
    validator: Box<validators::GenericValidator>,
) -> Result<String, std::io::Error>
where
    T: std::fmt::Display,
{
    let theme = CliTheme::default();
    let mut input: Input<String> = Input::with_theme(&theme);

    input
        .with_prompt(prompt.to_string())
        .allow_empty(allow_empty)
        .validate_with(validator)
        .interact()
}

pub fn select<T>(options: &Vec<String>, default: usize, prompt: T) -> Option<usize>
where
    T: std::fmt::Display,
{
    let theme = CliTheme::default();
    let mut select_obj = Select::with_theme(&theme);
    select_obj.with_prompt(prompt.to_string());
    select_obj.items(options).default(default).interact().ok()
}

pub fn preset_input<S, T>(prompt: S, preset: T) -> Option<String>
where
    S: std::fmt::Display,
    T: std::fmt::Display,
{
    let theme = CliTheme::default();
    let mut input: Input<String> = Input::with_theme(&theme);

    input
        .with_prompt(prompt.to_string())
        .default(preset.to_string())
        .interact()
        .ok()
}

/// To make quiet mode integration more simple
/// OptionalProgressBar can be used - all functions called
/// as normal, but will result in No-Ops during quiet mode
///
/// There may be an argument for implementing this using Deref
/// To coerce OptPB to a PB silently, but unsure
pub struct OptionalProgressBar {
    bar: Option<ProgressBar>,
}

impl OptionalProgressBar {
    pub fn new_spinner(quiet: bool) -> Self {
        Self {
            bar: quiet.then(ProgressBar::new_spinner),
        }
    }

    pub fn enable_steady_tick(&self, ms: core::time::Duration) {
        if let Some(pb) = self.bar.as_ref() {
            pb.enable_steady_tick(ms)
        }
    }

    pub fn finish_with_message(&self, msg: String) {
        if let Some(pb) = self.bar.as_ref() {
            pb.finish_with_message(msg);
        }
    }

    pub fn set_style(&self, style: ProgressStyle) {
        if let Some(pb) = self.bar.as_ref() {
            pb.set_style(style)
        }
    }

    pub fn set_message(&self, msg: String) {
        if let Some(pb) = self.bar.as_ref() {
            pb.set_message(msg)
        }
    }

    pub fn finish(&self) {
        if let Some(pb) = self.bar.as_ref() {
            pb.finish()
        }
    }
}

pub fn start_spinner(msg: &str, quiet: bool) -> OptionalProgressBar {
    let pb = OptionalProgressBar::new_spinner(quiet);
    pb.enable_steady_tick(core::time::Duration::from_millis(200));

    pb.set_style(
        ProgressStyle::default_spinner()
            .tick_strings(&["⣾", "⣽", "⣻", "⢿", "⡿", "⣟", "⣯", "⣷", "✔"])
            .template("{spinner:.green} {msg}")
            .expect("infallible"),
    );
    pb.set_message(msg.into());
    pb
}
