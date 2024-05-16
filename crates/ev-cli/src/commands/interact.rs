use dialoguer::Input;

use crate::theme::CliTheme;

pub mod validators {
    use lazy_static;
    use regex::Regex;
    use std::fmt::{Debug, Display};

    #[derive(Debug)]
    pub enum ValidationError {
        InvalidHostname,
        InvalidCustomDomain,
        InvalidDestinationDomain,
    }
    impl Display for ValidationError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            #[allow(unreachable_patterns)]
            match self {
                Self::InvalidHostname => write!(f, "Value must be a valid HTTPS domain"),
                Self::InvalidCustomDomain => write!(
                    f,
                    "Invalid custom domain. You should not use a \
                 top-level domain name, or include a protocol or path"
                ),
                Self::InvalidDestinationDomain => write!(
                    f,
                    "Destination Domain must be a valid hostname and not contain a protocol or path."
                ),
                _ => write!(f, "{:?}", self),
            }
        }
    }

    pub type GenericValidator = dyn Fn(&String) -> Result<(), ValidationError>;
    pub fn is_valid_hostname(input: &String) -> Result<(), ValidationError> {
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

    pub fn is_valid_custom_domain(input: &String) -> Result<(), ValidationError> {
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

    pub fn is_valid_destination_domain(input: &String) -> Result<(), ValidationError> {
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
}

pub fn input(prompt: Option<String>, allow_empty: bool) -> Option<String> {
    let theme = CliTheme::default();
    let mut input: Input<String> = Input::with_theme(&theme);
    if let Some(prompt) = prompt {
        input.with_prompt(prompt);
    }

    input.allow_empty(allow_empty).interact().ok()
}

pub fn validated_input(
    prompt: Option<String>,
    allow_empty: bool,
    validator: Box<validators::GenericValidator>,
) -> Option<String> {
    let theme = CliTheme::default();
    let mut input: Input<String> = Input::with_theme(&theme);
    if let Some(prompt) = prompt {
        input.with_prompt(prompt);
    }

    input
        .allow_empty(allow_empty)
        .validate_with(validator)
        .interact()
        .ok()
}
