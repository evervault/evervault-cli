pub mod client;

pub use reqwest::Client;

#[derive(Clone)]
pub enum AuthMode {
    NoAuth,
    ApiKey(String),
    BearerAuth(String),
}
