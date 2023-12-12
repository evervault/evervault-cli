pub mod assets;
pub mod client;
pub mod enclave;

pub use reqwest::Client;

#[derive(Clone)]
pub enum AuthMode {
    NoAuth,
    ApiKey(String),
    BearerAuth(String),
}
