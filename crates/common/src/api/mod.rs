pub mod client;
pub mod assets;

pub use reqwest::Client;

#[derive(Clone)]
pub enum AuthMode {
    NoAuth,
    ApiKey(String),
    BearerAuth(String),
}
