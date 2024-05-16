use std::fs::File;

use self::client::{ApiError, ApiErrorKind, ApiResult, HandleResponse};
use crate::relay::{CreateRelay, Relay};

use super::*;
use super::{
    client::{ApiClient, ApiClientError, GenericApiClient},
    AuthMode, BasicAuth,
};
use std::io::Write;

/// Client for Evervault API
pub struct EvApiClient {
    inner: GenericApiClient,
}

impl ApiClient for EvApiClient {
    fn client(&self) -> &reqwest::Client {
        self.inner.client()
    }

    fn base_url(&self) -> String {
        let domain = std::env::var("EV_DOMAIN").unwrap_or_else(|_| String::from("evervault.com"));
        format!("https://api.{}", domain)
    }

    fn auth(&self) -> &AuthMode {
        self.inner.auth()
    }

    fn update_auth(&mut self, _: AuthMode) -> Result<(), ApiClientError> {
        Err(ApiClientError::AuthModeNotSupported)
    }
}

impl EvApiClient {
    pub fn new(auth: BasicAuth) -> Self {
        Self {
            inner: GenericApiClient::from(AuthMode::BasicAuth(auth)),
        }
    }
}

#[async_trait::async_trait]
#[cfg_attr(test, mockall::automock)]
pub trait EvApi {
    async fn update_relay(&self, relay: &Relay) -> ApiResult<crate::relay::Relay>;
    async fn create_relay(&self, relay: &Relay) -> ApiResult<crate::relay::Relay>;
    async fn get_hello_function_template(&self, lang: String) -> ApiResult<File>;
}

#[async_trait::async_trait]
impl EvApi for EvApiClient {
    async fn update_relay(&self, relay: &Relay) -> ApiResult<crate::relay::Relay> {
        let update_relay_url = format!(
            "{}/relays/{}",
            self.base_url(),
            relay.id.clone().expect("Relay ID is required")
        );

        self.patch(&update_relay_url)
            .json(&CreateRelay {
                encrypt_empty_strings: relay.encrypt_empty_strings,
                authentication: relay.authentication.clone(),
                routes: relay.routes.clone(),
            })
            .send()
            .await
            .handle_json_response()
            .await
    }

    async fn create_relay(&self, relay: &Relay) -> ApiResult<crate::relay::Relay> {
        let create_relay_url = format!("{}/relays", self.base_url());
        self.post(&create_relay_url)
            .json(&relay)
            .send()
            .await
            .handle_json_response()
            .await
    }

    async fn get_hello_function_template(&self, lang: String) -> ApiResult<File> {
        let url = format!(
            "https://github.com/evervault/template-{}-hello-function/archive/master.zip",
            lang
        );
        match self.client().get(&url).send().await {
            Ok(res) if res.status().is_success() => {
                let mut tmpfile = tempfile::tempfile().unwrap();
                let bytes = res
                    .bytes()
                    .await
                    .map_err(|e| ApiError::new(ApiErrorKind::Unknown(Some(e))))?;

                tmpfile
                    .write(&bytes)
                    .map_err(|_| ApiError::new(ApiErrorKind::Unknown(None)))?;

                Ok(tmpfile)
            }
            Ok(res) => Err(ApiError::new(ApiError::get_error_from_status(
                res.status().as_u16(),
            ))),
            Err(e) => Err(ApiError::new(ApiErrorKind::Unknown(Some(e)))),
        }
    }
}
