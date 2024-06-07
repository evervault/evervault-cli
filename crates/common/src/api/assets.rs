use super::{
    client::{ApiClient, ApiClientError, ApiResult, GenericApiClient, HandleResponse},
    AuthMode,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Deserialize, Serialize)]
pub struct CLIVersions {
    pub latest: String,
    pub versions: HashMap<String, CLIMajorVersion>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CLIMajorVersion {
    pub latest: String,
    #[serde(rename = "deprecationDate")]
    pub deprecation_date: Option<String>,
}

pub struct AssetsClient {
    inner: GenericApiClient,
}

impl ApiClient for AssetsClient {
    fn client(&self) -> &reqwest::Client {
        self.inner.client()
    }

    fn base_url(&self) -> String {
        let stage = std::env::var("EV_DOMAIN").map_or("staging", |_| "production");
        format!("https://cli.evervault.com/cli/{stage}")
    }

    fn auth(&self) -> &AuthMode {
        self.inner.auth()
    }

    fn update_auth(&mut self, _: AuthMode) -> Result<(), ApiClientError> {
        Err(ApiClientError::AuthModeNotSupported)
    }
}

impl Default for AssetsClient {
    fn default() -> Self {
        Self::new()
    }
}

impl AssetsClient {
    pub fn new() -> Self {
        let generic_client = GenericApiClient::default();
        Self {
            inner: generic_client,
        }
    }

    pub async fn get_latest_cli_version(&self) -> ApiResult<String> {
        let cli_version_url = format!("{}/cli/version", self.base_url());
        self.get(&cli_version_url)
            .send()
            .await
            .handle_text_response()
            .await
    }

    pub async fn get_cli_install_script(&self) -> ApiResult<String> {
        let cli_install_url = format!("{}/cli/v1/install", self.base_url());
        self.get(&cli_install_url)
            .send()
            .await
            .handle_text_response()
            .await
    }

    pub async fn get_cli_versions(&self) -> ApiResult<CLIVersions> {
        let cli_versions = format!("{}/cli/versions", self.base_url());
        self.get(&cli_versions)
            .send()
            .await
            .handle_json_response::<CLIVersions>()
            .await
    }
}
