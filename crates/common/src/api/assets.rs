use super::{
    client::{ApiClient, ApiClientError, ApiResult, GenericApiClient, HandleResponse},
    AuthMode,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Deserialize, Serialize)]
pub struct CLIVersions {
    pub latest: String,
    /// Keyed by major version. A major can be listed with no releases (`null`)
    pub versions: HashMap<String, Option<CLIMajorVersion>>,
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
        let domain = std::env::var("EV_DOMAIN").unwrap_or_else(|_| String::from("evervault.com"));
        format!("https://cli.{}", domain)
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
        let cli_version_url = format!("{}/version", self.base_url());
        self.get(&cli_version_url)
            .send()
            .await
            .handle_text_response()
            .await
    }

    /// The install script for the latest release of a major version of the CLI
    pub fn cli_install_script_url(&self, major_version: u64) -> String {
        format!("{}/v{major_version}/install", self.base_url())
    }

    pub async fn get_cli_install_script(&self, major_version: u64) -> ApiResult<String> {
        self.get(&self.cli_install_script_url(major_version))
            .send()
            .await
            .handle_text_response()
            .await
    }

    pub async fn get_cli_versions(&self) -> ApiResult<CLIVersions> {
        let cli_versions = format!("{}/versions", self.base_url());
        self.get(&cli_versions)
            .send()
            .await
            .handle_json_response::<CLIVersions>()
            .await
    }
}
