use super::client::{ApiClient, ApiClientError, ApiResult, GenericApiClient, HandleResponse};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
struct RuntimeVersion {
    data_plane: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CLIVersion {
    pub latest: String,
    pub versions: HashMap<String, MajorVersion>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct MajorVersion {
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
        format!("https://cage-build-assets.{}", domain)
    }

    fn auth(&self) -> &super::AuthMode {
        self.inner.auth()
    }

    fn update_auth(&mut self, _: super::AuthMode) -> Result<(), ApiClientError> {
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
        let cli_install_url = format!("{}/cli/install", self.base_url());
        self.get(&cli_install_url)
            .send()
            .await
            .handle_text_response()
            .await
    }

    pub async fn get_latest_data_plane_version(&self) -> ApiResult<String> {
        let data_plane_version = format!("{}/runtime/latest", self.base_url());
        self.get(&data_plane_version)
            .send()
            .await
            .handle_json_response::<RuntimeVersion>()
            .await
            .map(|version| version.data_plane)
    }

    pub async fn get_latest_installer_version(&self) -> ApiResult<String> {
        let installer_version = format!("{}/installer/latest", self.base_url());
        self.get(&installer_version)
            .send()
            .await
            .handle_text_response()
            .await
            .map(|version| version.trim().to_string())
    }

    pub async fn get_cli_versions(&self) -> ApiResult<CLIVersion> {
        let data_plane_version = format!("{}/cli/versions", self.base_url());
        self.get(&data_plane_version)
            .send()
            .await
            .handle_json_response::<CLIVersion>()
            .await
    }
}
