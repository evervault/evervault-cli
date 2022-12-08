use super::client::{ApiClient, ApiClientError, ApiResult, GenericApiClient, HandleResponse};

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
}
