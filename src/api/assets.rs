use super::client::{ApiClient, ApiResult, HandleResponse};
use reqwest::Client;

pub struct AssetsClient {
    client: reqwest::Client,
}

impl ApiClient for AssetsClient {
    fn client(&self) -> &reqwest::Client {
        &self.client
    }

    fn base_url(&self) -> String {
        std::env::var("EV_ASSETS_URL")
            .unwrap_or(String::from("https://cage-build-assets.evervault.com"))
    }
}

impl AssetsClient {
    pub fn new() -> Self {
        Self {
            client: Client::new(),
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
