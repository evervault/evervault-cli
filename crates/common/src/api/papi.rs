use std::fs::File;

use self::client::{ApiError, ApiErrorKind, ApiResult, HandleResponse};
use crate::function::{
    CreateFunctionResponse, Function, FunctionDeployment, FunctionDeploymentCredentials,
    GetFunctionResponse,
};
use crate::relay::{CreateRelay, Relay};
use serde_json::json;

use super::*;
use super::{
    client::{ApiClient, ApiClientError, GenericApiClient},
    AuthMode, BasicAuth,
};
use std::io::Write;

/// Client for Evervault API
pub struct EvApiClient {
    inner: GenericApiClient,
    api_key: String,
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
            inner: GenericApiClient::from(AuthMode::BasicAuth(auth.clone())),
            api_key: auth.1,
        }
    }
}

#[async_trait::async_trait]
#[cfg_attr(test, mockall::automock)]
pub trait EvApi {
    async fn update_relay(&self, relay: &Relay) -> ApiResult<crate::relay::Relay>;
    async fn create_relay(&self, relay: &Relay) -> ApiResult<crate::relay::Relay>;
    async fn get_hello_function_template(&self, lang: String) -> ApiResult<File>;
    async fn get_all_functions_for_app(&self) -> ApiResult<Vec<Function>>;
    async fn get_function_update_credentials(
        &self,
        function_name: String,
    ) -> ApiResult<FunctionDeploymentCredentials>;
    async fn create_function_record(
        &self,
        function_name: String,
    ) -> ApiResult<FunctionDeploymentCredentials>;
    async fn upload_function(&self, url: &str, function: tokio::fs::File) -> ApiResult<()>;
    async fn get_function_deployment(
        &self,
        function_uuid: String,
        deployment_id: u64,
    ) -> ApiResult<FunctionDeployment>;
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

    async fn get_all_functions_for_app(&self) -> ApiResult<Vec<Function>> {
        let url = format!("{}/v2/functions", self.base_url());

        self.get(&url)
            .header("api-key", &self.api_key)
            .send()
            .await
            .handle_json_response::<GetFunctionResponse>()
            .await
            .map(|res| res.functions)
    }

    async fn get_function_update_credentials(
        &self,
        function_name: String,
    ) -> ApiResult<FunctionDeploymentCredentials> {
        let url = format!(
            "{}/v2/functions/{}/credentials",
            self.base_url(),
            function_name
        );

        self.get(&url)
            .header("api-key", &self.api_key)
            .send()
            .await
            .handle_json_response()
            .await
    }

    async fn create_function_record(
        &self,
        function_name: String,
    ) -> ApiResult<FunctionDeploymentCredentials> {
        let url = format!("{}/v2/functions", self.base_url());

        self.post(&url)
            .header("api-key", &self.api_key)
            .json(&json!({
                "name": function_name,
            }))
            .send()
            .await
            .handle_json_response::<CreateFunctionResponse>()
            .await
            .map(|res| res.into())
    }

    async fn upload_function(&self, url: &str, function: tokio::fs::File) -> ApiResult<()> {
        self.put(&url)
            .header("x-aws-acl", "private")
            .header("Content-Type", "application/zip")
            .header(
                "Content-Length",
                function
                    .metadata()
                    .await
                    .map_err(|_| ApiError::new(ApiErrorKind::Unknown(None)))?
                    .len()
                    .to_string(),
            )
            .body(function)
            .send()
            .await
            .handle_no_op_response()
    }

    async fn get_function_deployment(
        &self,
        function_uuid: String,
        deployment_id: u64,
    ) -> ApiResult<FunctionDeployment> {
        let url = format!(
            "{}/v2/functions/{}/deployments/{}",
            self.base_url(),
            function_uuid,
            deployment_id
        );

        self.get(&url)
            .header("api-key", &self.api_key)
            .send()
            .await
            .handle_json_response::<FunctionDeployment>()
            .await
    }
}
