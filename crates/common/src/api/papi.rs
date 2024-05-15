use self::client::{ApiResult, HandleResponse};
use crate::relay::Relay;

use super::*;
use super::{
    client::{ApiClient, ApiClientError, GenericApiClient},
    AuthMode, BasicAuth,
};
use serde::Deserialize;
use serde_json::{Map, Value};

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
}

#[async_trait::async_trait]
impl EvApi for EvApiClient {
    async fn update_relay(&self, relay: &Relay) -> ApiResult<crate::relay::Relay> {
        let update_relay_url = format!(
            "{}/relays/{}",
            self.base_url(),
            relay.id.clone().expect("Relay ID is required")
        );
        self.put(&update_relay_url)
            .json(&relay)
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

    // async fn get_relays(&self) -> ApiResult<Relays> {
    //     let get_relays_url = format!("{}/relays", self.base_url());
    //     self.get(&get_relays_url)
    //         .send()
    //         .await
    //         .handle_json_response()
    //         .await
    // }
}

#[derive(Deserialize)]
pub struct GetFunctionEnvironmentResponse {
    pub environment: Map<String, Value>,
}

// #[derive(Deserialize)]
// pub struct GetFunctionResponse {
//     pub functions: Vec<Function>,
// }

// #[derive(Deserialize)]
// #[serde(rename_all = "camelCase")]
// pub struct CreateFunctionResponse {
//     pub func: Function,
//     pub signed_url: String,
//     pub deployment_id: u64,
// }

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FunctionDeploymentCredentials {
    pub signed_url: String,
    pub uuid: String,
    pub deployment_id: u64,
}

// impl From<CreateFunctionResponse> for FunctionDeploymentCredentials {
//     fn from(create_function_res: CreateFunctionResponse) -> Self {
//         Self {
//             signed_url: create_function_res.signed_url,
//             deployment_id: create_function_res.deployment_id,
//             uuid: create_function_res.func.uuid,
//         }
//     }
// }

// #[derive(Debug, Deserialize)]
// #[serde(rename_all = "camelCase")]
// #[allow(dead_code)]
// pub struct FunctionDeployment {
//     id: u64,
//     lambda_version_id: Option<String>,
//     s3_etag: Option<String>,
//     s3_version_id: Option<String>,
//     function_version: u64,
//     pub status: FunctionDeploymentStatus,
//     #[serde(rename = "type")]
//     deployment_type: Option<String>,
//     commit_hash: Option<String>,
//     failure_reason: Option<String>,
//     published: bool,
// }
