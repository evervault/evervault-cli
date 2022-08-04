use super::client::{ApiClient, ApiResult, GenericApiClient, HandleResponse};
use super::AuthMode;
use reqwest::Client;
use serde::{Deserialize, Serialize};

pub struct CagesClient {
    inner: GenericApiClient,
}

impl ApiClient for CagesClient {
    fn new(auth_mode: AuthMode) -> Self {
        Self {
            inner: GenericApiClient::from(auth_mode),
        }
    }

    fn auth(&self) -> &AuthMode {
        self.inner.auth()
    }

    fn update_auth(&mut self, auth: AuthMode) {
        self.inner.update_auth(auth);
    }

    fn client(&self) -> &Client {
        self.inner.client()
    }

    fn base_url(&self) -> String {
        let api_base = self.inner.base_url();
        format!("{}/v2/cages", api_base)
    }
}

impl CagesClient {
    pub async fn create_cage_deployment_intent(
        &self,
        cage_name: &str,
        payload: CreateCageDeploymentIntentRequest,
    ) -> ApiResult<CreateCageDeploymentIntentResponse> {
        let deployment_intent_url = format!("{}/{}/credentials", self.base_url(), cage_name);
        self.post(&deployment_intent_url)
            .json(&payload)
            .send()
            .await
            .handle_response()
            .await
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CreateCageDeploymentIntentRequest {
    #[serde(flatten)]
    pcrs: crate::enclave::PCRs,
}

impl std::convert::From<&crate::enclave::PCRs> for CreateCageDeploymentIntentRequest {
    fn from(pcrs: &crate::enclave::PCRs) -> Self {
        Self { pcrs: pcrs.clone() }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateCageDeploymentIntentResponse {
    signed_url: String,
    cage_uuid: String,
    deployment_uuid: String,
    version: u32,
}

impl CreateCageDeploymentIntentResponse {
    pub fn signed_url(&self) -> &str {
        &self.signed_url
    }

    pub fn cage_uuid(&self) -> &str {
        &self.cage_uuid
    }

    pub fn deployment_uuid(&self) -> &str {
        &self.deployment_uuid
    }

    pub fn version(&self) -> u32 {
        self.version
    }
}
