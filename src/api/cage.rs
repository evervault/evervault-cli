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
    pub async fn create_cage(&self, cage_create_payload: CreateCageRequest) -> ApiResult<Cage> {
        let create_cage_url = format!("{}/", self.base_url());
        self.post(&create_cage_url)
            .json(&cage_create_payload)
            .send()
            .await
            .handle_response()
            .await
    }

    pub async fn create_cage_deployment_intent(
        &self,
        cage_uuid: &str,
        payload: CreateCageDeploymentIntentRequest,
    ) -> ApiResult<CreateCageDeploymentIntentResponse> {
        let deployment_intent_url = format!("{}/{}/credentials", self.base_url(), cage_uuid);
        self.post(&deployment_intent_url)
            .json(&payload)
            .send()
            .await
            .handle_response()
            .await
    }

    pub async fn get_cages(&self) -> ApiResult<GetCagesResponse> {
        let get_cages_url = format!("{}/", self.base_url());
        self.get(&get_cages_url)
            .send()
            .await
            .handle_response()
            .await
    }

    pub async fn get_cage(&self, cage_uuid: &str) -> ApiResult<GetCageResponse> {
        let get_cage_url = format!("{}/{}", self.base_url(), cage_uuid);
        self.get(&get_cage_url).send().await.handle_response().await
    }

    pub async fn get_cage_deployment_by_uuid(
        &self,
        cage_uuid: &str,
        deployment_uuid: &str,
    ) -> ApiResult<GetCageDeploymentResponse> {
        let get_cage_url = format!(
            "{}/{}/deployments/{}",
            self.base_url(),
            cage_uuid,
            deployment_uuid
        );
        self.get(&get_cage_url).send().await.handle_response().await
    }

    pub async fn get_signing_certs(&self) -> ApiResult<GetSigningCertsResponse> {
        let get_certs_url = format!("{}/signing/certs", self.base_url(),);
        self.get(&get_certs_url)
            .send()
            .await
            .handle_response()
            .await
    }

    pub async fn get_cage_cert_by_uuid(&self, cert_uuid: &str) -> ApiResult<CageSigningCert> {
        let get_cert_url = format!("{}/signing/certs/{}", self.base_url(), cert_uuid);
        self.get(&get_cert_url).send().await.handle_response().await
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateCageDeploymentIntentRequest {
    #[serde(flatten)]
    pcrs: crate::enclave::PCRs,
    debug_mode: bool,
}

impl CreateCageDeploymentIntentRequest {
    pub fn new(pcrs: &crate::enclave::PCRs, debug_mode: bool) -> Self {
        Self {
            pcrs: pcrs.clone(),
            debug_mode: debug_mode,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CreateCageRequest {
    name: String,
}

impl std::convert::From<String> for CreateCageRequest {
    fn from(cage_name: String) -> Self {
        Self { name: cage_name }
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

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CageState {
    Pending,
    Active,
    Deleted,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Cage {
    uuid: String,
    name: String,
    team_uuid: String,
    app_uuid: String,
    domain: String,
    state: CageState,
    created_at: String,
    updated_at: String,
}

impl Cage {
    pub fn uuid(&self) -> &str {
        &self.uuid
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn app_uuid(&self) -> &str {
        &self.app_uuid
    }

    pub fn team_uuid(&self) -> &str {
        &self.team_uuid
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CageDeployment {
    uuid: String,
    cage_uuid: String,
    version_uuid: String,
    signing_cert_uuid: String,
    debug_mode: bool,
    started_at: Option<String>,
    completed_at: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum BuildStatus {
    Pending,
    Building,
    Ready,
    Failed,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CageVersion {
    uuid: String,
    version: u16,
    control_plane_img_url: String,
    control_plane_version: Option<String>,
    data_plane_version: Option<String>,
    build_status: BuildStatus,
    failure_reason: Option<String>,
    started_at: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CageSigningCert {
    uuid: String,
    app_uuid: String,
    cert_hash: String,
    not_before: Option<String>,
    not_after: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum DeployStatus {
    Pending,
    Deploying,
    Ready,
    Failed,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CageRegionalDeployment {
    uuid: String,
    deployment_uuid: String,
    deployment_order: u16,
    region: String,
    failure_reason: String,
    deploy_status: DeployStatus,
    started_at: String,
    completed_at: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetCagesResponse {
    cages: Vec<Cage>,
}

impl GetCagesResponse {
    pub fn cages(&self) -> &Vec<Cage> {
        self.cages.as_ref()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeploymentsForGetCage {
    #[serde(flatten)]
    deployment: CageDeployment,
    #[serde(rename = "teeCageVersion")]
    version: CageVersion,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetCageResponse {
    #[serde(flatten)]
    cage: Cage,
    #[serde(rename = "teeCageDeployments")]
    deployments: Vec<DeploymentsForGetCage>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetCageDeploymentResponse {
    #[serde(flatten)]
    deployment: CageDeployment,
    tee_cage_version: CageVersion,
    tee_cage_signing_cert: CageSigningCert,
    tee_cage_regional_deployments: Vec<CageRegionalDeployment>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetSigningCertsResponse {
    certs: Vec<CageSigningCert>,
}
