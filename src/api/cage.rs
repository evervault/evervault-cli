use super::client::{ApiClient, ApiClientError, ApiResult, GenericApiClient, HandleResponse};
use super::AuthMode;
use reqwest::Client;
use serde::{Deserialize, Serialize};

#[derive(Clone)]
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

    fn update_auth(&mut self, auth: AuthMode) -> Result<(), ApiClientError> {
        self.inner.update_auth(auth)
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
            .handle_json_response()
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
            .handle_json_response()
            .await
    }

    pub async fn get_cages(&self) -> ApiResult<GetCagesResponse> {
        let get_cages_url = format!("{}/", self.base_url());
        self.get(&get_cages_url)
            .send()
            .await
            .handle_json_response()
            .await
    }

    pub async fn get_cage(&self, cage_uuid: &str) -> ApiResult<GetCageResponse> {
        let get_cage_url = format!("{}/{}", self.base_url(), cage_uuid);
        self.get(&get_cage_url)
            .send()
            .await
            .handle_json_response()
            .await
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
        self.get(&get_cage_url)
            .send()
            .await
            .handle_json_response()
            .await
    }

    pub async fn get_signing_certs(&self) -> ApiResult<GetSigningCertsResponse> {
        let get_certs_url = format!("{}/signing/certs", self.base_url(),);
        self.get(&get_certs_url)
            .send()
            .await
            .handle_json_response()
            .await
    }

    pub async fn get_cage_cert_by_uuid(&self, cert_uuid: &str) -> ApiResult<CageSigningCert> {
        let get_cert_url = format!("{}/signing/certs/{}", self.base_url(), cert_uuid);
        self.get(&get_cert_url)
            .send()
            .await
            .handle_json_response()
            .await
    }

    pub async fn get_cage_logs(
        &self,
        cage_uuid: &str,
        start_time: u128,
        end_time: u128,
    ) -> ApiResult<CageLogs> {
        let get_logs_url = format!(
            "{}/{}/logs?startTime={start_time}&endTime={end_time}",
            self.base_url(),
            cage_uuid
        );
        self.get(&get_logs_url)
            .send()
            .await
            .handle_json_response()
            .await
    }

    pub async fn delete_cage(&self, cage_uuid: &str) -> ApiResult<DeleteCageResponse> {
        let delete_cage_url = format!("{}/{}", self.base_url(), cage_uuid);
        self.delete(&delete_cage_url)
            .send()
            .await
            .handle_json_response()
            .await
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateCageDeploymentIntentRequest {
    #[serde(flatten)]
    pcrs: crate::enclave::PCRs,
    debug_mode: bool,
    egress_enabled: bool,
    eif_size_bytes: u64,
}

impl CreateCageDeploymentIntentRequest {
    pub fn new(
        pcrs: &crate::enclave::PCRs,
        debug_mode: bool,
        egress_enabled: bool,
        eif_size_bytes: u64,
    ) -> Self {
        Self {
            pcrs: pcrs.clone(),
            debug_mode,
            egress_enabled,
            eif_size_bytes,
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

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum CageState {
    Pending,
    Active,
    Deleting,
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

impl CageDeployment {
    pub fn is_finished(&self) -> bool {
        self.completed_at.is_some()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
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
    control_plane_img_url: Option<String>,
    control_plane_version: Option<String>,
    data_plane_version: Option<String>,
    build_status: BuildStatus,
    failure_reason: Option<String>,
    started_at: Option<String>,
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

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
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
    failure_reason: Option<String>,
    deploy_status: DeployStatus,
    // started_at should be required, but is being returned as null sometimes
    // should revert this to just String after API fix
    started_at: Option<String>,
    completed_at: Option<String>,
}

impl CageRegionalDeployment {
    pub fn is_failed(&self) -> bool {
        self.deploy_status == DeployStatus::Failed
    }

    pub fn get_failure_reason(&self) -> String {
        self.failure_reason.clone().unwrap_or(String::from(
            "Error deploying cage. Please contact Evervault Support",
        ))
    }
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

impl GetCageResponse {
    pub fn is_deleted(&self) -> bool {
        self.cage.state == CageState::Deleted
    }

    pub fn domain(&self) -> &str {
        self.cage.domain.as_str()
    }
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

impl GetCageDeploymentResponse {
    pub fn is_built(&self) -> bool {
        self.tee_cage_version.build_status == BuildStatus::Ready
    }

    pub fn is_finished(&self) -> bool {
        self.deployment.is_finished()
    }

    //TODO: Handle multi region deployment failures
    pub fn is_failed(&self) -> bool {
        self.tee_cage_regional_deployments[0].is_failed()
    }

    pub fn get_failure_reason(&self) -> String {
        self.tee_cage_regional_deployments[0].get_failure_reason()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetSigningCertsResponse {
    certs: Vec<CageSigningCert>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CageLogs {
    log_events: Vec<LogEvent>,
    next_token: Option<String>,
    start_time: String,
    end_time: String,
}

impl CageLogs {
    pub fn start_time(&self) -> &str {
        &self.start_time
    }

    pub fn end_time(&self) -> &str {
        &self.end_time
    }

    pub fn log_events(&self) -> &Vec<LogEvent> {
        &self.log_events
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LogEvent {
    timestamp: i64,
    message: String,
    ingestion_time: i64,
    instance_id: String,
}

impl LogEvent {
    pub fn timestamp(&self) -> i64 {
        self.timestamp
    }

    pub fn message(&self) -> &str {
        self.message.as_str()
    }

    pub fn instance_id(&self) -> &str {
        self.instance_id.as_str()
    }
}

pub type DeleteCageResponse = Cage;
