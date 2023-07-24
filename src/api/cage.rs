use crate::config::ValidatedCageBuildConfig;

use super::client::{ApiClient, ApiClientError, ApiResult, GenericApiClient, HandleResponse};
use super::AuthMode;
use reqwest::Client;
use serde::{Deserialize, Serialize};

#[derive(Clone)]
pub struct CagesClient {
    inner: GenericApiClient,
}

impl ApiClient for CagesClient {
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
    pub fn new(auth_mode: AuthMode) -> Self {
        Self {
            inner: GenericApiClient::from(auth_mode),
        }
    }

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

    pub async fn create_cage_signing_cert_ref(
        &self,
        payload: CreateCageSigningCertRefRequest,
    ) -> ApiResult<CreateCageSigningCertRefResponse> {
        let signing_cert_url = format!("{}/signing/certs", self.base_url());
        self.post(&signing_cert_url)
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

    pub async fn get_app_keys(
        &self,
        team_uuid: &str,
        app_uuid: &str,
    ) -> ApiResult<GetKeysResponse> {
        let get_cage_url = format!("{}/{}/apps/{}", self.keys_url(), team_uuid, app_uuid);
        self.get(&get_cage_url)
            .send()
            .await
            .handle_json_response()
            .await
    }

    pub async fn add_env_var(&self, cage_uuid: String, payload: AddSecretRequest) -> ApiResult<()> {
        let add_env_url = format!("{}/{}/secrets", self.base_url(), cage_uuid);
        self.put(&add_env_url)
            .json(&payload)
            .send()
            .await
            .handle_no_op_response()
    }

    pub async fn delete_env_var(&self, cage_uuid: String, name: String) -> ApiResult<()> {
        let delete_env_url = format!("{}/{}/secrets/{}", self.base_url(), cage_uuid, name);
        self.delete(&delete_env_url)
            .send()
            .await
            .handle_no_op_response()
    }

    pub async fn get_cage_env(&self, cage_uuid: String) -> ApiResult<CageEnv> {
        let get_env_url = format!("{}/{}/secrets", self.base_url(), cage_uuid);
        self.get(&get_env_url)
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

    pub async fn update_cage_locked_signing_certs(
        &self,
        cage_uuid: &str,
        payload: UpdateLockedCageSigningCertRequest,
    ) -> ApiResult<Vec<CageToSigningCert>> {
        let get_cage_lock_certs_url = format!("{}/{}/signing/certs", self.base_url(), cage_uuid);
        self.put(&get_cage_lock_certs_url)
            .json(&payload)
            .send()
            .await
            .handle_json_response()
            .await
    }

    pub async fn get_cage_locked_signing_certs(
        &self,
        cage_uuid: &str,
    ) -> ApiResult<Vec<CageSigningCert>> {
        let get_cage_lock_certs_url = format!("{}/{}/signing/certs", self.base_url(), cage_uuid);
        self.get(&get_cage_lock_certs_url)
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

    pub async fn restart_cage(&self, cage_uuid: &str) -> ApiResult<()> {
        let patch_cage_url = format!("{}/{}", self.base_url(), cage_uuid);
        self.patch(&patch_cage_url)
            .send()
            .await
            .handle_json_response()
            .await
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VersionMetadata {
    installer_version: String,
    git_hash: String,
    data_plane_version: String,
    git_timestamp: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateCageDeploymentIntentRequest {
    #[serde(flatten)]
    pcrs: crate::enclave::PCRs,
    debug_mode: bool,
    egress_enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    egress_domains: Option<Vec<String>>,
    eif_size_bytes: u64,
    not_before: String,
    not_after: String,
    metadata: VersionMetadata,
}

impl CreateCageDeploymentIntentRequest {
    pub fn new(
        pcrs: &crate::enclave::PCRs,
        config: ValidatedCageBuildConfig,
        eif_size_bytes: u64,
        data_plane_version: String,
        installer_version: String,
        git_timestamp: String,
        git_hash: String,
    ) -> Self {
        Self {
            pcrs: pcrs.clone(),
            debug_mode: config.debug,
            egress_enabled: config.egress.enabled,
            egress_domains: config.egress.destinations.clone(),
            eif_size_bytes,
            not_before: config.signing.not_before(),
            not_after: config.signing.not_after(),
            metadata: VersionMetadata {
                git_hash,
                installer_version,
                data_plane_version,
                git_timestamp,
            },
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateCageSigningCertRefRequest {
    cert_hash: String,
    name: String,
    not_before: String,
    not_after: String,
}

impl CreateCageSigningCertRefRequest {
    pub fn new(cert_hash: String, name: String, not_before: String, not_after: String) -> Self {
        Self {
            cert_hash,
            name,
            not_before,
            not_after,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateLockedCageSigningCertRequest {
    cert_uuids: Vec<String>,
}

impl UpdateLockedCageSigningCertRequest {
    pub fn new(cert_uuids: Vec<String>) -> Self {
        Self { cert_uuids }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateCageRequest {
    name: String,
    is_time_bound: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AddSecretRequest {
    pub name: String,
    pub secret: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CageSecrets {
    pub name: String,
    pub secret: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CageEnv {
    pub secrets: Vec<Secret>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Secret {
    pub name: String,
    pub secret: String,
}

impl CreateCageRequest {
    pub fn new(cage_name: String, is_time_bound: bool) -> Self {
        Self {
            name: cage_name,
            is_time_bound,
        }
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
#[serde(rename_all = "camelCase")]
pub struct CreateCageSigningCertRefResponse {
    cert_hash: String,
    not_before: String,
    not_after: String,
    name: String,
    uuid: String,
}

impl CreateCageSigningCertRefResponse {
    pub fn cert_hash(&self) -> &str {
        &self.cert_hash
    }

    pub fn not_before(&self) -> &str {
        &self.not_before
    }

    pub fn not_after(&self) -> &str {
        &self.not_after
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn uuid(&self) -> &str {
        &self.uuid
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CageToSigningCert {
    pub cage_uuid: String,
    pub signing_cert_uuid: String,
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
    pub uuid: String,
    pub name: String,
    pub team_uuid: String,
    pub app_uuid: String,
    pub domain: String,
    pub state: CageState,
    pub created_at: String,
    pub updated_at: String,
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

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, PartialOrd)]
#[serde(rename_all = "camelCase")]
pub struct CageSigningCert {
    name: Option<String>,
    uuid: String,
    app_uuid: String,
    cert_hash: String,
    not_before: Option<String>,
    not_after: Option<String>,
}

impl CageSigningCert {
    pub fn new(
        name: Option<String>,
        uuid: String,
        app_uuid: String,
        cert_hash: String,
        not_before: Option<String>,
        not_after: Option<String>,
    ) -> Self {
        Self {
            name,
            uuid,
            app_uuid,
            cert_hash,
            not_before,
            not_after,
        }
    }

    pub fn uuid(&self) -> &str {
        &self.uuid
    }

    pub fn app_uuid(&self) -> &str {
        &self.app_uuid
    }

    pub fn cert_hash(&self) -> &str {
        &self.cert_hash
    }

    pub fn not_before(&self) -> Option<String> {
        self.not_before.clone()
    }

    pub fn not_after(&self) -> Option<String> {
        self.not_after.clone()
    }

    pub fn name(&self) -> Option<String> {
        self.name.clone()
    }
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
    detailed_status: Option<String>,
}

impl CageRegionalDeployment {
    pub fn is_failed(&self) -> bool {
        self.deploy_status == DeployStatus::Failed
    }

    pub fn get_failure_reason(&self) -> String {
        self.failure_reason
            .clone()
            .unwrap_or_else(|| String::from("An unknown error occurred during deployment."))
    }

    pub fn get_detailed_status(&self) -> String {
        self.detailed_status
            .clone()
            .unwrap_or_else(|| String::from("Starting deployment."))
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

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetKeysResponse {
    pub ecdh_p256_key_uncompressed: String,
    pub ecdh_p256_key: String,
    pub ecdh_key: String,
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
    pub fn is_failed(&self) -> Option<bool> {
        self.tee_cage_regional_deployments
            .first()
            .map(|depl| depl.is_failed())
    }

    pub fn get_failure_reason(&self) -> Option<String> {
        self.tee_cage_regional_deployments
            .first()
            .map(|depl| depl.get_failure_reason())
    }

    pub fn get_detailed_status(&self) -> Option<String> {
        self.tee_cage_regional_deployments
            .first()
            .map(|depl| depl.get_detailed_status())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetSigningCertsResponse {
    pub certs: Vec<CageSigningCert>,
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

#[cfg(test)]
mod test {
    use super::*;

    fn get_testing_deployment() -> CageDeployment {
        CageDeployment {
            uuid: "abc".to_string(),
            cage_uuid: "def".to_string(),
            version_uuid: "ghi".to_string(),
            signing_cert_uuid: "jkl".to_string(),
            debug_mode: false,
            started_at: None,
            completed_at: None,
        }
    }

    fn get_testing_version() -> CageVersion {
        CageVersion {
            uuid: "abc".to_string(),
            version: 1,
            control_plane_img_url: Some("control-plane.com".to_string()),
            control_plane_version: Some("1.0.0".to_string()),
            data_plane_version: Some("1.0.0".to_string()),
            build_status: BuildStatus::Ready,
            failure_reason: None,
            started_at: None,
        }
    }

    fn get_testing_cert() -> CageSigningCert {
        CageSigningCert {
            name: Some("abc".to_string()),
            uuid: "abc".to_string(),
            app_uuid: "def".to_string(),
            cert_hash: "ghi".to_string(),
            not_before: None,
            not_after: None,
        }
    }

    #[test]
    fn test_empty_regional_deployments() {
        let deployment = get_testing_deployment();
        let version = get_testing_version();
        let cert = get_testing_cert();
        let deployment_with_empty_regional = GetCageDeploymentResponse {
            deployment,
            tee_cage_version: version,
            tee_cage_signing_cert: cert,
            tee_cage_regional_deployments: vec![],
        };

        assert!(deployment_with_empty_regional
            .get_detailed_status()
            .is_none());
        assert!(deployment_with_empty_regional
            .get_failure_reason()
            .is_none());
        assert!(deployment_with_empty_regional.is_failed().is_none());
    }

    #[test]
    fn test_populated_regional_deployments() {
        let deployment = get_testing_deployment();
        let version = get_testing_version();
        let cert = get_testing_cert();

        let failure_reason = "An error occurred provisioning your TEE".to_string();
        let detailed_failure_reason = "Insufficient capacity".to_string();
        let deployment_with_regional = GetCageDeploymentResponse {
            deployment,
            tee_cage_version: version,
            tee_cage_signing_cert: cert,
            tee_cage_regional_deployments: vec![CageRegionalDeployment {
                uuid: "abc".to_string(),
                deployment_uuid: "def".to_string(),
                deployment_order: 1,
                region: "us-east-1".to_string(),
                failure_reason: Some(failure_reason.clone()),
                deploy_status: DeployStatus::Failed,
                started_at: None,
                completed_at: None,
                detailed_status: Some(detailed_failure_reason.clone()),
            }],
        };

        assert_eq!(deployment_with_regional.is_failed(), Some(true));
        assert_eq!(
            deployment_with_regional.get_failure_reason(),
            Some(failure_reason)
        );
        assert_eq!(
            deployment_with_regional.get_detailed_status(),
            Some(detailed_failure_reason)
        );
    }
}
