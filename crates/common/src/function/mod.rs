use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Function {
    id: u64,
    team_uuid: String,
    app_uuid: Option<String>,
    pub name: String,
    pub uuid: String,
    s3_etag: Option<String>,
    status: Option<String>,
    pub environment_variables: Option<Map<String, Value>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum FunctionDeploymentStatus {
    Initiated,
    Uploading,
    Packaging,
    Provisioning,
    Deployed,
    Failed,
    Cancelled,
    CreatingRepo,
    UploadingTemplate,
    StartingBuild,
    QueuedForBuilding,
    Building,
    Retrying,
}

impl FunctionDeploymentStatus {
    pub fn get_progress_msg(&self) -> &str {
        match self {
            Self::Deployed => "Deployed!",
            Self::Failed => "Failed.",
            Self::Cancelled => "Cancelled.",
            Self::Initiated => "Initiated...",
            Self::Packaging => "Packaging...",
            Self::Provisioning => "Provisioning...",
            Self::Uploading => "Uploading...",
            Self::CreatingRepo => "Creating repo...",
            Self::UploadingTemplate => "Uploading template...",
            Self::StartingBuild => "Starting build...",
            Self::QueuedForBuilding => "Queued...",
            Self::Building => "Building...",
            Self::Retrying => "Retrying...",
        }
    }

    pub fn is_in_terminal_state(&self) -> bool {
        match self {
            Self::Deployed | Self::Cancelled | Self::Failed => true,
            _ => false,
        }
    }
}

#[derive(Deserialize)]
pub struct GetFunctionEnvironmentResponse {
    pub environment: serde_json::Map<String, serde_json::Value>,
}

#[derive(Deserialize)]
pub struct GetFunctionResponse {
    pub functions: Vec<Function>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateFunctionResponse {
    pub func: Function,
    pub signed_url: String,
    pub deployment_id: u64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FunctionDeploymentCredentials {
    pub signed_url: String,
    pub uuid: String,
    pub deployment_id: u64,
}

impl From<CreateFunctionResponse> for FunctionDeploymentCredentials {
    fn from(create_function_res: CreateFunctionResponse) -> Self {
        Self {
            signed_url: create_function_res.signed_url,
            deployment_id: create_function_res.deployment_id,
            uuid: create_function_res.func.uuid,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
pub struct FunctionDeployment {
    id: u64,
    lambda_version_id: Option<String>,
    s3_etag: Option<String>,
    s3_version_id: Option<String>,
    function_version: u64,
    pub status: FunctionDeploymentStatus,
    #[serde(rename = "type")]
    deployment_type: Option<String>,
    commit_hash: Option<String>,
    pub failure_reason: Option<String>,
    published: bool,
}
