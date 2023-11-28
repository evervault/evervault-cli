use crate::api::assets::AssetsClient;
use crate::api::cage::{
    BuildStatus, Cage, CageDeployment, CageRegionalDeployment, CageSigningCert, CageState,
    CageVersion, DeployStatus, DeploymentsForGetCage, GetCageDeploymentResponse, GetCageResponse,
};
use crate::build::build_enclave_image_file;
use crate::build::error::BuildError;
use crate::common::OutputPath;
use crate::config::{read_and_validate_config, ValidatedCageBuildConfig};
use crate::enclave::BuiltEnclave;

pub async fn build_test_cage(
    output_dir: Option<&str>,
    from_existing: Option<String>,
    reproducible: bool,
) -> Result<(BuiltEnclave, OutputPath), BuildError> {
    let dn_string = crate::cert::DistinguishedName::default();
    crate::cert::create_new_cert(std::path::Path::new("."), dn_string)
        .expect("Failed to gen cert in tests");
    let build_args = get_test_build_args();
    let assets_client = AssetsClient::new();

    let data_plane_version = assets_client.get_data_plane_version().await.unwrap();
    let installer_version = assets_client.get_installer_version().await.unwrap();
    let timestamp = "0".to_string();

    build_enclave_image_file(
        &build_args,
        ".",
        output_dir,
        false,
        None,
        data_plane_version,
        installer_version,
        timestamp,
        from_existing,
        reproducible,
    )
    .await
}

fn get_test_build_args() -> ValidatedCageBuildConfig {
    let (_cage_config, validated_config) = read_and_validate_config("./test.cage.toml", &())
        .expect("Testing config failed to validate");
    validated_config
}

pub fn build_get_cage_response(
    state: CageState,
    deployments: Vec<DeploymentsForGetCage>,
) -> GetCageResponse {
    GetCageResponse {
        cage: Cage {
            uuid: "abc".into(),
            name: "def".into(),
            team_uuid: "team_123".into(),
            app_uuid: "app_456".into(),
            domain: "cage.com".into(),
            state,
            created_at: "".into(),
            updated_at: "".into(),
        },
        deployments,
    }
}

pub fn build_get_cage_deployment(
    build_status: BuildStatus,
    deploy_status: DeployStatus,
    started_at: Option<String>,
    completed_at: Option<String>,
) -> GetCageDeploymentResponse {
    GetCageDeploymentResponse {
        deployment: CageDeployment {
            uuid: "".into(),
            cage_uuid: "".into(),
            version_uuid: "".into(),
            signing_cert_uuid: "".into(),
            debug_mode: true,
            started_at: started_at.clone(),
            completed_at: completed_at.clone(),
        },
        tee_cage_version: CageVersion {
            uuid: "".into(),
            version: 0,
            control_plane_img_url: Some("".into()),
            control_plane_version: Some("".into()),
            data_plane_version: None,
            build_status,
            failure_reason: None,
            started_at: started_at.clone(),
            healthcheck: None,
        },
        tee_cage_signing_cert: CageSigningCert {
            name: Some("".into()),
            uuid: "".into(),
            app_uuid: "".into(),
            cert_hash: "".into(),
            not_before: None,
            not_after: None,
        },
        tee_cage_regional_deployments: vec![CageRegionalDeployment {
            uuid: "".into(),
            deployment_uuid: "".into(),
            deployment_order: 0,
            region: "".into(),
            failure_reason: None,
            deploy_status,
            started_at,
            completed_at,
            detailed_status: Some("".into()),
        }],
    }
}
