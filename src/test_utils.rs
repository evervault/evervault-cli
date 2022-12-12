use crate::api::assets::AssetsClient;
use crate::build::build_enclave_image_file;
use crate::build::error::BuildError;
use crate::common::OutputPath;
use crate::config::{EgressSettings, ValidatedCageBuildConfig, ValidatedSigningInfo};
use crate::enclave::BuiltEnclave;

pub async fn build_test_cage(
    output_dir: Option<&str>,
) -> Result<(BuiltEnclave, OutputPath), BuildError> {
    let dn_string = crate::cert::DistinguishedName::default();
    crate::cert::create_new_cert(".".into(), dn_string).expect("Failed to gen cert in tests");
    let build_args = get_test_build_args();
    let assets_client = AssetsClient::new();
    let data_plane_version = assets_client.get_latest_data_plane_version().await.unwrap();
    build_enclave_image_file(
        &build_args,
        ".",
        output_dir,
        false,
        None,
        data_plane_version,
    )
    .await
}

fn get_test_build_args() -> ValidatedCageBuildConfig {
    ValidatedCageBuildConfig {
        cage_name: "test-cage".into(),
        cage_uuid: "1234".into(),
        app_uuid: "4321".into(),
        team_uuid: "teamid".into(),
        debug: false,
        egress: EgressSettings {
            enabled: false,
            destinations: None,
        },
        dockerfile: "./sample-user.Dockerfile".to_string(),
        signing: ValidatedSigningInfo {
            cert: "./cert.pem".into(),
            key: "./key.pem".into(),
        },
        attestation: None,
        disable_tls_termination: false,
    }
}
