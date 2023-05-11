use crate::api::assets::AssetsClient;
use crate::build::build_enclave_image_file;
use crate::build::error::BuildError;
use crate::common::OutputPath;
use crate::config::{read_and_validate_config, ValidatedCageBuildConfig};
use crate::enclave::BuiltEnclave;

pub async fn build_test_cage(
    output_dir: Option<&str>,
    from_existing: Option<String>,
) -> Result<(BuiltEnclave, OutputPath), BuildError> {
    let dn_string = crate::cert::DistinguishedName::default();
    crate::cert::create_new_cert(std::path::Path::new("."), dn_string)
        .expect("Failed to gen cert in tests");
    let build_args = get_test_build_args();
    let assets_client = AssetsClient::new();

    let data_plane_version = assets_client.get_latest_data_plane_version().await.unwrap();
    let installer_version = assets_client.get_latest_installer_version().await.unwrap();
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
    )
    .await
}

fn get_test_build_args() -> ValidatedCageBuildConfig {
    let (_cage_config, validated_config) = read_and_validate_config("./test.cage.toml", &())
        .expect("Testing config failed to validate");
    validated_config
}
