use crate::api::assets::AssetsClient;
use crate::build::build_enclave_image_file;
use crate::build::error::BuildError;
use crate::common::OutputPath;
use crate::config::{read_and_validate_config, ValidatedCageBuildConfig};
use crate::enclave::BuiltEnclave;

pub async fn build_test_cage(
    output_dir: Option<&str>,
    reproducible: bool,
    pin_versions: bool,
) -> Result<(BuiltEnclave, OutputPath), BuildError> {
    let dn_string = crate::cert::DistinguishedName::default();
    crate::cert::create_new_cert(std::path::Path::new("."), dn_string)
        .expect("Failed to gen cert in tests");
    let build_args = get_test_build_args();
    let assets_client = AssetsClient::new();

    // When testing reproducible builds, use pinned versions to avoid breaking the test on every release.
    let data_plane_version = if reproducible && pin_versions {
        "0.0.21".to_string()
    } else {
        assets_client.get_latest_data_plane_version().await.unwrap()
    };
    let installer_version = if reproducible && pin_versions {
        "701ea2dbdf708c12172c668af9c1d2b703bfcc95".to_string()
    } else {
        assets_client.get_latest_installer_version().await.unwrap()
    };

    build_enclave_image_file(
        &build_args,
        ".",
        output_dir,
        false,
        None,
        reproducible,
        data_plane_version,
        installer_version,
    )
    .await
}

fn get_test_build_args() -> ValidatedCageBuildConfig {
    let (_cage_config, validated_config) = read_and_validate_config("./test.cage.toml", &())
        .expect("Testing config failed to validate");
    validated_config
}
