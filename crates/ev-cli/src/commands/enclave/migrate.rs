use clap::Parser;
use ev_enclave::migrate::migrate_toml;
/// Migrate an Enclave toml from v0 to v1
#[derive(Parser, Debug)]
#[command(name = "migrate", about)]
pub struct MigrateArgs {
    /// Path to the toml file containing the Enclave's config
    #[arg(short = 'c', long = "config", default_value = "./cage.toml")]
    pub config: String,

    /// Path to the new toml created by the migration
    #[arg(short = 'o', long = "output")]
    pub output: Option<String>,
}

pub async fn run(args: MigrateArgs) -> exitcode::ExitCode {
    let serialized_config = match migrate_toml(&args.config) {
        Ok(bytes) => bytes,
        Err(e) => {
            log::error!("{}", e);
            return exitcode::SOFTWARE;
        }
    };

    let output_path = match args.output {
        Some(path) => path,
        None => args.config.clone(),
    };
    if let Err(e) = std::fs::write(&output_path, serialized_config) {
        log::error!("Error writing enclave.toml — {}", e);
        exitcode::IOERR
    } else {
        log::info!("Enclave.toml migrated successfully. You can now deploy a V1 Enclave using the deploy command");
        exitcode::OK
    }
}

#[cfg(test)]
mod migrate_tests {

    use std::fs::read;
    use tempfile::TempDir;

    use crate::commands::enclave::migrate::{run, MigrateArgs};

    #[tokio::test]
    async fn test_migrate_v0_to_v1() {
        let output_dir = TempDir::new().unwrap();
        let output_file = output_dir.path().join("v1.enclave.toml");
        let args = MigrateArgs {
            config: "../../fixtures/v0.cage.toml".into(),
            output: Some(output_file.to_str().unwrap().to_string()),
        };
        run(args).await;
        assert!(output_file.exists());
        let config_content = String::from_utf8(read(output_file).unwrap()).unwrap();
        let expected_config_content = r#"version = 1
name = "test-enclave"
uuid = "1234"
app_uuid = "4321"
team_uuid = "teamid"
debug = false
dockerfile = "./sample-user.Dockerfile"
api_key_auth = true
trx_logging = true
tls_termination = true
forward_proxy_protocol = false
trusted_headers = ["X-Evervault-*"]

[egress]
enabled = true
destinations = ["*"]

[signing]
certPath = "../../fixtures/cert.pem"
keyPath = "../../fixtures/key.pem"

[attestation]
HashAlgorithm = "Sha384 { ... }"
PCR0 = "1cd2135a6358458e390904fac3568eff4e6c7882c22e7925a830c8ba6b9b1ae117dd714cad64b1001475923a242fc887"
PCR1 = "bcdf05fefccaa8e55bf2c8d6dee9e79bbff31e34bf28a99aa19e6b29c37ee80b214a414b7607236edf26fcb78654e63f"
PCR2 = "42997b22af1f96a6b32372402af03a5d16e47316e7990314bdb01c0759fa11a7ae88e3ae2f3628b1c1ab734ea2f2ba34"
PCR8 = "a94237284c822603176cfe5abbf62664a786b8eef7c5ead7ff725fc2750f06520ce775fec55405ac1837cf2c42e1443a"
"#;
        assert_eq!(config_content, expected_config_content);
    }
}
