use crate::api;
use crate::api::{cage::Cage, client::ApiClient, AuthMode};
use crate::common::CliError;
use crate::config::{default_dockerfile, CageConfig, EgressSettings, SigningInfo};
use crate::get_api_key;
use clap::Parser;

/// Initialize a Cage.toml in the current directory
#[derive(Debug, Parser)]
#[clap(name = "init", about)]
pub struct InitArgs {
    /// Directory to write the Cage toml to. Defaults to the current directory.
    #[clap(short = 'o', long = "output", default_value = ".")]
    pub output_dir: String,

    /// Name of Cage to deploy
    #[clap(long = "name")]
    pub cage_name: String,

    /// Debug setting for the Cage
    #[clap(long = "debug")]
    pub debug: bool,

    /// Flag to enable egress on your Cage
    #[clap(long = "egress-enabled")]
    pub egress: bool,

    /// Dockerfile to build the Cage
    #[clap(short = 'f', long = "file")]
    pub dockerfile: Option<String>,

    /// Path to the signing cert to use for the Cage
    #[clap(long = "signing-cert")]
    pub cert_path: Option<String>,

    /// Path to the signing key to use for the Cage
    #[clap(long = "private-key")]
    pub key_path: Option<String>,

    /// Flag to enable cert generation during init. This will use the default certificate.
    #[clap(long = "generate-signing")]
    pub gen_signing_credentials: bool,

    /// Flag to disable tls termination. This will pass the raw TCP streams directly to your service.
    #[clap(long = "disable-tls-termination")]
    pub disable_tls_termination: bool,
}

impl std::convert::Into<CageConfig> for InitArgs {
    fn into(self: Self) -> CageConfig {
        let signing_info = if self.cert_path.is_none() && self.key_path.is_none() {
            None
        } else {
            Some(SigningInfo {
                cert: self.cert_path,
                key: self.key_path,
            })
        };

        CageConfig {
            name: self.cage_name,
            uuid: None,
            app_uuid: None,
            team_uuid: None,
            debug: self.debug,
            egress: EgressSettings {
                enabled: self.egress,
                destinations: None,
            },
            dockerfile: self.dockerfile.unwrap_or_else(default_dockerfile), // need to manually set default dockerfile
            signing: signing_info,
            attestation: None,
            disable_tls_termination: self.disable_tls_termination,
        }
    }
}

pub async fn run(init_args: InitArgs) -> exitcode::ExitCode {
    let api_key = get_api_key!();
    let cages_client = api::cage::CagesClient::new(AuthMode::ApiKey(api_key.clone()));

    let created_cage = match cages_client
        .create_cage(init_args.cage_name.clone().into())
        .await
    {
        Ok(cage_ref) => cage_ref,
        Err(e) => {
            log::error!("Error creating Cage record — {:?}", e);
            return e.exitcode();
        }
    };

    init_local_config(init_args, created_cage).await
}

async fn init_local_config(init_args: InitArgs, created_cage: Cage) -> exitcode::ExitCode {
    let output_path = std::path::Path::new(init_args.output_dir.as_str());
    let config_path = output_path.join("cage.toml");

    let gen_signing_credentials = init_args.gen_signing_credentials;
    let output_dir = init_args.output_dir.clone();

    let mut initial_config: CageConfig = init_args.into();
    initial_config.annotate(created_cage);

    if gen_signing_credentials && initial_config.signing.is_none() {
        log::info!("Generating signing credentials for cage");
        match crate::cert::create_new_cert(
            output_dir.as_str(),
            crate::cert::DistinguishedName::default(),
        ) {
            Ok((cert_path, key_path)) => {
                initial_config.set_cert(format!("{}", cert_path.display()));
                initial_config.set_key(format!("{}", key_path.display()));
            }
            Err(e) => {
                log::error!("Failed to generate cage signing credentials - {}", e);
                return e.exitcode();
            }
        }
    }

    let serialized_config = match toml::ser::to_vec(&initial_config) {
        Ok(bytes) => bytes,
        Err(e) => {
            log::error!("Error serializing cage.toml — {:?}", e);
            return exitcode::SOFTWARE;
        }
    };

    if let Err(e) = std::fs::write(config_path, serialized_config) {
        log::error!("Error writing cage.toml — {:?}", e);
        exitcode::IOERR
    } else {
        log::info!("Cage.toml initialized successfully. You can now deploy a Cage using the deploy command");
        exitcode::OK
    }
}

#[cfg(test)]
mod init_tests {
    use super::*;
    use crate::api::cage::CageState;

    use std::fs::read;
    use tempfile::TempDir;

    #[tokio::test]
    async fn init_local_config_test() {
        let output_dir = TempDir::new().unwrap();
        let sample_cage = Cage {
            uuid: "1234".into(),
            name: "hello-cage".into(),
            team_uuid: "1234".into(),
            app_uuid: "1234".into(),
            domain: "hello.com".into(),
            state: CageState::Pending,
            created_at: "00:00:00".into(),
            updated_at: "00:00:00".into(),
        };
        let init_args = InitArgs {
            output_dir: output_dir.path().to_str().unwrap().to_string(),
            cage_name: "hello".to_string(),
            debug: false,
            egress: true,
            dockerfile: Some("Dockerfile".into()),
            disable_tls_termination: false,
            gen_signing_credentials: false,
            cert_path: None,
            key_path: None,
        };
        init_local_config(init_args, sample_cage).await;
        let config_path = output_dir.path().join("cage.toml");
        assert!(config_path.exists());
        let config_content = String::from_utf8(read(config_path).unwrap()).unwrap();
        println!("cage_config_content: {}", config_content);
        let expected_config_content = r#"name = "hello"
uuid = "1234"
app_uuid = "1234"
team_uuid = "1234"
debug = false
dockerfile = "Dockerfile"
disable_tls_termination = false

[egress]
enabled = true
"#;
        assert_eq!(config_content, expected_config_content);
    }
}
