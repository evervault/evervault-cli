use crate::api;
use crate::api::cage::CreateCageRequest;
use crate::api::{cage::Cage, AuthMode};
use crate::common::CliError;
use crate::config::{default_dockerfile, CageConfig, EgressSettings, SigningInfo};
use crate::get_api_key;
use clap::{ArgGroup, Parser};

/// Initialize a Cage.toml in the current directory
#[derive(Debug, Parser)]
#[clap(name = "init", about)]
#[clap(group(
  ArgGroup::new("signing-cert")
    .arg("cert-path")
    .requires("key-path")
))]
#[clap(group(
  ArgGroup::new("signing-key")
    .arg("key-path")
    .requires("cert-path")
))]
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
    #[clap(long = "egress")]
    pub egress: bool,

    /// Dockerfile to build the Cage
    #[clap(short = 'f', long = "file")]
    pub dockerfile: Option<String>,

    /// Path to the signing cert to use for the Cage. If provided, the private-key must also be set.
    #[clap(long = "signing-cert")]
    pub cert_path: Option<String>,

    /// Path to the signing key to use for the Cage. If provided, the signing-cert must also be set.
    #[clap(long = "private-key")]
    pub key_path: Option<String>,

    /// Flag to disable tls termination. This will pass the raw TCP streams directly to your service.
    #[clap(long = "disable-tls-termination")]
    pub disable_tls_termination: bool,

    /// Disable API key auth for your Cage
    #[clap(long = "disable-api-key-auth")]
    pub disable_api_key_auth: bool,

    /// Flag to make your Cage delete after 6 hours
    #[clap(long = "self-destruct")]
    pub is_time_bound: bool,
}

impl std::convert::From<InitArgs> for CageConfig {
    fn from(val: InitArgs) -> Self {
        let signing_info = if val.cert_path.is_none() && val.key_path.is_none() {
            None
        } else {
            Some(SigningInfo {
                cert: val.cert_path,
                key: val.key_path,
            })
        };

        CageConfig {
            name: val.cage_name,
            uuid: None,
            app_uuid: None,
            team_uuid: None,
            debug: val.debug,
            egress: EgressSettings {
                enabled: val.egress,
                destinations: None,
            },
            dockerfile: val.dockerfile.unwrap_or_else(default_dockerfile), // need to manually set default dockerfile
            signing: signing_info,
            attestation: None,
            disable_tls_termination: val.disable_tls_termination,
            api_key_auth: !val.disable_api_key_auth,
        }
    }
}

pub async fn run(init_args: InitArgs) -> exitcode::ExitCode {
    let api_key = get_api_key!();
    let cages_client = api::cage::CagesClient::new(AuthMode::ApiKey(api_key.clone()));

    let create_cage_request =
        CreateCageRequest::new(init_args.cage_name.clone(), init_args.is_time_bound);
    let created_cage = match cages_client.create_cage(create_cage_request).await {
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

    let output_dir = init_args.output_dir.clone();

    let mut initial_config: CageConfig = init_args.into();
    initial_config.annotate(created_cage);

    if initial_config.signing.is_none() {
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
            cert_path: Some("./cert.pem".to_string()),
            key_path: Some("./key.pem".to_string()),
            is_time_bound: false,
            disable_api_key_auth: false,
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
api_key_auth = true
disable_tls_termination = false

[egress]
enabled = true

[signing]
certPath = "./cert.pem"
keyPath = "./key.pem"
"#;
        assert_eq!(config_content, expected_config_content);
    }
}
