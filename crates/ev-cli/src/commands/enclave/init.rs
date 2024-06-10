use clap::{ArgGroup, Parser};
use common::{api::AuthMode, CliError};
use ev_enclave::api::enclave::{Enclave, EnclaveApi};
use ev_enclave::config::{
    default_dockerfile, EgressSettings, EnclaveConfig, ScalingSettings, SigningInfo,
};

/// Initialize an Enclave.toml in the current directory
#[derive(Debug, Parser)]
#[command(name = "init", about)]
#[clap(group(
  ArgGroup::new("signing-cert")
    .arg("cert_path")
    .requires("key_path")
))]
#[clap(group(
  ArgGroup::new("signing-key")
    .arg("key_path")
    .requires("cert_path")
))]
pub struct InitArgs {
    /// Directory to write the Enclave toml to. Defaults to the current directory.
    #[arg(short = 'o', long = "output", default_value = ".")]
    pub output_dir: String,

    /// Name of Enclave to deploy
    #[arg(long = "name")]
    pub enclave_name: String,

    /// Debug setting for the Enclave
    #[arg(long = "debug")]
    pub debug: bool,

    /// Flag to enable egress on your Enclave
    #[arg(long = "egress")]
    pub egress: bool,

    /// Dockerfile to build the Enclave
    #[arg(short = 'f', long = "file")]
    pub dockerfile: Option<String>,

    /// Path to the signing cert to use for the Enclave. If provided, the private-key must also be set.
    #[arg(long = "signing-cert")]
    pub cert_path: Option<String>,

    /// Path to the signing key to use for the Enclave. If provided, the signing-cert must also be set.
    #[arg(long = "private-key")]
    pub key_path: Option<String>,

    /// Flag to disable tls termination. This will pass the raw TCP streams directly to your service.
    #[arg(long = "disable-tls-termination")]
    pub disable_tls_termination: bool,

    /// Disable API key auth for your Enclave
    #[arg(long = "disable-api-key-auth")]
    pub disable_api_key_auth: bool,

    /// Disable transaction logging in your Enclave
    #[arg(long = "disable-trx-logging")]
    pub trx_logging_disabled: bool,

    /// Flag to make your Enclave delete after 6 hours
    #[arg(long = "self-destruct")]
    pub is_time_bound: bool,

    /// Comma separated list of destinations to allow traffic to from the Enclave e.g api.evervault.com, default is allow all
    #[arg(long = "egress-destinations")]
    pub egress_destinations: Option<String>,

    /// Enables forwarding proxy protocol when TLS Termination is disabled
    #[arg(long = "forward-proxy-protocol")]
    pub forward_proxy_protocol: bool,

    /// Trusted headers sent into the Enclave will be persisted without redaction in the Enclave's transaction logs
    #[arg(long = "trusted-headers")]
    pub trusted_headers: Option<String>,

    /// The healthcheck endpoint exposed by your service
    #[arg(long = "healthcheck")]
    pub healthcheck: Option<String>,

    /// The desired number of instances for your Enclave to use. Default is 2.
    #[arg(long = "desired-replicas")]
    pub desired_replicas: Option<u32>,
}

impl std::convert::From<InitArgs> for EnclaveConfig {
    fn from(val: InitArgs) -> Self {
        let signing_info = if val.cert_path.is_none() && val.key_path.is_none() {
            None
        } else {
            Some(SigningInfo {
                cert: val.cert_path,
                key: val.key_path,
            })
        };

        EnclaveConfig {
            name: val.enclave_name,
            uuid: None,
            app_uuid: None,
            team_uuid: None,
            version: 1,
            debug: val.debug,

            egress: EgressSettings::new(convert_comma_list(val.egress_destinations), val.egress),
            scaling: val
                .desired_replicas
                .map(|desired_replicas| ScalingSettings { desired_replicas }),
            dockerfile: val.dockerfile.unwrap_or_else(default_dockerfile), // need to manually set default dockerfile
            signing: signing_info,
            attestation: None,
            tls_termination: !val.disable_tls_termination,
            api_key_auth: !val.disable_api_key_auth,
            trx_logging: !val.trx_logging_disabled,
            forward_proxy_protocol: val.forward_proxy_protocol,
            trusted_headers: convert_comma_list(val.trusted_headers).unwrap_or_default(),
            healthcheck: val.healthcheck,
        }
    }
}

fn convert_comma_list(maybe_str: Option<String>) -> Option<Vec<String>> {
    maybe_str.map(|str| str.split(',').map(|value| value.to_string()).collect())
}

pub async fn run(init_args: InitArgs, api_key: String) -> exitcode::ExitCode {
    let enclave_client =
        ev_enclave::api::enclave::EnclaveClient::new(AuthMode::ApiKey(api_key.clone()));

    let create_enclave_request = ev_enclave::api::enclave::CreateEnclaveRequest::new(
        init_args.enclave_name.clone(),
        init_args.is_time_bound,
    );
    let created_enclave = match enclave_client.create_enclave(create_enclave_request).await {
        Ok(enclave_ref) => enclave_ref,
        Err(e) => {
            log::error!("Error creating Enclave record — {e:?}");
            return e.exitcode();
        }
    };

    init_local_config(init_args, created_enclave).await
}

async fn init_local_config(init_args: InitArgs, created_enclave: Enclave) -> exitcode::ExitCode {
    let output_dir = init_args.output_dir.clone();
    let output_path = std::path::Path::new(output_dir.as_str());
    let config_path = output_path.join("enclave.toml");

    let mut initial_config: EnclaveConfig = init_args.into();
    initial_config.annotate(created_enclave);

    if initial_config.signing.is_none() {
        log::info!("Generating signing credentials for enclave");
        match crate::cert::create_new_cert(
            output_path,
            crate::cert::DistinguishedName::default(),
            crate::cert::DesiredLifetime::default(),
        ) {
            Ok((cert_path, key_path)) => {
                initial_config.set_cert(format!("{}", cert_path.display()));
                initial_config.set_key(format!("{}", key_path.display()));
            }
            Err(e) => {
                log::error!("Failed to generate Enclave signing credentials - {e}");
                return e.exitcode();
            }
        }
    }

    let serialized_config = match toml::ser::to_vec(&initial_config) {
        Ok(bytes) => bytes,
        Err(e) => {
            log::error!("Error serializing enclave.toml — {:?}", e);
            return exitcode::SOFTWARE;
        }
    };

    if let Err(e) = std::fs::write(config_path, serialized_config) {
        log::error!("Error writing enclave.toml — {:?}", e);
        exitcode::IOERR
    } else {
        log::info!("Enclave.toml initialized successfully. You can now deploy an Enclave using the deploy command");
        exitcode::OK
    }
}

#[cfg(test)]
mod init_tests {
    use super::*;
    use ev_enclave::api::enclave::EnclaveState;

    use std::fs::read;
    use tempfile::TempDir;

    #[tokio::test]
    async fn init_local_config_test() {
        let output_dir = TempDir::new().unwrap();
        let sample_enclave = Enclave {
            uuid: "1234".into(),
            name: "hello-enclave".into(),
            team_uuid: "1234".into(),
            app_uuid: "1234".into(),
            domain: "hello.com".into(),
            state: EnclaveState::Pending,
            created_at: "00:00:00".into(),
            updated_at: "00:00:00".into(),
        };
        let init_args = InitArgs {
            output_dir: output_dir.path().to_str().unwrap().to_string(),
            enclave_name: "hello".to_string(),
            debug: false,
            egress: true,
            desired_replicas: Some(2),
            dockerfile: Some("Dockerfile".into()),
            disable_tls_termination: false,
            cert_path: Some("./cert.pem".to_string()),
            key_path: Some("./key.pem".to_string()),
            is_time_bound: false,
            disable_api_key_auth: false,
            trx_logging_disabled: false,
            egress_destinations: Some("evervault.com".to_string()),
            forward_proxy_protocol: false,
            trusted_headers: Some("X-Evervault-*".to_string()),
            healthcheck: None,
        };
        init_local_config(init_args, sample_enclave).await;
        let config_path = output_dir.path().join("enclave.toml");
        assert!(config_path.exists());
        let config_content = String::from_utf8(read(config_path).unwrap()).unwrap();
        let expected_config_content = r#"version = 1
name = "hello"
uuid = "1234"
app_uuid = "1234"
team_uuid = "1234"
debug = false
dockerfile = "Dockerfile"
api_key_auth = true
trx_logging = true
tls_termination = true
forward_proxy_protocol = false
trusted_headers = ["X-Evervault-*"]

[egress]
enabled = true
destinations = ["evervault.com"]

[scaling]
desired_replicas = 2

[signing]
certPath = "./cert.pem"
keyPath = "./key.pem"
"#;
        assert_eq!(config_content, expected_config_content);
    }
}
