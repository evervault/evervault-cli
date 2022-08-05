use crate::api;
use crate::api::{client::ApiClient, AuthMode};
use crate::config::{CageConfig, EgressSettings, SigningInfo};
use clap::{ArgGroup, Parser};

/// Initialize a Cage.toml in the current directory
#[derive(Debug, Parser)]
#[clap(name = "init", about)]
#[clap(group(
  ArgGroup::new("egress-destinations")
    .arg("destinations")
    .requires("egress")
))]
pub struct InitArgs {
    /// Name of Cage to deploy
    #[clap(long = "name")]
    pub cage_name: String,

    /// Debug setting for the Cage
    #[clap(long = "debug")]
    pub debug: bool,

    /// Flag to enable egress on your Cage
    #[clap(long = "egress-enabled")]
    pub egress: bool,

    /// Destinations to allow egress traffic to, comma separated e.g. api.evervault.com,httpbin.org
    #[clap(long = "destinations")]
    pub destinations: Option<String>,

    /// Dockerfile to build the Cage
    #[clap(short = 'f', long = "file")]
    pub dockerfile: Option<String>,

    /// Path to the signing cert to use for the Cage
    #[clap(long = "signing-cert")]
    pub cert_path: Option<String>,

    /// Path to the signing key to use for the Cage
    #[clap(long = "private-key")]
    pub key_path: Option<String>,

    /// API key to be used for the api calls
    #[clap(long = "api-key")]
    pub api_key: String,
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
            debug: self.debug,
            egress: EgressSettings {
                enabled: self.egress,
                destinations: self
                    .destinations
                    .map(|dest| dest.split(",").map(String::from).collect::<Vec<String>>()),
            },
            dockerfile: self.dockerfile,
            signing: signing_info,
            attestation: None,
        }
    }
}

pub async fn run(init_args: InitArgs) {
    let cages_client = api::cage::CagesClient::new(AuthMode::ApiKey(init_args.api_key.clone()));

    let created_cage = match cages_client
        .create_cage(init_args.cage_name.clone().into())
        .await
    {
        Ok(cage_ref) => cage_ref,
        Err(e) => {
            eprintln!("Error creating Cage record — {:?}", e);
            return;
        }
    };

    let mut initial_config: CageConfig = init_args.into();
    initial_config.annotate(created_cage);

    let config_path = std::path::Path::new("./cage.toml");

    let serialized_config = match toml::ser::to_vec(&initial_config) {
        Ok(bytes) => bytes,
        Err(e) => {
            eprintln!("Error serializing cage.toml — {:?}", e);
            return;
        }
    };

    if let Err(e) = std::fs::write(config_path, serialized_config) {
        eprintln!("Error writing cage.toml — {:?}", e);
    }
}
