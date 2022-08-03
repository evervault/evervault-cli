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
    #[clap(long = "certificate")]
    pub cert_path: Option<String>,

    /// Path to the signing key to use for the Cage
    #[clap(long = "key")]
    pub key_path: Option<String>,
}

impl std::convert::Into<CageConfig> for InitArgs {
    fn into(self: Self) -> CageConfig {
        CageConfig {
            name: self.cage_name,
            debug: self.debug,
            egress: EgressSettings {
                enabled: self.egress,
                destinations: self
                    .destinations
                    .map(|dest| dest.split(",").map(String::from).collect::<Vec<String>>()),
            },
            dockerfile: self.dockerfile,
            signing: Some(SigningInfo {
                cert: self.cert_path,
                key: self.key_path,
            }),
            attestation: None,
        }
    }
}

pub fn run(init_args: InitArgs) {
    let initial_config: CageConfig = init_args.into();

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
