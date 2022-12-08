use crate::{
    config::CageConfig,
    encrypt::{self, EncryptError},
};
use clap::Parser;

#[derive(Clone, Debug, clap::ArgEnum)]
pub enum CurveName {
    Koblitz,
    Nist,
    Secp256r1,
    Secp256k1,
}

/// Encrypt a string
#[derive(Debug, Parser, Clone)]
#[clap(name = "encrypt", about)]
pub struct EncryptArgs {
    // Plaintext value to encrypt
    pub value: String,

    // Curve to use, options are Secp256r1 (alias nist) or Secp256k1 (alias koblitz)
    #[clap(arg_enum, default_value = "nist", long = "curve")]
    pub curve: CurveName,

    #[clap(long = "team_uuid")]
    pub team_uuid: Option<String>,

    #[clap(long = "app_uuid")]
    pub app_uuid: Option<String>,

    // Path to cage.toml config file
    #[clap(short = 'c', long = "config", default_value = "./cage.toml")]
    pub config: String,
}

pub async fn run(encrypt_args: EncryptArgs) -> exitcode::ExitCode {
    let (team_uuid, app_uuid) = match get_cage_details(encrypt_args.clone()) {
        Ok((team_uuid, app_uuid)) => (team_uuid, app_uuid),
        Err(e) => {
            log::error!("Config error {}", e);
            return exitcode::SOFTWARE;
        }
    };
    match encrypt::encrypt(encrypt_args.value, team_uuid, app_uuid, encrypt_args.curve).await {
        Ok(encrypted_string) => {
            println!("{}", encrypted_string);
            exitcode::OK
        }
        Err(e) => {
            log::info!("{}", e);
            exitcode::SOFTWARE
        }
    }
}

fn get_cage_details(encrypt_args: EncryptArgs) -> Result<(String, String), EncryptError> {
    if encrypt_args.team_uuid.is_none() || encrypt_args.app_uuid.is_none() {
        let cage_config = CageConfig::try_from_filepath(&encrypt_args.config)?;

        if cage_config.app_uuid.is_none() || cage_config.team_uuid.is_none() {
            Err(EncryptError::MissingUuid)
        } else {
            Ok((
                cage_config.team_uuid.unwrap(),
                cage_config.app_uuid.unwrap(),
            ))
        }
    } else {
        Ok((
            encrypt_args.team_uuid.unwrap(),
            encrypt_args.app_uuid.unwrap(),
        ))
    }
}
