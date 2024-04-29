use crate::version::check_version;
use crate::{
    config::EnclaveConfig,
    encrypt::{self, EncryptError},
};
use clap::{Parser, ValueEnum};

#[derive(Clone, Debug, ValueEnum)]
pub enum CurveName {
    Koblitz,
    Nist,
    Secp256r1,
    Secp256k1,
}

impl Default for CurveName {
    fn default() -> Self {
        CurveName::Nist
    }
}

/// Encrypt a string
#[derive(Debug, Parser, Clone)]
#[command(name = "encrypt", about)]
pub struct EncryptArgs {
    /// Plaintext value to encrypt
    pub value: String,

    /// Curve to use, options are Secp256r1 (alias nist) or Secp256k1 (alias koblitz)
    #[arg(long = "curve", value_enum)]
    pub curve: CurveName,

    #[arg(long = "team-uuid")]
    pub team_uuid: Option<String>,

    #[arg(long = "app-uuid")]
    pub app_uuid: Option<String>,

    /// Path to enclave.toml config file
    #[arg(short = 'c', long = "config", default_value = "./enclave.toml")]
    pub config: String,
}

pub async fn run(encrypt_args: EncryptArgs) -> exitcode::ExitCode {
    if let Err(e) = check_version().await {
        log::error!("{e}");
        return exitcode::SOFTWARE;
    };

    let (team_uuid, app_uuid) = match get_enclave_details(encrypt_args.clone()) {
        Ok((team_uuid, app_uuid)) => (team_uuid, app_uuid),
        Err(e) => {
            log::error!("Config error {e}");
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

fn get_enclave_details(encrypt_args: EncryptArgs) -> Result<(String, String), EncryptError> {
    if encrypt_args.team_uuid.is_none() || encrypt_args.app_uuid.is_none() {
        let enclave_config = EnclaveConfig::try_from_filepath(&encrypt_args.config)?;

        if enclave_config.app_uuid.is_none() || enclave_config.team_uuid.is_none() {
            Err(EncryptError::MissingUuid)
        } else {
            Ok((
                enclave_config.team_uuid.unwrap(),
                enclave_config.app_uuid.unwrap(),
            ))
        }
    } else {
        Ok((
            encrypt_args.team_uuid.unwrap(),
            encrypt_args.app_uuid.unwrap(),
        ))
    }
}
