use crate::encrypt;
use clap::Parser;

#[derive(Clone, Debug, clap::ArgEnum)]
pub enum CurveName {
    Koblitz,
    Nist,
}

/// Encrypt a string
#[derive(Debug, Parser)]
#[clap(name = "encrypt", about)]
pub struct EncryptArgs {
    // Plaintext value to encrypt
    #[clap(long = "value")]
    pub value: String,

    // Curve to use, options are nist or koblitz
    #[clap(arg_enum, default_value = "nist")]
    pub curve: CurveName,

    #[clap(long = "team_uuid")]
    pub team_uuid: String,

    #[clap(long = "app_uuid")]
    pub app_uuid: String,
}

pub async fn run(encrypt_args: EncryptArgs) -> exitcode::ExitCode {
    match encrypt::encrypt(
        encrypt_args.value,
        encrypt_args.team_uuid,
        encrypt_args.app_uuid,
        encrypt_args.curve,
    )
    .await
    {
        Ok(encrypted_string) => {
            println!("{}", encrypted_string);
            exitcode::OK
        },
        Err(e) => {
            println!("{}", e);
            exitcode::SOFTWARE
        },
    }
}
