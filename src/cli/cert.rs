use crate::cert::{self, DistinguishedName};
use crate::common::CliError;
use atty::Stream;
use clap::{Parser, Subcommand};

/// Manage Cage signing certificates
#[derive(Debug, Parser)]
#[clap(name = "cert", about)]
pub struct CertArgs {
    #[clap(subcommand)]
    action: CertCommands,
}

#[derive(Debug, Subcommand)]
pub enum CertCommands {
    /// Create a new Cage signing certificate
    #[clap()]
    New(NewCertArgs),
}

#[derive(Parser, Debug)]
#[clap(name = "new", about)]
pub struct NewCertArgs {
    /// Path to directory where the signing cert will be saved
    #[clap(short = 'o', long = "output", default_value = ".")]
    pub output_dir: String,

    /// Defining the certificate distinguished name e.g. "/CN=EV/C=IE/ST=LEI/L=DUB/O=Evervault/OU=Eng". If not given, a generic Cages subject will be used.
    #[clap(long = "subj")]
    pub subject: Option<String>,
}

pub fn run(cert_args: CertArgs) -> exitcode::ExitCode {
    match cert_args.action {
        CertCommands::New(new_args) => {
            let distinguished_name =
                match try_resolve_distinguished_name(new_args.subject.as_deref()) {
                    Ok(distinguished_name) => distinguished_name,
                    Err(e) => {
                        log::error!("{}", e);
                        return e.exitcode();
                    }
                };
            let output_path = std::path::Path::new(&new_args.output_dir);
            let (cert_path, key_path) = match cert::create_new_cert(output_path, distinguished_name)
            {
                Ok(paths) => paths,
                Err(e) => {
                    log::error!("An error occurred while generating your cert - {}", e);
                    return e.exitcode();
                }
            };

            if atty::is(Stream::Stdout) {
                log::info!("Signing cert successfully generated...");
                log::info!("> Certificate saved to {}", cert_path.display());
                log::info!("> Key saved to {}", key_path.display());
            } else {
                let success_msg = serde_json::json!({
                    "status": "success",
                    "output": {
                        "certificate": cert_path,
                        "privateKey": key_path
                    }
                });
                println!("{}", serde_json::to_string(&success_msg).unwrap());
            };
        }
    }

    exitcode::OK
}

fn try_resolve_distinguished_name(
    subj: Option<&str>,
) -> Result<DistinguishedName, cert::CertError> {
    let dn = match subj {
        Some(subj) => cert::DnBuilder::from(subj).try_into()?,
        None => DistinguishedName::default(),
    };
    Ok(dn)
}
