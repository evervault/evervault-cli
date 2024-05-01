use crate::cert::{self, DistinguishedName};
use crate::common::CliError;
use crate::config::EnclaveConfig;
use crate::get_api_key;
use crate::version::check_version;
use atty::Stream;
use clap::{Parser, Subcommand};
use exitcode::DATAERR;

/// Manage Enclave signing certificates
#[derive(Debug, Parser)]
#[command(name = "cert", about)]
pub struct CertArgs {
    #[command(subcommand)]
    action: CertCommands,
}

#[derive(Debug, Subcommand)]
pub enum CertCommands {
    /// Create a new Enclave signing certificate
    #[command()]
    New(NewCertArgs),
    /// Upload a Enclave signing certificate's metadata to Evervault
    #[command()]
    Upload(UploadCertArgs),
    /// Lock a Enclave to specific signing certificate. Enclave deployment will fail if the signing certificate is not the one specified.
    #[command()]
    Lock(LockCertArgs),
}

#[derive(Parser, Debug)]
#[command(name = "new", about)]
pub struct NewCertArgs {
    /// Path to directory where the signing cert will be saved
    #[arg(short = 'o', long = "output", default_value = ".")]
    pub output_dir: String,

    /// Defining the certificate distinguished name e.g. "/CN=EV/C=IE/ST=LEI/L=DUB/O=Evervault/OU=Eng". If not given, a generic Enclaves subject will be used.
    #[arg(long = "subj")]
    pub subject: Option<String>,
}

#[derive(Parser, Debug)]
#[command(name = "upload", about)]
pub struct UploadCertArgs {
    /// Path to directory where the signing cert will be saved
    #[arg(short = 'p', long = "cert_path")]
    pub cert_path: Option<String>,

    /// Name to attach to cert reference
    #[arg(long = "name")]
    pub name: String,

    /// Path to enclave.toml config file
    #[arg(short = 'c', long = "config", default_value = "./enclave.toml")]
    pub config: String,
}

#[derive(Parser, Debug)]
#[command(name = "lock", about)]
pub struct LockCertArgs {
    /// Path to enclave.toml config file
    #[arg(short = 'c', long = "config", default_value = "./enclave.toml")]
    pub config: String,
}

pub async fn run(cert_args: CertArgs) -> exitcode::ExitCode {
    if let Err(e) = check_version().await {
        log::error!("{e}");
        return exitcode::SOFTWARE;
    };

    match cert_args.action {
        CertCommands::New(new_args) => {
            let distinguished_name =
                match try_resolve_distinguished_name(new_args.subject.as_deref()) {
                    Ok(distinguished_name) => distinguished_name,
                    Err(e) => {
                        log::error!("{e}");
                        return e.exitcode();
                    }
                };
            let output_path = std::path::Path::new(&new_args.output_dir);
            let (cert_path, key_path) = match cert::create_new_cert(output_path, distinguished_name)
            {
                Ok(paths) => paths,
                Err(e) => {
                    log::error!("An error occurred while generating your cert - {e}");
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
        CertCommands::Upload(upload_args) => {
            let api_key = get_api_key!();

            let cert_path = match upload_args.cert_path {
                Some(cert_path) => cert_path,
                None => match EnclaveConfig::try_from_filepath(&upload_args.config) {
                    Ok(enclave_config) => match enclave_config.signing {
                        Some(signing_info) if signing_info.cert.is_some() => {
                            signing_info.cert.unwrap()
                        }
                        _ => {
                            log::error!("No signing info found in enclave.toml");
                            return DATAERR;
                        }
                    },
                    Err(e) => {
                        log::error!("An error occurred while reading enclave.toml - {e}");
                        return e.exitcode();
                    }
                },
            };

            let cert_ref =
                match cert::upload_new_cert_ref(&cert_path, &api_key, upload_args.name).await {
                    Ok(pcr8) => pcr8,
                    Err(e) => {
                        log::error!("An error occurred while generating PCR8 for your cert - {e}");
                        return e.exitcode();
                    }
                };

            if atty::is(Stream::Stdout) {
                log::info!("PCR8: {}", cert_ref.cert_hash());
                log::info!("Not Before: {}", cert_ref.not_before());
                log::info!("Not After: {}", cert_ref.not_after());
                log::info!("Certificate metadata uploaded to Evervault");
            } else {
                let success_msg = serde_json::json!({
                    "status": "success",
                    "output": cert_ref,
                });
                println!("{}", serde_json::to_string(&success_msg).unwrap());
            };
        }
        CertCommands::Lock(lock_cert_args) => {
            let api_key = get_api_key!();

            let (enclave_uuid, enclave_name) =
                match EnclaveConfig::try_from_filepath(&lock_cert_args.config) {
                    Ok(enclave_config) => match (enclave_config.uuid, enclave_config.name) {
                        (Some(uuid), name) => (uuid, name),
                        _ => {
                            log::error!("No Enclave details found in enclave.toml");
                            return DATAERR;
                        }
                    },
                    Err(_) => {
                        log::error!("Failed to load Enclave configuration");
                        return DATAERR;
                    }
                };

            if let Err(e) =
                cert::lock_enclave_to_certs(&api_key, &enclave_uuid, &enclave_name).await
            {
                return e.exitcode();
            }
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
