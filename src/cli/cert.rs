use atty::Stream;
use chrono::Datelike;
use std::io::Write;
use std::ops::Add;
use thiserror::Error;

use clap::{Parser, Subcommand};
use itertools::Itertools;
use rcgen::CertificateParams;

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

    /// Defining the certificate distinguished name e.g. "/CN=EV/C=IE/ST=LEI/L=DUB/O=Evervault/OU=Eng"
    #[clap(long = "subj")]
    pub subject: String,
}

#[derive(Debug, Error)]
enum CertError {
    #[error("The specified output path does not exist.")]
    OutputPathDoesNotExist,
    #[error("An error occurred while writing your cert to the file system - {0:?}")]
    FileWriteError(#[from] std::io::Error),
    #[error("An error occurred while serializing your cert - {0:?}")]
    CertSerializationError(#[from] rcgen::RcgenError),
    #[error("Failed to parse the subject provided")]
    InvalidCertSubjectProvided,
}

pub fn run(cert_args: CertArgs) {
    match cert_args.action {
        CertCommands::New(new_args) => create_new_cert(new_args),
    }
}

pub fn create_new_cert(new_cert_args: NewCertArgs) {
    let mut cert_params = CertificateParams::new(vec![]);
    cert_params.alg = &rcgen::PKCS_ECDSA_P384_SHA384;
    let subject_str = new_cert_args.subject.as_str();
    let distinguished_name: DistinguishedName = match DnBuilder::from(subject_str).try_into() {
        Ok(dn_record) => dn_record,
        Err(e) => {
            log::error!("{}", e);
            return;
        }
    };

    add_distinguished_name_to_cert_params(&mut cert_params, distinguished_name);

    let today = chrono::Utc::today();
    cert_params.not_before =
        rcgen::date_time_ymd(today.year(), today.month() as u8, today.day() as u8);

    let expiry_time = today.add(chrono::Duration::weeks(12));
    cert_params.not_after = rcgen::date_time_ymd(
        expiry_time.year(),
        expiry_time.month() as u8,
        expiry_time.day() as u8,
    );

    let cert = match rcgen::Certificate::from_params(cert_params) {
        Ok(cert) => cert,
        Err(e) => {
            log::error!("An error occurred while generating your cert - {:?}", e);
            return;
        }
    };

    let (cert_path, key_path) = match write_cert_to_fs(new_cert_args.output_dir.as_str(), cert) {
        Ok(paths) => paths,
        Err(e) => {
            log::error!("An error occurred while saving your cert - {:?}", e);
            return;
        }
    };

    if atty::is(Stream::Stdout) {
        println!("Signing cert successfully generated…");
        println!("> Certificate saved to {}", cert_path.display());
        println!("> Key saved to {}", key_path.display());
    } else {
        let success_msg = serde_json::json!({
            "status": "success",
            "output": {
                "certificate": cert_path,
                "privateKey": key_path
            }
        });
        println!("{}", serde_json::to_string(&success_msg).unwrap());
    }
}

fn add_distinguished_name_to_cert_params(
    cert_params: &mut CertificateParams,
    distinguished_name: DistinguishedName,
) {
    cert_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, distinguished_name.common_name);
    cert_params
        .distinguished_name
        .push(rcgen::DnType::CountryName, distinguished_name.country);
    cert_params
        .distinguished_name
        .push(rcgen::DnType::OrganizationName, distinguished_name.org);
    cert_params.distinguished_name.push(
        rcgen::DnType::OrganizationalUnitName,
        distinguished_name.org_unit,
    );
    cert_params
        .distinguished_name
        .push(rcgen::DnType::LocalityName, distinguished_name.locality);
    cert_params
        .distinguished_name
        .push(rcgen::DnType::StateOrProvinceName, distinguished_name.state);
}

fn write_cert_to_fs(
    output_path: &str,
    cert: rcgen::Certificate,
) -> Result<(std::path::PathBuf, std::path::PathBuf), CertError> {
    let output_path = std::path::Path::new(output_path);
    let path = output_path
        .canonicalize()
        .map_err(|_| CertError::OutputPathDoesNotExist)?;

    let cert_path = path.join("cert.pem");
    let mut cert_file = std::fs::File::create(cert_path.as_path())?;
    let serialized_cert = cert.serialize_pem()?;
    cert_file.write_all(serialized_cert.as_bytes())?;

    let key_path = path.join("key.pem");
    let mut key_file = std::fs::File::create(key_path.as_path())?;
    let serialized_key = cert.serialize_private_key_pem();
    key_file.write_all(serialized_key.as_bytes())?;

    Ok((cert_path, key_path))
}

#[derive(Debug)]
struct DistinguishedName<'a> {
    country: &'a str,
    common_name: &'a str,
    locality: &'a str,
    org: &'a str,
    org_unit: &'a str,
    state: &'a str,
}

#[derive(Debug, Default)]
struct DnBuilder<'a> {
    country: Option<&'a str>,
    common_name: Option<&'a str>,
    locality: Option<&'a str>,
    org: Option<&'a str>,
    org_unit: Option<&'a str>,
    state: Option<&'a str>,
}

impl<'a, 'b> std::convert::From<&'a str> for DnBuilder<'b>
where
    'a: 'b, // can convert a str slice into a DnBuilder so long as the slice outlives the builder
{
    fn from(value: &'a str) -> Self {
        let mut builder = DnBuilder::default();
        value
            .split("/")
            .for_each(|term| match term.split("=").collect_tuple() {
                Some(("C", country)) => builder.country = Some(country),
                Some(("CN", common)) => builder.common_name = Some(common),
                Some(("L", local)) => builder.locality = Some(local),
                Some(("O", org)) => builder.org = Some(org),
                Some(("OU", org_unit)) => builder.org_unit = Some(org_unit),
                Some(("ST", state)) => builder.state = Some(state),
                Some((unknown_key, _)) => {
                    log::debug!("Unknown key found in subject string - {}", unknown_key);
                }
                None => {}
            });
        builder
    }
}

impl<'a> std::convert::TryInto<DistinguishedName<'a>> for DnBuilder<'a> {
    type Error = CertError;

    fn try_into(self) -> Result<DistinguishedName<'a>, Self::Error> {
        Ok(DistinguishedName {
            country: self.country.ok_or(CertError::InvalidCertSubjectProvided)?,
            common_name: self
                .common_name
                .ok_or(CertError::InvalidCertSubjectProvided)?,
            locality: self.locality.ok_or(CertError::InvalidCertSubjectProvided)?,
            org: self.org.ok_or(CertError::InvalidCertSubjectProvided)?,
            org_unit: self.org_unit.ok_or(CertError::InvalidCertSubjectProvided)?,
            state: self.state.ok_or(CertError::InvalidCertSubjectProvided)?,
        })
    }
}
