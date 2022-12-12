use chrono::Datelike;
use itertools::Itertools;
use rcgen::CertificateParams;
use std::io::Write;
use std::ops::Add;
use std::path::PathBuf;

pub mod error;
pub use error::CertError;

pub fn create_new_cert(
    output_dir: &str,
    distinguished_name: DistinguishedName,
) -> Result<(PathBuf, PathBuf), CertError> {
    let mut cert_params = CertificateParams::new(vec![]);
    cert_params.alg = &rcgen::PKCS_ECDSA_P384_SHA384;

    add_distinguished_name_to_cert_params(&mut cert_params, distinguished_name);

    let today = chrono::Utc::today();
    cert_params.not_before =
        rcgen::date_time_ymd(today.year(), today.month() as u8, today.day() as u8);

    let expiry_time = today.add(chrono::Duration::weeks(52));
    cert_params.not_after = rcgen::date_time_ymd(
        expiry_time.year(),
        expiry_time.month() as u8,
        expiry_time.day() as u8,
    );

    let cert = rcgen::Certificate::from_params(cert_params)?;

    let (cert_path, key_path) = write_cert_to_fs(output_dir, cert)?;

    Ok((cert_path, key_path))
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
pub struct DistinguishedName<'a> {
    country: &'a str,
    common_name: &'a str,
    locality: &'a str,
    org: &'a str,
    org_unit: &'a str,
    state: &'a str,
}

impl<'a> std::default::Default for DistinguishedName<'a> {
    fn default() -> Self {
        Self {
            country: "IE",
            common_name: "cages.evervault.com",
            locality: "DUB",
            org: "ENG",
            org_unit: "CAGES",
            state: "LEI",
        }
    }
}

#[derive(Debug, Default)]
pub struct DnBuilder<'a> {
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
            .split('/')
            .for_each(|term| match term.split('=').collect_tuple() {
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
