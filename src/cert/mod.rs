use chrono::{Datelike, TimeZone, Utc};
use itertools::Itertools;
use rcgen::CertificateParams;
use std::io::{Read, Write};
use std::ops::Add;
use std::path::{Path, PathBuf};
use x509_parser::parse_x509_certificate;
use x509_parser::prelude::{parse_x509_pem, X509Certificate};

pub mod error;
pub use error::CertError;

#[derive(Debug, Clone)]
pub struct CertValidityPeriod {
    pub not_before: String,
    pub not_after: String,
}

impl CertValidityPeriod {
    pub fn new(not_before: String, not_after: String) -> Self {
        Self {
            not_before,
            not_after,
        }
    }
}

pub fn create_new_cert(
    output_dir: &Path,
    distinguished_name: DistinguishedName,
) -> Result<(PathBuf, PathBuf), CertError> {
    let mut cert_params = CertificateParams::new(vec![]);
    cert_params.alg = &rcgen::PKCS_ECDSA_P384_SHA384;

    add_distinguished_name_to_cert_params(&mut cert_params, distinguished_name);

    let now = Utc::now();
    cert_params.not_before = rcgen::date_time_ymd(now.year(), now.month() as u8, now.day() as u8);

    let expiry_time = now.add(chrono::Duration::weeks(52));
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
    output_path: &Path,
    cert: rcgen::Certificate,
) -> Result<(PathBuf, PathBuf), CertError> {
    if !output_path.exists() {
        return Err(CertError::OutputPathDoesNotExist);
    }

    let cert_path = output_path.join("cert.pem");
    let mut cert_file = std::fs::File::create(cert_path.as_path())?;
    let serialized_cert = cert.serialize_pem()?;
    cert_file.write_all(serialized_cert.as_bytes())?;

    let key_path = output_path.join("key.pem");
    let mut key_file = std::fs::File::create(key_path.as_path())?;
    let serialized_key = cert.serialize_private_key_pem();
    key_file.write_all(serialized_key.as_bytes())?;

    Ok((cert_path, key_path))
}

fn epoch_to_date(epoch: i64) -> Result<String, CertError> {
    match chrono::Utc.timestamp_opt(epoch, 0) {
        chrono::LocalResult::Single(date) => Ok(date.format("%Y-%m-%dT%H:%M:%S%z").to_string()),
        _ => Err(CertError::InvalidDate),
    }
}

fn extract_cert_validity_period_from_x509(
    cert: &X509Certificate,
) -> Result<CertValidityPeriod, CertError> {
    let now = chrono::Utc::now().timestamp();
    let not_before = cert.tbs_certificate.validity.not_before.timestamp();
    let not_after = cert.tbs_certificate.validity.not_after.timestamp();

    if now < not_before {
        return Err(CertError::CertNotYetValid);
    } else if now > not_after {
        return Err(CertError::CertHasExpired);
    }

    let cert_validity_period =
        CertValidityPeriod::new(epoch_to_date(not_before)?, epoch_to_date(not_after)?);

    Ok(cert_validity_period)
}

pub fn get_cert_validity_period(path: &Path) -> Result<CertValidityPeriod, CertError> {
    let cert_file = std::fs::File::open(path)?;
    let mut cert_reader = std::io::BufReader::new(cert_file);
    let mut cert_contents = Vec::new();
    cert_reader.read_to_end(&mut cert_contents)?;

    let (_, pem) = parse_x509_pem(&cert_contents).map_err(CertError::PEMError)?;
    let (_, x509) = parse_x509_certificate(&pem.contents).map_err(CertError::X509Error)?;

    extract_cert_validity_period_from_x509(&x509)
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

#[test]
fn test_epoch_to_date() {
    let epoch: i64 = 1619196863;
    let expected_date = "2021-04-23T16:54:23+0000";

    let date = epoch_to_date(epoch).unwrap();
    assert_eq!(expected_date, date);
}

#[test]
fn test_get_cert_validity_period() {
    let path = Path::new("./test-cert/cert.pem");

    let cert_validity_period = get_cert_validity_period(path).unwrap();

    let expected_not_before = "2023-04-06T00:00:00+0000";
    let expected_not_after = "2024-04-04T00:00:00+0000";

    assert_eq!(expected_not_before, cert_validity_period.not_before);
    assert_eq!(expected_not_after, cert_validity_period.not_after);
}
