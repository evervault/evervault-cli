use aws_nitro_enclaves_image_format::defs::eif_hasher::EifHasher;
use chrono::{DateTime, Datelike, Local, TimeZone, Utc};
use dialoguer::{Confirm, MultiSelect};
use itertools::Itertools;
use rcgen::CertificateParams;
use sha2::{Digest, Sha384};
use std::cmp::Ordering;
use std::io::{Read, Write};
use std::ops::Add;
use std::path::{Path, PathBuf};
use x509_parser::parse_x509_certificate;
use x509_parser::prelude::{parse_x509_pem, X509Certificate};

use crate::api::enclave::{
    CreateEnclaveSigningCertRefRequest, CreateEnclaveSigningCertRefResponse, EnclaveApi,
    EnclaveSigningCert, UpdateLockedEnclaveSigningCertRequest,
};
use crate::api::{self, AuthMode};

pub mod error;
pub use error::CertError;

pub struct DesiredLifetime {
    days: i64,
    weeks: i64,
    years: i64,
}

impl std::default::Default for DesiredLifetime {
    fn default() -> Self {
        Self {
            days: Default::default(),
            weeks: Default::default(),
            years: 1,
        }
    }
}

impl DesiredLifetime {
    pub fn new(days: Option<i64>, weeks: Option<i64>, years: Option<i64>) -> Self {
        let use_default_lifetime = days.is_none() && weeks.is_none() && years.is_none();

        if use_default_lifetime {
            Self::default()
        } else {
            Self {
                days: days.unwrap_or_default(),
                weeks: weeks.unwrap_or_default(),
                years: years.unwrap_or_default(),
            }
        }
    }
}

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
    desired_lifetime: DesiredLifetime,
) -> Result<(PathBuf, PathBuf), CertError> {
    let mut cert_params = CertificateParams::new(vec![]);
    cert_params.alg = &rcgen::PKCS_ECDSA_P384_SHA384;

    add_distinguished_name_to_cert_params(&mut cert_params, distinguished_name);

    let now = Utc::now();
    cert_params.not_before = rcgen::date_time_ymd(now.year(), now.month() as u8, now.day() as u8);

    let expiry_time = now
        .add(chrono::Duration::days(desired_lifetime.days))
        .add(chrono::Duration::weeks(desired_lifetime.weeks))
        .add(chrono::Duration::weeks(desired_lifetime.years * 52));

    if expiry_time.cmp(&now) != Ordering::Greater {
      return Err(CertError::CertExpiryIsInThePast(expiry_time));
    }

    cert_params.not_after = rcgen::date_time_ymd(
        expiry_time.year(),
        expiry_time.month() as u8,
        expiry_time.day() as u8,
    );

    let cert = rcgen::Certificate::from_params(cert_params)?;

    let (cert_path, key_path) = write_cert_to_fs(output_dir, cert)?;

    Ok((cert_path, key_path))
}

pub fn get_cert_pcr(cert_path: &Path) -> Result<String, CertError> {
    if !cert_path.exists() {
        return Err(CertError::CertPathDoesNotExist(cert_path.to_path_buf()));
    }

    let cert_contents = read_cert_bytes_from_fs(cert_path)?;
    let (_, pem) = parse_x509_pem(&cert_contents).map_err(CertError::PEMError)?;

    let mut hasher = EifHasher::new_without_cache(Sha384::new()).map_err(CertError::HashError)?;

    hasher
        .write_all(&pem.contents)
        .map_err(|err| CertError::HashError(err.to_string()))?;

    let hash_bytes = hasher
        .tpm_extend_finalize_reset()
        .map_err(|err| CertError::HashError(err.to_string()))?;

    let hash = hex::encode(hash_bytes);

    Ok(hash)
}

pub async fn upload_new_cert_ref(
    cert_path: &str,
    api_key: &str,
    name: String,
) -> Result<CreateEnclaveSigningCertRefResponse, CertError> {
    let path = std::path::Path::new(cert_path);

    let pcr8 = get_cert_pcr(path)?;
    let validity_period = get_cert_validity_period(path)?;

    let enclave_api = api::enclave::EnclaveClient::new(AuthMode::ApiKey(api_key.to_string()));

    let payload = CreateEnclaveSigningCertRefRequest::new(
        pcr8.clone(),
        name,
        validity_period.not_before,
        validity_period.not_after,
    );

    let cert_ref = match enclave_api.create_enclave_signing_cert_ref(payload).await {
        Ok(cert_ref) => cert_ref,
        Err(e) => {
            log::error!("Error upload Enclave signing cert ref — {:?}", e);
            return Err(CertError::ApiError(e));
        }
    };

    Ok(cert_ref)
}

fn format_cert_for_multi_select(cert: &EnclaveSigningCert) -> String {
    let name = cert.name().unwrap_or_default();
    let cert_hash = cert.cert_hash();
    let not_after = cert
        .not_after()
        .and_then(|time| format_expiry_time(&time).ok())
        .unwrap_or_else(|| "Failed to get cert expiry".to_string());

    format!("{} {} ({})", name, cert_hash, not_after)
}

fn format_expiry_time(expiry_time: &str) -> Result<String, CertError> {
    let dt = DateTime::parse_from_rfc3339(expiry_time).map_err(CertError::TimstampParseError)?;

    let now = Local::now();
    let duration = dt.signed_duration_since(now);

    let formatted_duration = if duration.num_hours() < 0 {
        "Expired".to_string()
    } else if duration.num_hours() >= 24 {
        format!("Expires in {} days", duration.num_days())
    } else {
        format!("Expires in {} hours", duration.num_hours())
    };

    Ok(formatted_duration)
}

#[derive(Debug, Clone, PartialEq, PartialOrd)]
struct CertWithFormattedString {
    cert: EnclaveSigningCert,
    formatted: String,
    locked: bool,
}

impl CertWithFormattedString {
    fn new(cert: &EnclaveSigningCert, locked: bool) -> Self {
        Self {
            formatted: format_cert_for_multi_select(cert),
            cert: cert.clone(),
            locked,
        }
    }
}

async fn get_certs_for_selection(
    enclave_api: api::enclave::EnclaveClient,
    enclave_uuid: &str,
) -> Result<Vec<CertWithFormattedString>, CertError> {
    let available_certs = match enclave_api.get_signing_certs().await {
        Ok(res) => res.certs,
        Err(e) => {
            log::error!("Error getting Enclave signing cert refs — {:?}", e);
            return Err(CertError::ApiError(e));
        }
    };

    let locked_certs = match enclave_api
        .get_enclave_locked_signing_certs(enclave_uuid)
        .await
    {
        Ok(certs) => certs,
        Err(e) => {
            log::error!("Error getting Enclave signing cert — {:?}", e);
            return Err(CertError::ApiError(e));
        }
    };

    let locked_cert_uuids = locked_certs
        .iter()
        .map(|cert| cert.uuid())
        .collect::<Vec<&str>>();

    let available_formatted: Vec<CertWithFormattedString> = available_certs
        .iter()
        .filter(|cert| !locked_cert_uuids.contains(&cert.uuid()))
        .map(|cert| CertWithFormattedString::new(cert, false))
        .collect::<Vec<CertWithFormattedString>>();

    let locked_formatted = locked_certs
        .iter()
        .map(|cert| CertWithFormattedString::new(cert, true))
        .collect::<Vec<CertWithFormattedString>>();

    let all_formatted = [available_formatted, locked_formatted].concat();

    Ok(all_formatted)
}

fn sort_certs_by_expiry(
    mut certs: Vec<CertWithFormattedString>,
) -> Result<Vec<CertWithFormattedString>, CertError> {
    certs.sort_by_key(|cert| {
        cert.cert
            .not_after()
            .unwrap_or("Failed to get cert expiry".to_string())
    });
    Ok(certs)
}

pub async fn lock_enclave_to_certs(
    api_key: &str,
    enclave_uuid: &str,
    enclave_name: &str,
) -> Result<(), CertError> {
    let enclave_api = api::enclave::EnclaveClient::new(AuthMode::ApiKey(api_key.to_string()));

    let certs_for_select = get_certs_for_selection(enclave_api.clone(), enclave_uuid).await?;

    if certs_for_select.is_empty() {
        log::error!("No certs found for the current app. You must upload a cert using the `ev cert upload` command or deployment an Enclave before you can create a cert lock.");
        return Err(CertError::NoCertsFound);
    }

    let sorted_certs_for_select = sort_certs_by_expiry(certs_for_select)?;

    let chosen: Vec<usize> = MultiSelect::new()
        .with_prompt("Select Certs To Lock Enclave To. Press Space To Select, Enter To Confirm.\n Cert Name | PCR8 (Hash of cert) | Cert Expiry ")
        .report(false)
        .max_length(6)
        .items_checked(
            sorted_certs_for_select
                .iter()
                .map(|cert| (cert.formatted.as_str(), cert.locked))
                .collect::<Vec<(&str, bool)>>()
                .as_slice(),
        )
        .interact()?;

    let chosen_cert_uuids = chosen
        .iter()
        .filter_map(|index| {
            sorted_certs_for_select
                .get(*index)
                .map(|cert| cert.cert.uuid().to_string())
        })
        .collect::<Vec<String>>();

    let payload = UpdateLockedEnclaveSigningCertRequest::new(chosen_cert_uuids.clone());

    let amount_chosen = chosen_cert_uuids.len();
    let msg = match amount_chosen {
        0 => format!(
            "No certs selected. Enclave {} will not be locked to any certs.",
            enclave_name
        ),
        1 => format!(
            "1 cert selected. Enclave {} will be locked to this cert.",
            enclave_name
        ),
        _ => format!(
            "{} certs selected. Enclave {} will be locked to these certs",
            amount_chosen, enclave_name
        ),
    };

    log::info!("{}", msg);
    //Need to ask the user to confirm they want to continue
    let confirmed = Confirm::new()
        .with_prompt("Do you want to continue?")
        .interact()?;

    if !confirmed {
        log::info!("Close one! Update Cancelled.");
        return Ok(());
    }

    if let Err(e) = enclave_api
        .update_enclave_locked_signing_certs(enclave_uuid, payload)
        .await
    {
        log::error!("Error locking Enclave to certs - {e}");
        return Err(CertError::ApiError(e));
    };

    let final_msg = match amount_chosen {
        0 => format!(
            "Enclave {} successfully unlocked from all certs!",
            enclave_name
        ),
        1 => format!("Enclave {} successfully locked to 1 cert!", enclave_name),
        _ => format!(
            "Enclave {} successfully locked to {} certs!",
            enclave_name, amount_chosen
        ),
    };

    log::info!("{}", final_msg);

    Ok(())
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
    let cert_contents = read_cert_bytes_from_fs(path)?;

    let (_, pem) = parse_x509_pem(&cert_contents).map_err(CertError::PEMError)?;
    let (_, x509) = parse_x509_certificate(&pem.contents).map_err(CertError::X509Error)?;

    extract_cert_validity_period_from_x509(&x509)
}

fn read_cert_bytes_from_fs(path: &Path) -> Result<Vec<u8>, CertError> {
    let cert_file = std::fs::File::open(path)?;
    let mut cert_reader = std::io::BufReader::new(cert_file);
    let mut cert_contents = Vec::new();
    cert_reader.read_to_end(&mut cert_contents)?;

    Ok(cert_contents)
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
            common_name: "enclaves.evervault.com",
            locality: "DUB",
            org: "ENG",
            org_unit: "ENCLAVES",
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

#[cfg(test)]
mod test {
    use super::*;

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

    #[test]
    fn test_sort_certs_by_expiry() {
        let cert1 = EnclaveSigningCert::new(
            None,
            "uuid1".to_string(),
            "app_uuid1".to_string(),
            "hash1".to_string(),
            None,
            Some("2023-04-17T12:00:00Z".to_string()),
        );
        let cert2 = EnclaveSigningCert::new(
            None,
            "uuid2".to_string(),
            "app_uuid2".to_string(),
            "hash2".to_string(),
            None,
            Some("2023-04-18T12:00:00Z".to_string()),
        );
        let cert3 = EnclaveSigningCert::new(
            None,
            "uuid3".to_string(),
            "app_uuid3".to_string(),
            "hash3".to_string(),
            None,
            Some("2023-04-16T12:00:00Z".to_string()),
        );

        let certs = vec![
            CertWithFormattedString::new(&cert1, false),
            CertWithFormattedString::new(&cert2, false),
            CertWithFormattedString::new(&cert3, false),
        ];

        let result = sort_certs_by_expiry(certs);

        assert!(result.is_ok());
        let sorted_certs = result.unwrap();

        assert_eq!(sorted_certs.len(), 3);
        assert_eq!(
            sorted_certs[0].cert.not_after(),
            Some("2023-04-16T12:00:00Z".to_string())
        );
        assert_eq!(
            sorted_certs[1].cert.not_after(),
            Some("2023-04-17T12:00:00Z".to_string())
        );
        assert_eq!(
            sorted_certs[2].cert.not_after(),
            Some("2023-04-18T12:00:00Z".to_string())
        );
    }
}
