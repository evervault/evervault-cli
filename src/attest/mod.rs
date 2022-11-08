pub mod error;

use attestation_doc_validation::{validate_attestation_doc, AttestationError, PCRs};
use aws_nitro_enclaves_nsm_api::api::AttestationDoc;
use error::AttestCommandError;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio_rustls::rustls::{
    client::{ClientConfig, ServerCertVerified, ServerCertVerifier},
    RootCertStore,
};
use x509_parser::{certificate::X509Certificate, prelude::FromDer};

/**
 * Adapted from code written by chinaza-evervault
**/

struct SubjectAltNameAttestationValidator {
    context_sender: mpsc::Sender<Result<AttestationDoc, AttestationError>>,
    expected_pcrs: PCRs,
}

fn extract_signed_cose_sign_1_from_certificate(
    certificate: X509Certificate,
) -> Result<Vec<u8>, AttestCommandError> {
    let subject_alt_names = certificate
        .subject_alternative_name()?
        .ok_or(AttestCommandError::NoSubjectAltNames)?;
    let parsed_attestation_bytes = subject_alt_names
        .value
        .general_names
        .iter()
        .flat_map(|alt_name| match alt_name {
            x509_parser::extensions::GeneralName::DNSName(name) => Some(name),
            _ => None,
        })
        .flat_map(|x| x.split('.').next())
        .reduce(|a, b| if a.len() > b.len() { a } else { b })
        .ok_or(AttestCommandError::ParseError)?;
    Ok(hex::decode(parsed_attestation_bytes)?)
}

macro_rules! to_rustls_general_error {
    ($err:expr) => {
        tokio_rustls::rustls::Error::General($err.to_string())
    };
}

impl ServerCertVerifier for SubjectAltNameAttestationValidator {
    fn verify_server_cert(
        &self,
        certificate: &tokio_rustls::rustls::Certificate,
        _intermediates: &[tokio_rustls::rustls::Certificate],
        _server_name: &tokio_rustls::rustls::ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: std::time::SystemTime,
    ) -> std::result::Result<ServerCertVerified, tokio_rustls::rustls::Error> {
        let (_, certificate_parsed) = X509Certificate::from_der(certificate.as_ref())
            .map_err(|e| to_rustls_general_error!(e))?;
        let cose_sign_1_bytes = extract_signed_cose_sign_1_from_certificate(certificate_parsed)
            .map_err(|e| to_rustls_general_error!(e))?;
        let attestation_validation_result =
            validate_attestation_doc(&cose_sign_1_bytes, &self.expected_pcrs);

        let verification_result = match &attestation_validation_result {
            Ok(_attestation_doc) => Ok(ServerCertVerified::assertion()),
            Err(e) => Err(to_rustls_general_error!(e)),
        };

        let context_sender = self.context_sender.clone();
        tokio::spawn(async move { context_sender.send(attestation_validation_result).await });

        verification_result
    }
}

pub async fn attest_connection_to_cage(
    domain: &str,
    expected_pcrs: PCRs,
) -> Result<(), AttestCommandError> {
    let destinations = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        tokio::net::lookup_host((domain, 443)),
    )
    .await??
    .collect::<Vec<_>>();
    let stream = tokio::net::TcpStream::connect(&destinations[..]).await?;
    let mut client_config = ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(RootCertStore::empty())
        .with_no_client_auth();
    let (tx, _rx) = mpsc::channel(1);
    let validator = Arc::new(SubjectAltNameAttestationValidator {
        context_sender: tx,
        expected_pcrs,
    });
    client_config
        .dangerous()
        .set_certificate_verifier(validator);
    let tls_connector: tokio_rustls::TlsConnector = Arc::new(client_config).into();

    // a successful connection means the validator has successfully validated the attestation doc
    let mut connection = tls_connector.connect(domain.try_into()?, stream).await?;
    let (_io, session) = connection.get_mut();
    session.send_close_notify();
    Ok(())
}

#[cfg(test)]
mod attest_tests {
    use super::*;

    #[tokio::test]
    async fn connection_to_synthetic_cage_in_debug_mode() {
        let expected_pcrs = PCRs {
            pcr_0: "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000".to_string(),
            pcr_1: "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000".to_string(),
            pcr_2: "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000".to_string(),
            pcr_8: "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000".to_string(),
        };
        attest_connection_to_cage(
            "synthetic-cage.app_f5f084041a7e.cages.evervault.com",
            expected_pcrs,
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn connection_to_synthetic_cage_in_debug_mode_expecting_incorrect_pcrs() {
        let expected_pcrs = PCRs {
            pcr_0: "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000".to_string(),
            pcr_1: "00000000000different000000000000000000000000PCRs00000000000000000000000000000000000000000000000".to_string(),
            pcr_2: "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000".to_string(),
            pcr_8: "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000".to_string(),
        };
        let err = attest_connection_to_cage(
            "synthetic-cage.app_f5f084041a7e.cages.evervault.com",
            expected_pcrs,
        )
        .await
        .unwrap_err();

        assert!(err
            .to_string()
            .contains("The PCRs found were different to those that were expected."));
    }
}
