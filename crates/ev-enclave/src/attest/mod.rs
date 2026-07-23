pub mod error;

use attestation_doc_validation::error::AttestationError;
use attestation_doc_validation::validate_attestation_doc_against_cert;
use attestation_doc_validation::{attestation_doc::PCRs, validate_expected_pcrs};
use base64::decode;
use error::AttestCommandError;
use serde::Deserialize;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio_rustls::rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider},
    pki_types::{CertificateDer, ServerName, UnixTime},
    ClientConfig, DigitallySignedStruct, Error, SignatureScheme,
};
use x509_parser::{certificate::X509Certificate, prelude::FromDer};

/**
 * Adapted from code written by chinaza-evervault
**/

struct SubjectAltNameAttestationValidator {
    context_sender: mpsc::Sender<Result<(), AttestationError>>,
    expected_pcrs: PCRs,
    attestation_doc: Vec<u8>,
}

macro_rules! to_rustls_general_error {
    ($err:expr) => {
        Error::General($err.to_string())
    };
}

impl std::fmt::Debug for SubjectAltNameAttestationValidator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SubjectAltNameAttestationValidator")
            .finish()
    }
}

impl ServerCertVerifier for SubjectAltNameAttestationValidator {
    fn verify_server_cert(
        &self,
        certificate: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, Error> {
        let (_, certificate_parsed) = X509Certificate::from_der(certificate.as_ref())
            .map_err(|e| to_rustls_general_error!(e))?;
        let attestation_doc =
            validate_attestation_doc_against_cert(&certificate_parsed, &self.attestation_doc)
                .map_err(|e| to_rustls_general_error!(e))?;
        let attestation_validation_result =
            validate_expected_pcrs(&attestation_doc, &self.expected_pcrs);
        let verification_result = match &attestation_validation_result {
            Ok(_attestation_doc) => Ok(ServerCertVerified::assertion()),
            Err(e) => Err(to_rustls_general_error!(e)),
        };

        let context_sender = self.context_sender.clone();
        tokio::spawn(async move { context_sender.send(attestation_validation_result).await });

        verification_result
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        let provider = CryptoProvider::get_default()
            .ok_or_else(|| Error::General("no crypto provider installed".into()))?;
        verify_tls12_signature(
            message,
            cert,
            dss,
            &provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        let provider = CryptoProvider::get_default()
            .ok_or_else(|| Error::General("no crypto provider installed".into()))?;
        verify_tls13_signature(
            message,
            cert,
            dss,
            &provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        CryptoProvider::get_default()
            .map(|p| {
                p.signature_verification_algorithms
                    .supported_schemes()
                    .to_vec()
            })
            .unwrap_or_default()
    }
}

pub async fn attest_connection_to_enclave(
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
    let attestation_doc = get_attestation_doc(domain).await?;
    let (tx, _rx) = mpsc::channel(1);
    let validator = Arc::new(SubjectAltNameAttestationValidator {
        context_sender: tx,
        expected_pcrs,
        attestation_doc,
    });
    let client_config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(validator)
        .with_no_client_auth();
    let tls_connector: tokio_rustls::TlsConnector = Arc::new(client_config).into();

    // a successful connection means the validator has successfully validated the attestation doc
    let server_name = ServerName::try_from(domain.to_owned())?;
    let mut connection = tls_connector.connect(server_name, stream).await?;
    let (_io, session) = connection.get_mut();
    session.send_close_notify();
    Ok(())
}

#[derive(Deserialize, Debug)]
struct AttestationDocResponse {
    attestation_doc: String,
}

async fn get_attestation_doc(domain: &str) -> Result<Vec<u8>, AttestCommandError> {
    let client = reqwest::Client::new();

    let response = client
        .get(format!("https://{}/.well-known/attestation", domain))
        .send()
        .await?;

    if response.status().is_success() {
        let body: AttestationDocResponse = response.json().await?;
        Ok(decode(body.attestation_doc)?)
    } else {
        Err(AttestCommandError::AttestationDocRetrievalError(
            response.status().to_string(),
        ))
    }
}

#[cfg(test)]
mod attest_tests {
    use super::*;

    #[tokio::test]
    async fn connection_to_synthetic_enclave_in_debug_mode() {
        let expected_pcrs = PCRs {
            pcr_0: "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000".to_string(),
            pcr_1: "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000".to_string(),
            pcr_2: "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000".to_string(),
            pcr_8: "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000".to_string(),
        };
        attest_connection_to_enclave(
            "synthetic-cage.app-f5f084041a7e.cage.evervault.com",
            expected_pcrs,
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn connection_to_synthetic_enclave_in_debug_mode_expecting_incorrect_pcrs() {
        let expected_pcrs = PCRs {
            pcr_0: "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000".to_string(),
            pcr_1: "00000000000different000000000000000000000000PCRs00000000000000000000000000000000000000000000000".to_string(),
            pcr_2: "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000".to_string(),
            pcr_8: "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000".to_string(),
        };
        let err = attest_connection_to_enclave(
            "synthetic-cage.app-f5f084041a7e.cage.evervault.com",
            expected_pcrs,
        )
        .await
        .unwrap_err();

        assert!(err
            .to_string()
            .contains("The PCRs found were different to the expected values."));
    }
}
