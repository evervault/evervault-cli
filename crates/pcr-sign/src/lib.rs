use std::num::ParseIntError;

pub use p384::ecdsa::{
    signature::{Error as SignatureError, Signer, Verifier as _Verifier},
    Signature as EcdsaSig, SigningKey, VerifyingKey,
};

/// Wrapping stuct to ensure signatures are generated correctly for the provided version
pub struct Signature<'a, T: PCRProvider> {
    version: SignatureVersion,
    pcrs: &'a T,
    private_key: SigningKey,
}

impl<'a, T: PCRProvider> Signature<'a, T> {
    pub fn new(version: SignatureVersion, pcrs: &'a T, private_key: SigningKey) -> Self {
        Self {
            version,
            pcrs,
            private_key,
        }
    }

    /// Produce a hex encoded signature over the PCRs formatted for the given signature version.
    pub fn sign(&self) -> String {
        let formatted_payload = self.version.format_signature_payload(self.pcrs);
        let signed: EcdsaSig = self.private_key.sign(&formatted_payload);
        let der_encoded_sig = signed.to_der();
        let hex_slice = HexSlice(der_encoded_sig.as_bytes());
        format!("{:02X}{:X}", self.version.to_byte(), hex_slice)
    }
}

/// Create a verifying instance over a signature and set of PCRs
pub struct Verifier<'a, T: PCRProvider> {
    signature: &'a str,
    pcrs: &'a T,
    verifier_key: VerifyingKey,
}

impl<'a, T: PCRProvider> Verifier<'a, T> {
    pub fn new(signature: &'a str, pcrs: &'a T, verifier_key: VerifyingKey) -> Self {
        Self {
            signature,
            pcrs,
            verifier_key,
        }
    }

    /// Attempt to verify the provided signature over the PCRs using the given key. The signature version is inferred from the leading byte over the signature.
    pub fn try_verify(&self) -> Result<(), SignatureVerificationError> {
        let decoded_signature = decode_hex(&self.signature)?;
        let (signature_version, signature) = decoded_signature.split_at(1);
        let parsed_version = SignatureVersion::try_from(signature_version[0])?;
        let ecdsa_sig = EcdsaSig::from_der(signature)?;

        let signature_payload = parsed_version.format_signature_payload(self.pcrs);
        self.verifier_key.verify(&signature_payload, &ecdsa_sig)?;
        Ok(())
    }
}

/// Enum of supported signature versions
#[derive(Clone)]
pub enum SignatureVersion {
    V1,
}

impl SignatureVersion {
    /// Convert the Signature version to a byte to be used as the leading byte on the signature for later parsing.
    pub fn to_byte(&self) -> u8 {
        match self {
            Self::V1 => 1_u8,
        }
    }

    /// Format a set of PCRs to be signed according to the signature version scheme.
    ///
    /// Currently supported signature versions are: V1.
    ///
    /// V1 Signature Format:
    /// VERSION
    /// 1
    /// PCR0
    /// <PCR0 Value>
    /// PCR1
    /// <PCR1 Value>
    /// PCR2
    /// <PCR2 Value>
    /// PCR8
    /// <PCR8 Value>
    pub fn format_signature_payload<T: PCRProvider>(&self, provider: &T) -> Vec<u8> {
        match self {
            Self::V1 => self.format_payload_for_v1(provider),
        }
    }

    fn format_payload_for_v1<T: PCRProvider>(&self, provider: &T) -> Vec<u8> {
        let formatted_payload = format!(
            "VERSION\n{}\nPCR0\n{}\nPCR1\n{}\nPCR2\n{}\nPCR8\n{}",
            self.to_string(),
            provider.pcr0().to_uppercase(),
            provider.pcr1().to_uppercase(),
            provider.pcr2().to_uppercase(),
            provider.pcr8().to_uppercase()
        );

        formatted_payload.as_bytes().to_vec()
    }
}

impl std::default::Default for SignatureVersion {
    fn default() -> Self {
        Self::V1
    }
}

impl std::convert::TryFrom<u8> for SignatureVersion {
    type Error = SignatureVerificationError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1_u8 => Ok(Self::V1),
            _ => Err(SignatureVerificationError::UnsupportedSignatureVersion),
        }
    }
}

impl std::fmt::Display for SignatureVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::V1 => write!(f, "1")?,
        };
        Ok(())
    }
}

/// Trait to expose PCRs from arbitrary types. PCR8 is assumed to be provided as the EIF is signed using the same private key in the ev-enclave project.
pub trait PCRProvider {
    fn pcr0(&self) -> &str;
    fn pcr1(&self) -> &str;
    fn pcr2(&self) -> &str;
    fn pcr8(&self) -> &str;
}

/// Utility type to enable Hex upper case serialization of slices of `u8`s
struct HexSlice<'a>(&'a [u8]);

impl<'a> std::fmt::UpperHex for HexSlice<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02X}")?;
        }
        Ok(())
    }
}

/// Decode hex strings back into a vec. Step over pairs of hex characters and decode them to a byte.
fn decode_hex(hex_str: &str) -> Result<Vec<u8>, ParseIntError> {
    (0..hex_str.len())
        .step_by(2)
        .map(|start_byte| u8::from_str_radix(&hex_str[start_byte..start_byte + 2], 16))
        .collect()
}

/// Error types returned from verifying a signature over PCRs
#[derive(Debug)]
pub enum SignatureVerificationError {
    /// Failed to decode a given signature as hex data.
    HexDecode,
    /// Failed to validate the signature using the provided verifying key.
    SignatureError(SignatureError),
    /// Signature version is not supported.
    UnsupportedSignatureVersion,
}

impl std::convert::From<ParseIntError> for SignatureVerificationError {
    fn from(_: ParseIntError) -> Self {
        Self::HexDecode
    }
}

impl std::convert::From<SignatureError> for SignatureVerificationError {
    fn from(e: SignatureError) -> Self {
        Self::SignatureError(e)
    }
}

impl std::fmt::Display for SignatureVerificationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::HexDecode => {
                write!(f, "Failed to decode hex encoded value to bytes. Please ensure the inputs are valid hex.")?;
            }
            Self::SignatureError(e) => {
                write!(
                    f,
                    "Failed to validate provided signature over the PCR set provided - {e}"
                )?;
            },
            Self::UnsupportedSignatureVersion => {
                write!(
                    f,
                    "Failed to parse leading byte to known signature version"
                )?;
            }
            Self::UnsupportedSignatureVersion => {
                write!(f, "Failed to parse leading byte to known signature version")?;
            }
        };
        Ok(())
    }
}

impl std::error::Error for SignatureVerificationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::SignatureError(e) => e.source(),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestPCRs {
        pub pcr0: String,
        pub pcr1: String,
        pub pcr2: String,
        pub pcr8: String,
    }

    impl std::convert::From<String> for TestPCRs {
        fn from(value: String) -> Self {
            Self {
                pcr0: value.clone(),
                pcr1: value.clone(),
                pcr2: value.clone(),
                pcr8: value,
            }
        }
    }

    impl PCRProvider for TestPCRs {
        fn pcr0(&self) -> &str {
            self.pcr0.as_str()
        }

        fn pcr1(&self) -> &str {
            self.pcr1.as_str()
        }

        fn pcr2(&self) -> &str {
            self.pcr2.as_str()
        }

        fn pcr8(&self) -> &str {
            self.pcr8.as_str()
        }
    }

    #[test]
    fn test_debug_pcr_formatting() {
        let debug_pcr = "0".repeat(96);
        let pcrs = TestPCRs::from(debug_pcr.clone());
        let formatted_payload = SignatureVersion::V1.format_signature_payload(&pcrs);
        let decoded_payload = String::from_utf8(formatted_payload).unwrap();
        assert_eq!(
            decoded_payload,
            format!(
                "VERSION\n{}\nPCR0\n{}\nPCR1\n{}\nPCR2\n{}\nPCR8\n{}",
                SignatureVersion::V1.to_string(),
                &debug_pcr,
                &debug_pcr,
                &debug_pcr,
                &debug_pcr
            )
        );
    }

    #[test]
    fn test_ordered_pcr_formatting() {
        let pcrs = TestPCRs {
            pcr0: "0".to_string(),
            pcr1: "1".to_string(),
            pcr2: "2".to_string(),
            pcr8: "8".to_string(),
        };
        let formatted_payload = SignatureVersion::V1.format_signature_payload(&pcrs);
        let decoded_payload = String::from_utf8(formatted_payload).unwrap();
        assert_eq!(
            decoded_payload,
            format!(
                "VERSION\n{}\nPCR0\n{}\nPCR1\n{}\nPCR2\n{}\nPCR8\n{}",
                SignatureVersion::V1.to_string(),
                pcrs.pcr0(),
                pcrs.pcr1(),
                pcrs.pcr2(),
                pcrs.pcr8()
            )
        );
    }

    #[test]
    fn test_decode_hex() {
        let decoded = decode_hex("FF").unwrap();
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded, vec![255_u8]);
    }

    #[test]
    fn test_sign_and_verify() {
        let signing_key = SigningKey::random(&mut rand_core::OsRng);
        let debug_pcrs = TestPCRs::from("0".repeat(96));
        let verifier = VerifyingKey::from(signing_key.clone());
        let signature = Signature::new(SignatureVersion::V1, &debug_pcrs, signing_key);
        let signature = signature.sign();
        let sig_to_verify = Verifier::new(&signature, &debug_pcrs, verifier);
        let verification = sig_to_verify.try_verify();
        assert!(verification.is_ok());
    }

    #[test]
    fn test_verify_with_invalid_signature() {
        let signing_key = SigningKey::random(&mut rand_core::OsRng);
        let debug_pcrs = TestPCRs::from("0".repeat(96));
        let verifier = VerifyingKey::from(signing_key);
        let sig = "thisisnothex";
        let sig_to_verify = Verifier::new(&sig, &debug_pcrs, verifier);
        let verification = sig_to_verify.try_verify();
        assert!(verification.is_err());
        #[allow(unused_variables)]
        let verification_err = verification.unwrap_err();
        assert!(matches!(
            verification_err,
            SignatureVerificationError::HexDecode
        ));
    }

    #[test]
    fn test_verify_with_incorrect_verifying_key() {
        let signing_key = SigningKey::random(&mut rand_core::OsRng);
        let debug_pcrs = TestPCRs::from("0".repeat(96));
        let signer = Signature::new(SignatureVersion::V1, &debug_pcrs, signing_key);
        let signature = signer.sign();
        let incorrect_key = SigningKey::random(&mut rand_core::OsRng);
        let incorrect_verifier = VerifyingKey::from(incorrect_key);

        let verifier = Verifier::new(&signature, &debug_pcrs, incorrect_verifier);
        let verdict = verifier.try_verify();
        assert!(verdict.is_err());
        let verification_err = verdict.unwrap_err();
        assert!(matches!(
            verification_err,
            SignatureVerificationError::SignatureError(_)
        ));
    }

    #[test]
    fn test_verify_with_unsupported_signature_version() {
        let signing_key = SigningKey::random(&mut rand_core::OsRng);
        let debug_pcrs = TestPCRs::from("0".repeat(96));
        let signer = Signature::new(SignatureVersion::V1, &debug_pcrs, signing_key.clone());
        let signature = signer.sign();
        let (_version, original_signature) = signature.split_at(2);
        let mut unsupported_version = "00".to_string();
        unsupported_version.push_str(original_signature);
        let correct_verifying_key = VerifyingKey::from(signing_key);
        let verifier = Verifier::new(&unsupported_version, &debug_pcrs, correct_verifying_key);
        let verdict = verifier.try_verify();
        assert!(verdict.is_err());
        let verification_err = verdict.unwrap_err();
        assert!(matches!(
            verification_err,
            SignatureVerificationError::UnsupportedSignatureVersion
        ));
    }
}
