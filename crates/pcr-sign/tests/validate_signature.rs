use p384::pkcs8::DecodePublicKey;
use pcr_sign::{Verifier, PCRProvider, SignatureVerificationError, SigningKey, VerifyingKey};
use rand_core::OsRng;

const DEBUG_PCR_VALUE: &'static str = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

struct DebugPCRs;

impl PCRProvider for DebugPCRs {
    fn pcr0(&self) -> &str {
        DEBUG_PCR_VALUE
    }

    fn pcr1(&self) -> &str {
        DEBUG_PCR_VALUE
    }

    fn pcr2(&self) -> &str {
        DEBUG_PCR_VALUE
    }

    fn pcr8(&self) -> &str {
        DEBUG_PCR_VALUE
    }
}

#[test]
pub fn test_signature_verification_using_generated_keys() {
    let precomputed_signature = include_bytes!("../signature.txt");
    let signature_str = String::from_utf8(precomputed_signature.to_vec()).unwrap();

    let public_key = include_bytes!("../testing-pub-key.pem");
    let pub_key_str = String::from_utf8(public_key.to_vec()).unwrap();
    let verifying_key = VerifyingKey::from_public_key_pem(&pub_key_str).unwrap();
    let debug_pcrs = DebugPCRs;
    let verifier = Verifier::new(&signature_str, &debug_pcrs, verifying_key);
    let verification_verdict = verifier.try_verify();
    assert!(verification_verdict.is_ok());
}

#[test]
pub fn test_signature_verification_using_incorrect_key() {
    let precomputed_signature = include_bytes!("../signature.txt");
    let signature_str = String::from_utf8(precomputed_signature.to_vec()).unwrap();

    let random_key = SigningKey::random(&mut OsRng);
    let verifying_key = VerifyingKey::from(random_key);
    let debug_pcrs: DebugPCRs = DebugPCRs;
    let verifier = Verifier::new(&signature_str, &debug_pcrs, verifying_key);
    let verification_verdict = verifier.try_verify();
    assert!(verification_verdict.is_err());
    let verification_error = verification_verdict.unwrap_err();
    assert!(matches!(
        verification_error,
        SignatureVerificationError::SignatureError(_)
    ));
}