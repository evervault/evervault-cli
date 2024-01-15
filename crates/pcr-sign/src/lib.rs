use std::num::ParseIntError;

use p384::ecdsa::{VerifyingKey, SigningKey, Signature, signature::{Verifier,Signer,Error as SignatureError}};

pub trait PCRProvider {
  fn pcr0(&self) -> &str;
  fn pcr1(&self) -> &str;
  fn pcr2(&self) -> &str;
  fn pcr8(&self) -> &str;
}

/// Format a set of PCRs to be signed. All PCR values and their labels are capitalised in the signature payload.
/// The returned value is the UTF8 encoded signature payload.
/// 
/// The PCRs are formatted as follows:
/// PCR0
/// <PCR0 Value>
/// PCR1
/// <PCR1 Value>
/// PCR2
/// <PCR2 Value>
/// PCR8
/// <PCR8 Value>
/// 
/// 
/// For example, an Enclave with all 0 PCR values would produce a signature payload of:
/// PCR0
/// 000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
/// PCR1
/// 000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
/// PCR2
/// 000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
/// PCR8
/// 000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
pub fn format_signature_payload<T: PCRProvider>(pcr_provider: &T) -> Vec<u8> {
  let formatted_payload = format!(
    "PCR0\n{}\nPCR1\n{}\nPCR2\n{}\nPCR8\n{}",
    pcr_provider.pcr0().to_uppercase(),
    pcr_provider.pcr1().to_uppercase(),
    pcr_provider.pcr2().to_uppercase(),
    pcr_provider.pcr8().to_uppercase()
  );

  formatted_payload.as_bytes().to_vec()
}

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
    .map(|start_byte| u8::from_str_radix(&hex_str[start_byte..start_byte+1], 16))
    .collect()
}

/// Encode a set of PCRs according to the spec defined in `format_signature_payload`, and sign with the given private key.
/// Returns a der encoded signature in upper case hex.
pub fn sign_pcrs<T: PCRProvider>(private_key: SigningKey, pcr_provider: &T) -> String {
  let payload = format_signature_payload(pcr_provider);
  let signature: Signature = private_key.sign(&payload);
  let der_encoded_sig = signature.to_der();
  let hex_slice = HexSlice(der_encoded_sig.as_bytes());
  format!("{:X}", hex_slice)
}

/// Error types returned from verifying a signature over PCRs
#[derive(Debug)]
pub enum SignatureVerificationError {
  HexDecode,
  SignatureError(SignatureError)
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
          },
          Self::SignatureError(e) => {
            write!(f, "Failed to validate provided signature over the PCR set provided - {e}")?;
          }
        };
        Ok(())
    }
}

impl std::error::Error for SignatureVerificationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
          Self::SignatureError(e) => e.source(),
          _ => None
        }
    }
}

/// Verify a signature over a set of PCRs using the provided verifying key. Returns `Ok(())` if the signature is deemed to be valid, else an `Err(SignatureVerificationError)`
pub fn verify_pcrs<T: PCRProvider>(public_key: VerifyingKey, signature: String, pcr_provider: &T) -> Result<(), SignatureVerificationError> {
  let signature_payload = format_signature_payload(pcr_provider);
  let decoded_signature = decode_hex(&signature)?;
  let signature = Signature::from_der(&decoded_signature)?;
  public_key.verify(&signature_payload, &signature)?;
  Ok(())
}