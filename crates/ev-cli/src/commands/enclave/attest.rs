use attestation_doc_validation::attestation_doc::PCRs;
use attestation_doc_validation::PCRProvider;
use clap::Parser;
use common::api::BasicAuth;
use ev_enclave::attest::attest_connection_to_enclave;
use ev_enclave::config::EnclaveConfig;
use ev_enclave::describe::describe_eif;

/// Validate the attestation doc provided by an Enclave
#[derive(Debug, Parser)]
#[command(name = "attest", about)]
pub struct AttestArgs {
    /// Path to enclave.toml config file
    #[arg(short = 'c', long = "config", default_value = "./enclave.toml")]
    pub config: String,
    /// Path to EIF file. When included, the attestation measures returned from the Enclave will be compared to the measures of the EIF.
    #[arg(long = "eif-path")]
    pub eif_path: Option<String>,
}

macro_rules! unwrap_or_exit_with_error {
    ($res:expr) => {
        match $res {
            Ok(val) => val,
            Err(e) => {
                log::error!("{}", e.to_string());
                return exitcode::SOFTWARE;
            }
        }
    };
}

pub async fn run(attest_args: AttestArgs, _: BasicAuth) -> i32 {
    let config = unwrap_or_exit_with_error!(EnclaveConfig::try_from_filepath(&attest_args.config));
    let domain = unwrap_or_exit_with_error!(config.get_enclave_domain());

    let expected_pcrs = if let Some(eif_path) = attest_args.eif_path {
        let description = unwrap_or_exit_with_error!(describe_eif(&eif_path, false, false));
        description.measurements.measurements().clone()
    } else {
        unwrap_or_exit_with_error!(config.get_attestation()).clone()
    };

    let expected_pcrs = PCRs {
        pcr_0: expected_pcrs.pcrs().pcr0.clone(),
        pcr_1: expected_pcrs.pcrs().pcr1.clone(),
        pcr_2: expected_pcrs.pcrs().pcr2.clone(),
        pcr_8: expected_pcrs
            .pcrs()
            .pcr8
            .as_ref()
            .expect("When PCRs are set in the toml file, PCR8 should always be present")
            .clone(),
    };

    match attest_connection_to_enclave(&domain, expected_pcrs.clone()).await {
        Ok(_) => {
            log::info!("Attestation successful!\n\nhttps://{} returned a signed attestation doc which had PCRs:\n\n{}", domain, expected_pcrs.to_string());
            exitcode::OK
        }
        Err(e) => {
            log::error!("Failed to attest Enclave - {e}");
            exitcode::SOFTWARE
        }
    }
}
