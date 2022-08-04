use crate::describe::describe_eif;
use clap::Parser;

/// Get the PCRs of a built EIF
#[derive(Debug, Parser)]
#[clap(name = "describe", about)]
pub struct DescribeArgs {
    /// Path to the EIF to descibe.
    #[clap(default_value = "./enclave.eif")]
    pub eif_path: String,
}

pub async fn run(describe_args: DescribeArgs) {
    let description = match describe_eif(&describe_args.eif_path) {
        Ok(measurements) => measurements,
        Err(e) => {
            log::error!("Failed to describe eif — {}", e);
            return;
        }
    };

    println!("{}", serde_json::to_string_pretty(&description).unwrap());
}
