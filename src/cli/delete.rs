use crate::common::CliError;
use crate::delete::delete_cage;
use crate::get_api_key;
use clap::Parser;

/// Delete a Cage from a toml file.
#[derive(Debug, Parser)]
#[clap(name = "delete", about)]
pub struct DeleteArgs {
    /// Path to cage.toml config file
    #[clap(short = 'c', long = "config", default_value = "./cage.toml")]
    pub config: String,

    /// Disable verbose output
    #[clap(long)]
    pub quiet: bool,
}

pub async fn run(delete_args: DeleteArgs) -> exitcode::ExitCode {
    let api_key = get_api_key!();
    match delete_cage(delete_args.config.as_str(), api_key.as_str()).await {
        Ok(_) => println!("Deletion was successful"),
        Err(e) => {
            println!("{}", e);
            return e.exitcode();
        }
    };

    exitcode::OK
}
