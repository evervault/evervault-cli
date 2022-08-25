use crate::delete::delete_cage;
use clap::Parser;

/// Deploy a Cage from a toml file.
#[derive(Debug, Parser)]
#[clap(name = "deploy", about)]
pub struct DeleteArgs {
    /// Path to cage.toml config file
    #[clap(short = 'c', long = "config", default_value = "./cage.toml")]
    pub config: String,

    /// API Key
    #[clap(long = "api-key")]
    pub api_key: String,

    /// Disable verbose output
    #[clap(long)]
    pub quiet: bool,
}

pub async fn run(delete_args: DeleteArgs) {
    match delete_cage(delete_args).await {
        Ok(_) => println!("Deletion was successful"),
        Err(e) => println!("{}", e),
    };
}
