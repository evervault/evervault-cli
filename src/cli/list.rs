use crate::api;
use crate::api::{client::ApiClient, AuthMode};
use clap::Parser;

/// List your Cages and Deployments
#[derive(Debug, Parser)]
#[clap(name = "list", about)]
pub struct List {
    /// The resource to list
    #[clap(subcommand)]
    resource: ListCommands,
    /// The API key to use to authenticate with the API
    #[clap(long = "api-key")]
    pub api_key: String,
}

/// The supported list commands
#[derive(Debug, Parser)]
#[clap(name = "list", about)]
pub enum ListCommands {
    /// List Cages
    #[clap()]
    Cages,
}

pub async fn run(list_action: List) {
    let auth = AuthMode::ApiKey(list_action.api_key.clone());

    let cage_client = api::cage::CagesClient::new(auth);

    match list_action.resource {
        ListCommands::Cages => list_cages(&cage_client).await,
    }
}

async fn list_cages(cage_client: &api::cage::CagesClient) {
    let cages = match cage_client.get_cages().await {
        Ok(cages) => cages,
        Err(e) => {
            log::error!("An error occurred while retrieving your Cages — {:?}", e);
            return;
        }
    };

    let serialized_cages = serde_json::to_string_pretty(&cages).unwrap();
    println!("{}", serialized_cages);
}
