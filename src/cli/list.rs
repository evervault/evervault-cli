use crate::api;
use crate::api::{client::ApiClient, AuthMode};
use crate::common::CliError;
use clap::Parser;

/// List your Cages and Deployments
#[derive(Debug, Parser)]
#[clap(name = "list", about)]
pub struct List {
    /// The resource to list
    #[clap(subcommand)]
    resource: ListCommands,
}

/// The supported list commands
#[derive(Debug, Parser)]
#[clap(name = "list", about)]
pub enum ListCommands {
    /// List Cages
    #[clap()]
    Cages(CageListArgs),
    /// List Cage Deployments
    #[clap()]
    Deployments(DeploymentArgs),
}

impl ListCommands {
    fn get_api_key(&self) -> String {
        match self {
            Self::Cages(args) => args.api_key.clone(),
            Self::Deployments(args) => args.api_key.clone(),
        }
    }
}

#[derive(Debug, Parser)]
pub struct CageListArgs {
    /// The API key to use to authenticate with the API
    #[clap(long = "api-key")]
    pub api_key: String,
}

#[derive(Debug, Parser)]
pub struct DeploymentArgs {
    /// The cage uuid to get deployments for
    #[clap(long = "cage-uuid")]
    cage_uuid: String,
    /// The API key to use to authenticate with the API
    #[clap(long = "api-key")]
    pub api_key: String,
}

pub async fn run(list_action: List) -> exitcode::ExitCode {
    let auth = AuthMode::ApiKey(list_action.resource.get_api_key());

    let cage_client = api::cage::CagesClient::new(auth);

    match list_action.resource {
        ListCommands::Cages(_) => list_cages(&cage_client).await,
        ListCommands::Deployments(deployment_args) => {
            list_deployments(&cage_client, deployment_args).await
        }
    }
}

async fn list_cages(cage_client: &api::cage::CagesClient) -> exitcode::ExitCode {
    let cages = match cage_client.get_cages().await {
        Ok(cages) => cages,
        Err(e) => {
            log::error!("An error occurred while retrieving your Cages — {:?}", e);
            return e.exitcode();
        }
    };

    let serialized_cages = serde_json::to_string_pretty(&cages).unwrap();
    println!("{}", serialized_cages);
    exitcode::OK
}

async fn list_deployments(
    cage_client: &api::cage::CagesClient,
    deployment_args: DeploymentArgs,
) -> exitcode::ExitCode {
    let cages = match cage_client.get_cage(&deployment_args.cage_uuid).await {
        Ok(cages) => cages,
        Err(e) => {
            log::error!("An error occurred while retrieving your Cages — {:?}", e);
            return e.exitcode();
        }
    };

    let serialized_cages = serde_json::to_string_pretty(&cages).unwrap();
    println!("{}", serialized_cages);
    exitcode::OK
}
