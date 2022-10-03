use crate::api::{client::ApiClient, AuthMode};
use crate::common::CliError;
use crate::config::{read_and_validate_config, BuildTimeConfig};
use crate::{api, get_api_key};
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
    Cages,
    /// List Cage Deployments
    #[clap()]
    Deployments(DeploymentArgs),
}

#[derive(Debug, Parser)]
pub struct DeploymentArgs {
    /// The cage uuid to get deployments for
    #[clap(long = "cage-uuid")]
    cage_uuid: Option<String>,

    /// The file containing the Cage config
    #[clap(short = 'c', long = "config", default_value = "./cage.toml")]
    config: String,
}
impl BuildTimeConfig for DeploymentArgs {}

pub async fn run(list_action: List) -> exitcode::ExitCode {
    let api_key = get_api_key!();
    let auth = AuthMode::ApiKey(api_key);

    let cage_client = api::cage::CagesClient::new(auth);

    match list_action.resource {
        ListCommands::Cages => list_cages(&cage_client).await,
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
    log::info!("{}", serialized_cages);
    exitcode::OK
}

async fn list_deployments(
    cage_client: &api::cage::CagesClient,
    deployment_args: DeploymentArgs,
) -> exitcode::ExitCode {
    let cage_uuid = if let Some(uuid) = deployment_args.cage_uuid.clone() {
        uuid
    } else {
        match read_and_validate_config(&deployment_args.config, &deployment_args) {
            Ok((_, validated_config)) => validated_config.cage_uuid().to_string(),
            Err(e) => {
                log::error!(
                    "No Cage uuid provided, and failed to parse the Cage config - {}",
                    e
                );
                return e.exitcode();
            }
        }
    };

    let cages = match cage_client.get_cage(&cage_uuid).await {
        Ok(cages) => cages,
        Err(e) => {
            log::error!("An error occurred while retrieving your Cages — {:?}", e);
            return e.exitcode();
        }
    };

    let serialized_cages = serde_json::to_string_pretty(&cages).unwrap();
    log::info!("{}", serialized_cages);
    exitcode::OK
}
