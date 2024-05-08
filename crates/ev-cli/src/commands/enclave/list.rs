use crate::version::check_version;
use clap::Parser;
use common::{api::AuthMode, CliError};
use ev_enclave::api;
use ev_enclave::api::enclave::EnclaveApi;
use ev_enclave::config::{read_and_validate_config, BuildTimeConfig};

/// List your Enclaves and Deployments
#[derive(Debug, Parser)]
#[command(name = "list", about)]
pub struct List {
    /// The resource to list
    #[command(subcommand)]
    resource: ListCommands,
}

/// The supported list commands
#[derive(Debug, Parser)]
#[command(name = "list", about)]
pub enum ListCommands {
    /// List Enclaves
    #[command()]
    Enclaves,
    /// List Enclave Deployments
    #[command()]
    Deployments(DeploymentArgs),
}

#[derive(Debug, Parser)]
pub struct DeploymentArgs {
    /// The Enclave uuid to get deployments for
    #[arg(long = "enclave-uuid")]
    enclave_uuid: Option<String>,

    /// The file containing the Enclave config
    #[arg(short = 'c', long = "config", default_value = "./enclave.toml")]
    config: String,
}
impl BuildTimeConfig for DeploymentArgs {}

pub async fn run(list_action: List, api_key: String) -> exitcode::ExitCode {
    if let Err(e) = check_version().await {
        log::error!("{}", e);
        return exitcode::SOFTWARE;
    };

    let auth = AuthMode::ApiKey(api_key);

    let enclave_client = api::enclave::EnclaveClient::new(auth);

    match list_action.resource {
        ListCommands::Enclaves => list_enclaves(&enclave_client).await,
        ListCommands::Deployments(deployment_args) => {
            list_deployments(&enclave_client, deployment_args).await
        }
    }
}

async fn list_enclaves(enclave_client: &api::enclave::EnclaveClient) -> exitcode::ExitCode {
    let enclaves = match enclave_client.get_enclaves().await {
        Ok(enclaves) => enclaves,
        Err(e) => {
            log::error!("An error occurred while retrieving your Enclaves — {:?}", e);
            return e.exitcode();
        }
    };

    let serialized_enclaves = serde_json::to_string_pretty(&enclaves).unwrap();
    println!("{}", serialized_enclaves);
    exitcode::OK
}

async fn list_deployments(
    enclave_client: &api::enclave::EnclaveClient,
    deployment_args: DeploymentArgs,
) -> exitcode::ExitCode {
    let enclave_uuid = if let Some(uuid) = deployment_args.enclave_uuid.clone() {
        uuid
    } else {
        match read_and_validate_config(&deployment_args.config, &deployment_args) {
            Ok((_, validated_config)) => validated_config.enclave_uuid().to_string(),
            Err(e) => {
                log::error!(
                    "No Enclave uuid provided, and failed to parse the Enclave config - {}",
                    e
                );
                return e.exitcode();
            }
        }
    };

    let enclave = match enclave_client.get_enclave(&enclave_uuid).await {
        Ok(enclave) => enclave,
        Err(e) => {
            log::error!("An error occurred while retrieving your Enclaves — {:?}", e);
            return e.exitcode();
        }
    };

    let serialized_deployments = serde_json::to_string_pretty(&enclave).unwrap();
    println!("{}", serialized_deployments);
    exitcode::OK
}
