use crate::api;
use crate::api::cage::CagesClient;
use crate::api::{client::ApiClient, AuthMode};
use crate::common::{get_tracker, ProgressLogger};
use crate::config::{CageConfig, ValidatedCageBuildConfig};
mod error;
use error::DeleteError;

pub async fn delete_cage(config: &str, api_key: &str) -> Result<(), DeleteError> {
    let cage_config = CageConfig::try_from_filepath(config)?;
    let validated_config: ValidatedCageBuildConfig = cage_config.as_ref().try_into()?;

    let cage_uuid = validated_config.cage_uuid().to_string();

    let cage_api = api::cage::CagesClient::new(AuthMode::ApiKey(api_key.to_string()));

    let deleted_cage = match cage_api.delete_cage(&cage_uuid).await {
        Ok(cage_ref) => cage_ref,
        Err(e) => {
            eprintln!("Error initiating cage deletion — {:?}", e);
            return Err(DeleteError::ApiError(e));
        }
    };

    let progress_bar = get_tracker("Deleting Cage...", false);

    watch_deletion(cage_api, deleted_cage.uuid(), progress_bar).await;
    Ok(())
}

async fn watch_deletion(cage_api: CagesClient, cage_uuid: &str, progress_bar: impl ProgressLogger) {
    loop {
        match cage_api.get_cage(cage_uuid).await {
            Ok(cage_response) => {
                if cage_response.is_deleted() {
                    progress_bar.finish_with_message("Cage deleted!");
                    break;
                }
            }
            Err(e) => {
                progress_bar.finish();
                println!("Unable to retrieve deletion status. Error: {:?}", e);
                break;
            }
        };
        tokio::time::sleep(std::time::Duration::from_millis(6000)).await;
    }
}
