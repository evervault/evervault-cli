use crate::api;
use crate::api::cage::CagesClient;
use crate::api::{client::ApiClient, AuthMode};
use crate::common::get_progress_bar;
use crate::config::CageConfig;
mod error;
use error::DeleteError;
use indicatif::ProgressBar;

pub async fn delete_cage(config: &str, api_key: &str) -> Result<(), DeleteError> {
    let cage_config = CageConfig::try_from_filepath(config)?;

    let cage_uuid = match cage_config.uuid {
        Some(uuid) => uuid,
        None => return Err(DeleteError::MissingUuid),
    };

    let cage_api = api::cage::CagesClient::new(AuthMode::ApiKey(api_key.to_string()));

    let deleted_cage = match cage_api.delete_cage(&cage_uuid).await {
        Ok(cage_ref) => cage_ref,
        Err(e) => {
            log::error!("Error initiating cage deletion — {:?}", e);
            return Err(DeleteError::ApiError(e));
        }
    };

    let progress_bar = get_progress_bar("Deleting Cage...");

    watch_deletion(cage_api, deleted_cage.uuid(), progress_bar).await;
    Ok(())
}

async fn watch_deletion(cage_api: CagesClient, cage_uuid: &str, progress_bar: ProgressBar) {
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
                log::error!("Unable to retrieve deletion status. Error: {:?}", e);
                break;
            }
        };
        tokio::time::sleep(std::time::Duration::from_millis(6000)).await;
    }
}
