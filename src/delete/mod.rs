use crate::api;
use crate::api::cage::CagesClient;
use crate::api::{client::ApiClient, AuthMode};
use crate::config::{CageConfig, CageConfigError};
use crate::progress::{get_tracker, ProgressLogger};
mod error;
use error::DeleteError;

fn resolve_cage_uuid(given_uuid: Option<&str>, config_path: &str) -> Result<Option<String>, CageConfigError> {
  if let Some(given_uuid) = given_uuid {
    return Ok(Some(given_uuid.to_string()));
  }
  let config = CageConfig::try_from_filepath(config_path)?;
  Ok(config.uuid)
}

pub async fn delete_cage(
    config: &str,
    cage_uuid: Option<&str>,
    api_key: &str,
    background: bool,
) -> Result<(), DeleteError> {
    let maybe_cage_uuid = resolve_cage_uuid(cage_uuid, config)?;
    let cage_uuid = match maybe_cage_uuid {
        Some(given_cage_uuid) => given_cage_uuid,
        _ => return Err(DeleteError::MissingUuid),
    };

    let cage_api = api::cage::CagesClient::new(AuthMode::ApiKey(api_key.to_string()));

    let deleted_cage = match cage_api.delete_cage(&cage_uuid).await {
        Ok(cage_ref) => cage_ref,
        Err(e) => {
            log::error!("Error initiating cage deletion — {:?}", e);
            return Err(DeleteError::ApiError(e));
        }
    };

    if !background {
        let progress_bar = get_tracker("Deleting Cage...", None);

        watch_deletion(cage_api, deleted_cage.uuid(), progress_bar).await;
    }
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
                log::error!("Unable to retrieve deletion status. Error: {:?}", e);
                break;
            }
        };
        tokio::time::sleep(std::time::Duration::from_millis(6000)).await;
    }
}
