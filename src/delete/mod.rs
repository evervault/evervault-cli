use crate::api;
use crate::api::cage::CagesClient;
use crate::api::AuthMode;
use crate::config::{CageConfig, CageConfigError};
use crate::progress::{get_tracker, poll_fn_and_report_status, ProgressLogger, StatusReport};
mod error;
use error::DeleteError;

fn resolve_cage_uuid(
    given_uuid: Option<&str>,
    config_path: &str,
) -> Result<Option<String>, CageConfigError> {
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
    async fn check_delete_status(
        cage_api: CagesClient,
        args: Vec<String>,
    ) -> Result<StatusReport, DeleteError> {
        let cage_uuid = args.get(0).unwrap();
        match cage_api.get_cage(cage_uuid).await {
            Ok(cage_response) if cage_response.is_deleted() => {
                Ok(StatusReport::Complete("Cage deleted!".to_string()))
            }
            Ok(_) => Ok(StatusReport::NoOp),
            Err(e) => {
                log::error!("Unable to retrieve deletion status. Error: {:?}", e);
                Ok(StatusReport::Failed)
            }
        }
    }

    let check_delete_args = vec![cage_uuid.to_string()];
    let _ = poll_fn_and_report_status(
        cage_api,
        check_delete_args,
        check_delete_status,
        progress_bar,
    )
    .await;
}
