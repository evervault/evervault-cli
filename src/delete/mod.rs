use std::sync::Arc;

use crate::api;
use crate::api::cage::CageApi;
use crate::api::AuthMode;
use crate::progress::{get_tracker, poll_fn_and_report_status, ProgressLogger, StatusReport};
mod error;
use error::DeleteError;

pub async fn delete_cage(
    config: &str,
    cage_uuid: Option<&str>,
    api_key: &str,
    background: bool,
) -> Result<(), DeleteError> {
    let maybe_cage_uuid = crate::common::resolve_cage_uuid(cage_uuid, config)?;
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

        watch_deletion(cage_api, deleted_cage.uuid(), progress_bar).await?;
    }
    Ok(())
}

async fn watch_deletion<T: CageApi>(
    cage_api: T,
    cage_uuid: &str,
    progress_bar: impl ProgressLogger,
) -> Result<(), DeleteError> {
    async fn check_delete_status<T: CageApi>(
        cage_api: Arc<T>,
        args: Vec<String>,
    ) -> Result<StatusReport, DeleteError> {
        let cage_uuid = args.get(0).unwrap();
        let cage_response = match cage_api.get_cage(cage_uuid).await {
            Ok(response) => response,
            Err(e) => {
                log::error!("Unable to retrieve deletion status. Error: {:?}", e);
                return Err(e.into());
            }
        };
        if cage_response.is_deleted() {
            Ok(StatusReport::Complete("Cage deleted!".to_string()))
        } else {
            Ok(StatusReport::NoOp)
        }
    }

    let check_delete_args = vec![cage_uuid.to_string()];
    poll_fn_and_report_status(
        Arc::new(cage_api),
        check_delete_args,
        check_delete_status,
        progress_bar,
    )
    .await?;
    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::api::cage::{CageState, DeleteCageResponse, MockCageApi};
    use crate::api::client::ApiError;
    use crate::progress::NonTty;
    use crate::test_utils::build_get_cage_response;

    #[tokio::test]
    async fn test_watch_deletion_with_healthy_responses() {
        let mut mock_api = MockCageApi::new();

        let mut responses = vec![
            build_get_cage_response(CageState::Pending, vec![]),
            build_get_cage_response(CageState::Deleting, vec![]),
            build_get_cage_response(CageState::Deleted, vec![]),
        ]
        .into_iter();

        mock_api
            .expect_get_cage()
            .times(3)
            .returning(move |_| Box::pin(std::future::ready(Ok(responses.next().unwrap()))));
        let result = watch_deletion(mock_api, "abc".into(), NonTty).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_watch_deletion_with_errors() {
        let mut mock_api = MockCageApi::new();

        let mut responses = vec![
            ApiError::new(api::client::ApiErrorKind::Internal),
            ApiError::new(api::client::ApiErrorKind::Internal),
            ApiError::new(api::client::ApiErrorKind::Internal),
            ApiError::new(api::client::ApiErrorKind::Internal),
            ApiError::new(api::client::ApiErrorKind::Internal),
        ]
        .into_iter();

        mock_api
            .expect_get_cage()
            .times(5)
            .returning(move |_| Box::pin(std::future::ready(Err(responses.next().unwrap()))));
        let result = watch_deletion(mock_api, "abc".into(), NonTty).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_delete_cage_performs_polling_cage_status() {
        let mut mock_api = MockCageApi::new();
        mock_api.expect_delete_cage().returning(move |_| {
            Box::pin(std::future::ready(Ok(DeleteCageResponse {
                uuid: "abc".into(),
                name: "def".into(),
                team_uuid: "team".into(),
                app_uuid: "app".into(),
                domain: "cage.com".into(),
                state: CageState::Deleting,
                created_at: "".into(),
                updated_at: "".into(),
            })))
        });

        let mut responses = vec![
            Ok(build_get_cage_response(CageState::Deleting, vec![])),
            Ok(build_get_cage_response(CageState::Deleting, vec![])),
            Err(ApiError::new(api::client::ApiErrorKind::Internal)),
            Ok(build_get_cage_response(CageState::Deleted, vec![])),
        ]
        .into_iter();

        mock_api
            .expect_get_cage()
            .times(4)
            .returning(move |_| Box::pin(std::future::ready(responses.next().unwrap())));
        let result = watch_deletion(mock_api, "abc".into(), NonTty).await;
        assert!(result.is_ok());
    }
}
