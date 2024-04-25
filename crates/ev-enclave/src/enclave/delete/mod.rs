use crate::enclave::{
    api,
    api::enclave::EnclaveApi,
    api::AuthMode,
    common,
    progress::{get_tracker, poll_fn_and_report_status, ProgressLogger, StatusReport},
};
use std::sync::Arc;
mod error;
use error::DeleteError;

pub async fn delete_enclave(
    config: &str,
    enclave_uuid: Option<&str>,
    api_key: &str,
    background: bool,
) -> Result<(), DeleteError> {
    let maybe_enclave_uuid = common::resolve_enclave_uuid(enclave_uuid, config)?;
    let enclave_uuid = match maybe_enclave_uuid {
        Some(given_enclave_uuid) => given_enclave_uuid,
        _ => return Err(DeleteError::MissingUuid),
    };

    let enclave_api = api::enclave::EnclaveClient::new(AuthMode::ApiKey(api_key.to_string()));

    let deleted_enclave = match enclave_api.delete_enclave(&enclave_uuid).await {
        Ok(enclave_ref) => enclave_ref,
        Err(e) => {
            return Err(DeleteError::ApiError(e));
        }
    };

    if !background {
        let progress_bar = get_tracker("Deleting Enclave...", None);

        watch_deletion(enclave_api, deleted_enclave.uuid(), progress_bar).await?;
    }
    Ok(())
}

async fn watch_deletion<T: EnclaveApi>(
    enclave_api: T,
    enclave_uuid: &str,
    progress_bar: impl ProgressLogger,
) -> Result<(), DeleteError> {
    async fn check_delete_status<T: EnclaveApi>(
        enclave_api: Arc<T>,
        args: Vec<String>,
    ) -> Result<StatusReport, DeleteError> {
        let enclave_uuid = args.get(0).unwrap();
        let enclave_response = match enclave_api.get_enclave(enclave_uuid).await {
            Ok(response) => response,
            Err(e) => {
                log::error!("Unable to retrieve deletion status. Error: {:?}", e);
                return Err(e.into());
            }
        };
        if enclave_response.is_deleted() {
            Ok(StatusReport::Complete("Enclave deleted!".to_string()))
        } else {
            Ok(StatusReport::NoOp)
        }
    }

    let check_delete_args = vec![enclave_uuid.to_string()];
    poll_fn_and_report_status(
        Arc::new(enclave_api),
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
    use crate::enclave::{
        api::client::ApiError,
        api::enclave::{DeleteEnclaveResponse, EnclaveState, MockEnclaveApi},
        progress::NonTty,
        test_utils::build_get_enclave_response,
    };

    #[tokio::test]
    async fn test_watch_deletion_with_healthy_responses() {
        let mut mock_api = MockEnclaveApi::new();

        let mut responses = vec![
            build_get_enclave_response(EnclaveState::Pending, vec![]),
            build_get_enclave_response(EnclaveState::Deleting, vec![]),
            build_get_enclave_response(EnclaveState::Deleted, vec![]),
        ]
        .into_iter();

        mock_api
            .expect_get_enclave()
            .times(3)
            .returning(move |_| Box::pin(std::future::ready(Ok(responses.next().unwrap()))));
        let result = watch_deletion(mock_api, "abc".into(), NonTty).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_watch_deletion_with_errors() {
        let mut mock_api = MockEnclaveApi::new();

        let mut responses = vec![
            ApiError::new(api::client::ApiErrorKind::Internal),
            ApiError::new(api::client::ApiErrorKind::Internal),
            ApiError::new(api::client::ApiErrorKind::Internal),
            ApiError::new(api::client::ApiErrorKind::Internal),
            ApiError::new(api::client::ApiErrorKind::Internal),
        ]
        .into_iter();

        mock_api
            .expect_get_enclave()
            .times(5)
            .returning(move |_| Box::pin(std::future::ready(Err(responses.next().unwrap()))));
        let result = watch_deletion(mock_api, "abc".into(), NonTty).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_delete_enclave_performs_polling_enclave_status() {
        let mut mock_api = MockEnclaveApi::new();
        mock_api.expect_delete_enclave().returning(move |_| {
            Box::pin(std::future::ready(Ok(DeleteEnclaveResponse {
                uuid: "abc".into(),
                name: "def".into(),
                team_uuid: "team".into(),
                app_uuid: "app".into(),
                domain: "enclave.com".into(),
                state: EnclaveState::Deleting,
                created_at: "".into(),
                updated_at: "".into(),
            })))
        });

        let mut responses = vec![
            Ok(build_get_enclave_response(EnclaveState::Deleting, vec![])),
            Ok(build_get_enclave_response(EnclaveState::Deleting, vec![])),
            Err(ApiError::new(api::client::ApiErrorKind::Internal)),
            Ok(build_get_enclave_response(EnclaveState::Deleted, vec![])),
        ]
        .into_iter();

        mock_api
            .expect_get_enclave()
            .times(4)
            .returning(move |_| Box::pin(std::future::ready(responses.next().unwrap())));
        let result = watch_deletion(mock_api, "abc".into(), NonTty).await;
        assert!(result.is_ok());
    }
}
