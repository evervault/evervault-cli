use crate::api;
use crate::api::cage::CagesClient;
use crate::api::{client::ApiClient, AuthMode};
use crate::cli::delete::DeleteArgs;
use crate::config::{CageConfig, ValidatedCageBuildConfig};
mod error;
use error::DeleteError;
use indicatif::{ProgressBar, ProgressStyle};

pub async fn delete_cage(delete_args: DeleteArgs) -> Result<(), DeleteError> {
    let cage_config = CageConfig::try_from_filepath(&delete_args.config)?;

    let validated_config: ValidatedCageBuildConfig = cage_config.clone().try_into()?;

    let cage_uuid = validated_config.cage_uuid().to_string();

    let cage_api = api::cage::CagesClient::new(AuthMode::ApiKey(delete_args.api_key.clone()));

    let get_progress_bar = |start_msg: &str| {
        let progress_bar = ProgressBar::new_spinner();
        progress_bar.enable_steady_tick(80);
        progress_bar.set_style(
            ProgressStyle::default_spinner()
                .tick_strings(&["⣾", "⣽", "⣻", "⢿", "⡿", "⣟", "⣯", "⣷", "[INFO]"])
                .template("{spinner:.green} {msg}"),
        );
        progress_bar.set_message(start_msg);
        progress_bar
    };

    let deleted_cage = match cage_api.delete_cage(&cage_uuid).await {
        Ok(cage_ref) => cage_ref,
        Err(e) => {
            eprintln!("Error initiating cage deletion — {:?}", e);
            return Err(DeleteError::ApiError(e));
        }
    };

    let progress_bar = get_progress_bar("Deleting Cage...");

    watch_deletion(
        cage_api,
        deleted_cage.uuid(),
        progress_bar,
    )
    .await;
    Ok(())
}

async fn watch_deletion(
    cage_api: CagesClient,
    cage_uuid: &str,
    progress_bar: ProgressBar,
) {
    loop {
        match cage_api
            .get_cage(cage_uuid)
            .await
        {
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
