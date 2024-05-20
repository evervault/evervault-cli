use super::client::{ApiError, ApiErrorKind, ApiResult};

pub async fn upload_function_s3(signed_url: &str, function: tokio::fs::File) -> ApiResult<()> {
    let res = reqwest::Client::new()
        .put(signed_url)
        .header("x-aws-acl", "private")
        .header("Content-Type", "application/zip")
        .header(
            "Content-Length",
            function
                .metadata()
                .await
                .map_err(|_| ApiError::new(ApiErrorKind::Unknown(None)))?
                .len()
                .to_string(),
        )
        .body(reqwest::Body::wrap_stream(
            tokio_util::io::ReaderStream::new(function),
        ))
        .send()
        .await?;

    if !res.status().is_success() {
        return Err(res.status().into());
    }

    Ok(())
}
