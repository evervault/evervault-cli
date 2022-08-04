use super::AuthMode;
use async_trait::async_trait;
use reqwest::{Client, RequestBuilder, Response};
use reqwest::{Error, Result};
use serde::de::DeserializeOwned;
use std::time::Duration;

#[derive(Clone)]
pub struct GenericApiClient {
    client: Client,
    auth: AuthMode,
}

impl Default for GenericApiClient {
    fn default() -> Self {
        let client = Client::builder().timeout(Duration::from_secs(60)).build();
        Self {
            client: client.unwrap(),
            auth: AuthMode::NoAuth,
        }
    }
}

impl std::convert::From<AuthMode> for GenericApiClient {
    fn from(auth_mode: AuthMode) -> Self {
        let mut client = Self::default();
        client.auth = auth_mode;
        client
    }
}

impl ApiClient for GenericApiClient {
    fn new(auth_mode: AuthMode) -> Self {
        Self::from(auth_mode)
    }

    fn auth(&self) -> &AuthMode {
        &self.auth
    }

    fn update_auth(&mut self, auth: AuthMode) {
        self.auth = auth;
    }

    fn client(&self) -> &Client {
        &self.client
    }
}

pub trait ApiClient {
    fn new(auth_mode: AuthMode) -> Self;
    fn auth(&self) -> &AuthMode;
    fn update_auth(&mut self, auth: AuthMode);
    fn client(&self) -> &Client;

    #[cfg(debug_assertions)]
    fn base_url(&self) -> String {
        std::env::var("EV_API_URL").unwrap_or(String::from("http://localhost:3000"))
    }

    #[cfg(not(debug_assertions))]
    fn base_url(&self) -> String {
        String::from("https://internal-api.evervault.com")
    }

    fn user_agent(&self) -> String {
        format!("evervault-cage-cli/{}", env!("CARGO_PKG_VERSION"))
    }

    fn is_authorised(&self) -> bool {
        !matches!(self.auth(), AuthMode::NoAuth)
    }

    fn get(&self, url: &String) -> RequestBuilder {
        self.prepare(self.client().get(url))
    }

    fn post(&self, url: &String) -> RequestBuilder {
        self.prepare(self.client().post(url))
    }

    fn put(&self, url: &String) -> RequestBuilder {
        self.prepare(self.client().put(url))
    }

    fn delete(&self, url: &String) -> RequestBuilder {
        self.prepare(self.client().delete(url))
    }

    fn prepare(&self, mut request_builder: RequestBuilder) -> RequestBuilder {
        request_builder = request_builder.header("user-agent", self.user_agent());
        match &self.auth() {
            AuthMode::NoAuth => request_builder,
            AuthMode::ApiKey(api_key) => request_builder.header("api-key", api_key),
            AuthMode::BearerAuth(token) => request_builder.bearer_auth(token),
        }
    }
}

#[async_trait]
pub trait HandleResponse {
    async fn handle_response<T: DeserializeOwned>(self) -> ApiResult<T>;
    fn handle_no_op_response(self) -> ApiResult<()>;
}

#[async_trait]
impl HandleResponse for Result<Response> {
    async fn handle_response<T: DeserializeOwned>(self) -> ApiResult<T> {
        match self {
            Ok(res) if res.status().is_success() => res
                .json()
                .await
                .map_err(|e| ApiError::ParsingError(e.to_string())),
            Ok(res) => Err(ApiError::get_error_from_status(res.status().as_u16())),
            Err(e) => Err(ApiError::Unknown(Some(e))),
        }
    }

    fn handle_no_op_response(self) -> ApiResult<()> {
        match self {
            Ok(res) if res.status().is_success() => Ok(()),
            Ok(res) => Err(ApiError::get_error_from_status(res.status().as_u16())),
            Err(e) => Err(ApiError::Unknown(Some(e))),
        }
    }
}

#[derive(Debug)]
pub enum ApiError {
    BadRequest,
    NotFound,
    Unauthorized,
    Internal,
    Forbidden,
    Conflict,
    Unknown(Option<Error>),
    ParsingError(String),
}

pub type ApiResult<T> = core::result::Result<T, ApiError>;

impl ApiError {
    pub fn get_error_from_status(code: u16) -> Self {
        match code {
            400 => Self::BadRequest,
            401 => Self::Unauthorized,
            403 => Self::Forbidden,
            404 => Self::NotFound,
            409 => Self::Conflict,
            500 => Self::Internal,
            _ => Self::Unknown(None),
        }
    }

    pub fn to_msg(&self) -> String {
        match self {
            Self::BadRequest => "400: Bad Request".to_owned(),
            Self::Unauthorized => "401: Unauthorized".to_owned(),
            Self::Forbidden => "403: Forbidden".to_owned(),
            Self::NotFound => "404: Not Found".to_owned(),
            Self::Conflict => "409: Conflict".to_owned(),
            Self::Internal => "500: Internal Server Error".to_owned(),
            Self::Unknown(e) => format!("An unexpected error occured: {:?}", e),
            Self::ParsingError(_) => {
                "An error occurred while parsing the server's response.to_owned()".to_owned()
            }
        }
    }
}
