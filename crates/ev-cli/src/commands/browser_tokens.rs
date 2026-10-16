use crate::{errors, CmdOutput};
use clap::{builder::TypedValueParser, error::ErrorKind, Arg, Command, Parser};
use common::api::{client::ApiError, papi::EvApiClient};
use common::api::{papi::EvApi, BasicAuth};
use common::browser_tokens::{
    BrowserTokenData, BrowserTokenPermission, CreateBrowserTokens, CustomProxy, ProxyScheme,
    ProxySettings,
};
use percent_encoding::percent_decode_str;
use std::{ffi::OsStr, num::NonZeroU64};
use thiserror::Error;

/// Create browser tokens using the Evervault API
#[derive(Debug, Parser)]
#[command(name = "browser-tokens", about)]
pub struct BrowserTokensArgs {
    /// A sensitive value to tokenize, in the form <CATEGORY>:<ID>:<VALUE> (e.g. card.number:primary-card-pan:ev:encrypted:...). Can be repeated.
    ///
    /// CATEGORY is the type of value: card.number, card.cvv, or credential.password.
    ///
    /// ID is your own label for the value (1-64 characters, unique per request). It's used to match tokens in the response and appears in Evervault logs, so don't put sensitive data in it.
    #[arg(
        short,
        long = "data",
        value_name = "CATEGORY:ID:VALUE",
        required = true,
        value_parser = Redacted(parse_data)
    )]
    data: Vec<BrowserTokenData>,

    /// Where the tokens may be used, in the form <ACTION>:<TARGET> (e.g. decrypt:api.stripe.com). Can be repeated.
    ///
    /// ACTION is what's allowed, e.g. decrypt.
    ///
    /// TARGET is the hostname that receives the plaintext: an exact hostname, a subdomain wildcard like `*.shopify.com`, or `*` for any host.
    #[arg(
        short,
        long = "permission",
        value_name = "ACTION:TARGET",
        required = true,
        value_parser = parse_permission
    )]
    permissions: Vec<BrowserTokenPermission>,

    /// How long the tokens are valid for, in seconds
    #[arg(long)]
    ttl: Option<NonZeroU64>,

    /// Route through your own egress proxy, given as <http|https>://<USERNAME>:<PASSWORD>@<HOST>:<PORT>
    ///
    /// Percent-encode special characters in USERNAME and PASSWORD (e.g. `#` as `%23`, `/` as `%2F`).
    #[arg(long, value_name = "URL", value_parser = Redacted(parse_custom_proxy))]
    proxy: Option<CustomProxy>,
}

/// Wraps a value parser so a rejected value is never echoed back. Clap's own errors repeat the
/// whole argument, which for `--data` is the sensitive value and for `--proxy` holds a password.
#[derive(Clone)]
struct Redacted<F>(F);

impl<T, F> TypedValueParser for Redacted<F>
where
    T: Clone + Send + Sync + 'static,
    F: Fn(&str) -> Result<T, String> + Clone + Send + Sync + 'static,
{
    type Value = T;

    fn parse_ref(
        &self,
        cmd: &Command,
        arg: Option<&Arg>,
        value: &OsStr,
    ) -> Result<Self::Value, clap::Error> {
        let arg = arg.map(ToString::to_string).unwrap_or_default();
        let invalid = |reason: &str| {
            cmd.clone().error(
                ErrorKind::ValueValidation,
                format!("invalid value for '{arg}': {reason}"),
            )
        };

        let value = value.to_str().ok_or_else(|| invalid("not valid UTF-8"))?;
        (self.0)(value).map_err(|reason| invalid(&reason))
    }
}

fn parse_data(s: &str) -> Result<BrowserTokenData, String> {
    // The value goes last as encrypted values (ev:encrypted:...) contain colons
    match s.splitn(3, ':').collect::<Vec<_>>()[..] {
        [category, id, value] if !category.is_empty() && !id.is_empty() && !value.is_empty() => {
            Ok(BrowserTokenData {
                category: category.to_string(),
                id: id.to_string(),
                value: value.to_string(),
            })
        }
        _ => Err("expected the form <CATEGORY>:<ID>:<VALUE>".to_string()),
    }
}

fn parse_permission(s: &str) -> Result<BrowserTokenPermission, String> {
    match s.split_once(':') {
        Some((action, target)) if !action.is_empty() && !target.is_empty() => {
            Ok(BrowserTokenPermission {
                action: action.to_string(),
                target: target.to_string(),
            })
        }
        _ => Err("expected the form <ACTION>:<TARGET>".to_string()),
    }
}

fn parse_custom_proxy(s: &str) -> Result<CustomProxy, String> {
    const EXPECTED: &str = "expected the form <http|https>://<USERNAME>:<PASSWORD>@<HOST>:<PORT>";

    let url = url::Url::parse(s).map_err(|e| format!("{e}: {EXPECTED}"))?;
    let scheme = match url.scheme() {
        "http" => ProxyScheme::Http,
        "https" => ProxyScheme::Https,
        _ => return Err(format!("unsupported scheme: {EXPECTED}")),
    };
    if !matches!(url.path(), "" | "/") || url.query().is_some() || url.fragment().is_some() {
        return Err(format!(
            "a proxy has no path, query or fragment: {EXPECTED}"
        ));
    }
    let port = match url.port_or_known_default() {
        _ if !has_explicit_port(s) => return Err(format!("missing port: {EXPECTED}")),
        Some(0) | None => return Err("0 is not a valid port".to_string()),
        Some(port) => port,
    };
    let decode = |part: &str| {
        percent_decode_str(part)
            .decode_utf8()
            .map(|decoded| decoded.into_owned())
            .map_err(|_| "USERNAME and PASSWORD must be valid percent-encoded UTF-8".to_string())
    };

    match (url.username(), url.password(), url.host_str()) {
        (username, Some(password), Some(hostname)) if !username.is_empty() => Ok(CustomProxy {
            scheme,
            username: decode(username)?,
            password: decode(password)?,
            hostname: hostname.to_string(),
            port,
        }),
        _ => Err(EXPECTED.to_string()),
    }
}

/// Whether a port was written in the URL. Read off the input because `Url` drops a port that
/// matches the scheme's default, so `https://...:443` parses the same as having no port
fn has_explicit_port(s: &str) -> bool {
    let rest = s.split_once("://").map_or(s, |(_, rest)| rest);
    let authority = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    let host_and_port = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);

    host_and_port
        .rsplit_once(':')
        .is_some_and(|(_, port)| !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()))
}

impl BrowserTokensArgs {
    fn into_request(self) -> CreateBrowserTokens {
        CreateBrowserTokens {
            data: self.data,
            permissions: self.permissions,
            ttl: self.ttl,
            proxy_settings: self.proxy.map(ProxySettings::Custom),
        }
    }
}

/// Describes a request for `--verbose` output without the values being tokenized or the proxy credentials
fn summarize(request: &CreateBrowserTokens) -> String {
    let values = request
        .data
        .iter()
        .map(|data| format!("{} ({})", data.id, data.category))
        .collect::<Vec<_>>()
        .join(", ");
    let permissions = request
        .permissions
        .iter()
        .map(|permission| format!("{}:{}", permission.action, permission.target))
        .collect::<Vec<_>>()
        .join(", ");
    let ttl = request
        .ttl
        .map_or("server default".to_string(), |ttl| format!("{ttl}s"));
    let proxy = match &request.proxy_settings {
        Some(ProxySettings::Custom(proxy)) => {
            let scheme = match proxy.scheme {
                ProxyScheme::Http => "http",
                ProxyScheme::Https => "https",
            };
            format!("{scheme}://{}:{}", proxy.hostname, proxy.port)
        }
        None => "none".to_string(),
    };

    format!(
        "Creating browser tokens for {values}; permissions: {permissions}; ttl: {ttl}; proxy: {proxy}"
    )
}

#[derive(Error, Debug)]
pub enum BrowserTokensError {
    #[error("An error occurred while creating browser tokens: {0}")]
    ApiError(#[from] ApiError),
}

impl CmdOutput for BrowserTokensError {
    fn exitcode(&self) -> i32 {
        errors::SOFTWARE
    }

    fn code(&self) -> String {
        match self {
            BrowserTokensError::ApiError(_) => "generic/api-error",
        }
        .to_string()
    }

    fn data(&self) -> Option<serde_json::Value> {
        None
    }
}

#[derive(strum_macros::Display)]
pub enum BrowserTokensMessage {
    #[strum(to_string = "")]
    Success { tokens: serde_json::Value },
}

impl CmdOutput for BrowserTokensMessage {
    fn exitcode(&self) -> i32 {
        errors::OK
    }

    fn code(&self) -> String {
        match self {
            BrowserTokensMessage::Success { .. } => "generic/success",
        }
        .to_string()
    }

    fn data(&self) -> Option<serde_json::Value> {
        match self {
            BrowserTokensMessage::Success { tokens } => Some(tokens.clone()),
        }
    }
}

pub async fn run(
    args: BrowserTokensArgs,
    auth: BasicAuth,
) -> Result<BrowserTokensMessage, BrowserTokensError> {
    let api_client = EvApiClient::new(auth);
    let request = args.into_request();
    log::debug!("{}", summarize(&request));

    let tokens = api_client.create_browser_tokens(&request).await?;

    Ok(BrowserTokensMessage::Success { tokens })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_parse_data_keeps_colons_in_value() {
        let data = parse_data("card.number:primary-card-pan:ev:encrypted:abc").unwrap();
        assert_eq!(data.category, "card.number");
        assert_eq!(data.id, "primary-card-pan");
        assert_eq!(data.value, "ev:encrypted:abc");
    }

    #[test]
    fn test_parse_data_rejects_missing_parts() {
        assert!(parse_data("card.number:4242424242424242").is_err());
        assert!(parse_data("card.number::4242424242424242").is_err());
    }

    #[test]
    fn test_request_body_matches_api() {
        let args = BrowserTokensArgs::try_parse_from([
            "browser-tokens",
            "--data",
            "card.number:pan:ev:encrypted:abc",
            "--data",
            "card.cvv:cvv:123",
            "--permission",
            "decrypt:www.example-merchant.com",
            "--permission",
            "decrypt:*.payment-gateway.com",
            "--ttl",
            "300",
            "--proxy",
            "https://user:p%40ss@proxy.example.com:443",
        ])
        .unwrap();

        assert_eq!(
            serde_json::to_value(args.into_request()).unwrap(),
            json!({
                "data": [
                    { "category": "card.number", "id": "pan", "value": "ev:encrypted:abc" },
                    { "category": "card.cvv", "id": "cvv", "value": "123" }
                ],
                "permissions": [
                    { "action": "decrypt", "target": "www.example-merchant.com" },
                    { "action": "decrypt", "target": "*.payment-gateway.com" }
                ],
                "ttl": 300,
                "proxySettings": {
                    "type": "custom",
                    "scheme": "https",
                    "username": "user",
                    "password": "p@ss",
                    "hostname": "proxy.example.com",
                    "port": 443
                }
            })
        );
    }

    #[test]
    fn test_request_body_omits_optional_fields() {
        let args = BrowserTokensArgs::try_parse_from([
            "browser-tokens",
            "-d",
            "credential.password:login:secret",
            "-p",
            "decrypt:*",
        ])
        .unwrap();

        assert_eq!(
            serde_json::to_value(args.into_request()).unwrap(),
            json!({
                "data": [{ "category": "credential.password", "id": "login", "value": "secret" }],
                "permissions": [{ "action": "decrypt", "target": "*" }]
            })
        );
    }

    #[test]
    fn test_ttl_must_be_nonzero() {
        let parse = |ttl: &str| {
            BrowserTokensArgs::try_parse_from([
                "browser-tokens",
                "-d",
                "card.cvv:cvv:123",
                "-p",
                "decrypt:*",
                "--ttl",
                ttl,
            ])
        };

        assert!(parse("1").is_ok());
        assert!(parse("0").is_err());
    }

    #[test]
    fn test_parse_custom_proxy() {
        let proxy = parse_custom_proxy("http://user:pass@10.0.0.1:8080").unwrap();
        assert_eq!(proxy.scheme, ProxyScheme::Http);
        assert_eq!(proxy.hostname, "10.0.0.1");
        assert_eq!(proxy.port, 8080);

        assert!(parse_custom_proxy("https://proxy.example.com").is_err());
        assert!(parse_custom_proxy("https://user@proxy.example.com").is_err());
        assert!(parse_custom_proxy("socks5://user:pass@proxy.example.com:1080").is_err());
        assert!(parse_custom_proxy("http://user:pass@proxy.example.com:0").is_err());
    }

    #[test]
    fn test_parse_custom_proxy_requires_a_port() {
        assert_eq!(
            parse_custom_proxy("https://user:pass@proxy.example.com").unwrap_err(),
            "missing port: expected the form <http|https>://<USERNAME>:<PASSWORD>@<HOST>:<PORT>"
        );
        assert!(parse_custom_proxy("http://user:pass@[2001:db8::1]").is_err());

        // `Url` drops a port matching the scheme's default, which must still count as given
        assert_eq!(
            parse_custom_proxy("https://user:pass@proxy.example.com:443")
                .unwrap()
                .port,
            443
        );
        assert_eq!(
            parse_custom_proxy("http://user:pass@proxy.example.com:80/")
                .unwrap()
                .port,
            80
        );
        assert_eq!(
            parse_custom_proxy("http://user:pass@[2001:db8::1]:8080")
                .unwrap()
                .port,
            8080
        );
    }

    #[test]
    fn test_parse_custom_proxy_rejects_a_path_query_or_fragment() {
        for url in [
            "http://user:pass@proxy.example.com:8080/some/path",
            "http://user:pass@proxy.example.com:8080?x=1",
            "http://user:pass@proxy.example.com:8080#section",
        ] {
            assert!(parse_custom_proxy(url).is_err(), "{url} was accepted");
        }
    }

    #[test]
    fn test_parse_custom_proxy_decodes_credentials_strictly() {
        let proxy =
            parse_custom_proxy("http://us%3Aer:p%23ss%2Fword@proxy.example.com:8080").unwrap();
        assert_eq!(proxy.username, "us:er");
        assert_eq!(proxy.password, "p#ss/word");

        assert_eq!(
            parse_custom_proxy("http://user:%FF@proxy.example.com:8080").unwrap_err(),
            "USERNAME and PASSWORD must be valid percent-encoded UTF-8"
        );
    }

    #[test]
    fn test_summary_omits_secrets() {
        let args = BrowserTokensArgs::try_parse_from([
            "browser-tokens",
            "-d",
            "card.cvv:cvv:123",
            "-p",
            "decrypt:*.example.com",
            "--proxy",
            "https://user:hunter2@egress-proxy.example.com:443",
        ])
        .unwrap();

        let summary = summarize(&args.into_request());

        assert_eq!(
            summary,
            "Creating browser tokens for cvv (card.cvv); permissions: decrypt:*.example.com; \
             ttl: server default; proxy: https://egress-proxy.example.com:443"
        );
        assert!(!summary.contains("123") && !summary.contains("hunter2"));
    }

    #[test]
    fn test_invalid_values_are_not_echoed() {
        let parse = |extra: [&str; 2]| {
            let base = ["browser-tokens", "-p", "decrypt:*"];
            BrowserTokensArgs::try_parse_from(base.iter().chain(extra.iter()))
                .unwrap_err()
                .to_string()
        };

        let error = parse(["-d", "card.number:4242424242424242"]);
        assert!(error.contains("expected the form"), "{error}");
        assert!(!error.contains("4242424242424242"), "{error}");

        let error = parse(["-d", "card.cvv:cvv-without-a-value"]);
        assert!(!error.contains("cvv-without-a-value"), "{error}");

        let error = parse(["--proxy", "socks5://user:hunter2@proxy.example.com"]);
        assert!(error.contains("--proxy"), "{error}");
        assert!(!error.contains("hunter2"), "{error}");
    }

    #[test]
    fn test_parse_permission() {
        let permission = parse_permission("decrypt:*.shopify.com").unwrap();
        assert_eq!(permission.action, "decrypt");
        assert_eq!(permission.target, "*.shopify.com");

        assert_eq!(parse_permission("decrypt:*").unwrap().target, "*");
        // Which actions exist is left to the API, so a CLI release isn't needed when one is added
        assert_eq!(
            parse_permission("encrypt:api.stripe.com").unwrap().action,
            "encrypt"
        );

        assert!(parse_permission("api.stripe.com").is_err());
        assert!(parse_permission("decrypt:").is_err());
        assert!(parse_permission(":api.stripe.com").is_err());
    }
}
