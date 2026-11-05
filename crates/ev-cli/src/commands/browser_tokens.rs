use crate::{errors, CmdOutput};
use clap::{builder::TypedValueParser, error::ErrorKind, Arg, ArgGroup, Command, Parser};
use common::api::{client::ApiError, papi::EvApiClient};
use common::api::{papi::EvApi, BasicAuth};
use common::browser_tokens::{
    BrowserTokenData, BrowserTokenPermission, CreateBrowserTokens, CustomProxy, ExitLocation,
    ProxyScheme, ProxySettings, Resource,
};
use percent_encoding::percent_decode_str;
use std::{ffi::OsStr, num::NonZeroU64};
use thiserror::Error;

/// Create browser tokens using the Evervault API
#[derive(Debug, Parser)]
#[command(name = "browser-tokens", about)]
#[command(group(
    ArgGroup::new("exit_area")
        .args(["exit_region", "exit_city", "exit_postal_code"])
        .multiple(false)
))]
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
    ///
    /// A TARGET starting with `ev:` is an Evervault-managed allow list instead, e.g. decrypt:ev:psps@1.
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

    /// How the session's traffic leaves Evervault: residential, datacenter, or your own egress proxy given as <http|https>://<USERNAME>:<PASSWORD>@<HOST>:<PORT>
    ///
    /// residential uses an Evervault-managed residential proxy; narrow where it exits with the --exit-* options.
    ///
    /// datacenter egresses directly from Evervault's infrastructure, the same as leaving --proxy out.
    ///
    /// For your own proxy, percent-encode special characters in USERNAME and PASSWORD (e.g. `#` as `%23`, `/` as `%2F`).
    #[arg(long, value_name = "residential|datacenter|URL", value_parser = Redacted(parse_proxy))]
    proxy: Option<ProxySettings>,

    /// Country a residential session exits from, as an ISO 3166-1 alpha-2 code (e.g. GB). Defaults to the deployment's country.
    #[arg(long, value_name = "CODE")]
    exit_country: Option<String>,

    /// Region within --exit-country, as an ISO 3166-2 code (e.g. US-CA)
    #[arg(long, value_name = "CODE", requires = "exit_country")]
    exit_region: Option<String>,

    /// City within --exit-country, by its English name (e.g. London)
    #[arg(long, value_name = "NAME", requires = "exit_country")]
    exit_city: Option<String>,

    /// Postal code within --exit-country (e.g. 90210)
    #[arg(long, value_name = "CODE", requires = "exit_country")]
    exit_postal_code: Option<String>,
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
            let resource = if target.starts_with("ev:") {
                Resource::AllowList(target.to_string())
            } else {
                Resource::Target(target.to_string())
            };
            Ok(BrowserTokenPermission {
                action: action.to_string(),
                resource,
            })
        }
        _ => Err("expected the form <ACTION>:<TARGET>".to_string()),
    }
}

fn parse_proxy(s: &str) -> Result<ProxySettings, String> {
    match s.to_lowercase().as_str() {
        "datacenter" => Ok(ProxySettings::Datacenter {}),
        "residential" => Ok(ProxySettings::Residential {
            exit_location: None,
        }),
        _ => parse_custom_proxy(s)
            .map(ProxySettings::Custom)
            .map_err(|reason| {
                if s.contains("://") {
                    reason
                } else {
                    "expected residential, datacenter or <http|https>://<USERNAME>:<PASSWORD>@<HOST>:<PORT>".to_string()
                }
            }),
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
    fn into_request(self) -> Result<CreateBrowserTokens, BrowserTokensError> {
        let exit_location = match (
            self.exit_country,
            self.exit_region,
            self.exit_city,
            self.exit_postal_code,
        ) {
            (None, ..) => None,
            (Some(country), Some(region), ..) => Some(ExitLocation::Region { country, region }),
            (Some(country), _, Some(city), _) => Some(ExitLocation::City { country, city }),
            (Some(country), _, _, Some(postal_code)) => Some(ExitLocation::PostalCode {
                country,
                postal_code,
            }),
            (Some(country), None, None, None) => Some(ExitLocation::Country { country }),
        };
        let proxy_settings = match self.proxy {
            Some(ProxySettings::Residential { .. }) => {
                Some(ProxySettings::Residential { exit_location })
            }
            proxy if exit_location.is_none() => proxy,
            _ => return Err(BrowserTokensError::ExitLocationRequiresResidential),
        };

        Ok(CreateBrowserTokens {
            data: self.data,
            permissions: self.permissions,
            ttl: self.ttl,
            proxy_settings,
        })
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
        .map(|permission| {
            let (Resource::Target(target) | Resource::AllowList(target)) = &permission.resource;
            format!("{}:{target}", permission.action)
        })
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
        Some(ProxySettings::Residential { exit_location }) => match exit_location {
            None => "residential (default country)".to_string(),
            Some(ExitLocation::Country { country }) => format!("residential ({country})"),
            Some(
                ExitLocation::Region {
                    country,
                    region: area,
                }
                | ExitLocation::City {
                    country,
                    city: area,
                }
                | ExitLocation::PostalCode {
                    country,
                    postal_code: area,
                },
            ) => format!("residential ({country}, {area})"),
        },
        Some(ProxySettings::Datacenter {}) => "datacenter".to_string(),
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
    #[error("--exit-country, --exit-region, --exit-city and --exit-postal-code can only be used with --proxy residential")]
    ExitLocationRequiresResidential,
}

impl CmdOutput for BrowserTokensError {
    fn exitcode(&self) -> i32 {
        match self {
            BrowserTokensError::ApiError(_) => errors::SOFTWARE,
            BrowserTokensError::ExitLocationRequiresResidential => errors::USAGE,
        }
    }

    fn code(&self) -> String {
        match self {
            BrowserTokensError::ApiError(_) => "generic/api-error",
            BrowserTokensError::ExitLocationRequiresResidential => "generic/invalid-arguments",
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
    let request = args.into_request()?;
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
            serde_json::to_value(args.into_request().unwrap()).unwrap(),
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
            serde_json::to_value(args.into_request().unwrap()).unwrap(),
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

        let summary = summarize(&args.into_request().unwrap());

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
        assert_eq!(
            permission.resource,
            Resource::Target("*.shopify.com".to_string())
        );

        assert_eq!(
            parse_permission("decrypt:*").unwrap().resource,
            Resource::Target("*".to_string())
        );
        // Which actions exist is left to the API, so a CLI release isn't needed when one is added
        assert_eq!(
            parse_permission("encrypt:api.stripe.com").unwrap().action,
            "encrypt"
        );

        assert!(parse_permission("api.stripe.com").is_err());
        assert!(parse_permission("decrypt:").is_err());
        assert!(parse_permission(":api.stripe.com").is_err());
    }

    #[test]
    fn test_parse_permission_allow_list() {
        let permission = parse_permission("decrypt:ev:psps@1").unwrap();
        assert_eq!(permission.action, "decrypt");
        assert_eq!(
            permission.resource,
            Resource::AllowList("ev:psps@1".to_string())
        );

        assert_eq!(
            parse_permission("decrypt:ev.example.com").unwrap().resource,
            Resource::Target("ev.example.com".to_string())
        );
    }

    #[test]
    fn test_request_body_with_allow_list() {
        let args = BrowserTokensArgs::try_parse_from([
            "browser-tokens",
            "-d",
            "card.cvv:cvv:123",
            "-p",
            "decrypt:ev:psps@1",
            "-p",
            "decrypt:api.stripe.com",
        ])
        .unwrap();
        let request = args.into_request().unwrap();

        assert_eq!(
            serde_json::to_value(&request).unwrap()["permissions"],
            json!([
                { "action": "decrypt", "allowList": "ev:psps@1" },
                { "action": "decrypt", "target": "api.stripe.com" }
            ])
        );
        assert!(
            summarize(&request).contains("permissions: decrypt:ev:psps@1, decrypt:api.stripe.com;")
        );
    }

    fn parse_args(extra: &[&str]) -> Result<BrowserTokensArgs, clap::Error> {
        let base = [
            "browser-tokens",
            "-d",
            "card.cvv:cvv:123",
            "-p",
            "decrypt:*",
        ];
        BrowserTokensArgs::try_parse_from(base.iter().chain(extra))
    }

    fn proxy_settings(extra: &[&str]) -> serde_json::Value {
        let request = parse_args(extra).unwrap().into_request().unwrap();
        serde_json::to_value(request).unwrap()["proxySettings"].clone()
    }

    #[test]
    fn test_datacenter_proxy() {
        assert_eq!(
            proxy_settings(&["--proxy", "datacenter"]),
            json!({ "type": "datacenter" })
        );
    }

    #[test]
    fn test_proxy_keywords_ignore_case() {
        assert_eq!(
            proxy_settings(&["--proxy", "Residential"]),
            json!({ "type": "residential" })
        );
    }

    #[test]
    fn test_residential_proxy_without_location_omits_it() {
        assert_eq!(
            proxy_settings(&["--proxy", "residential"]),
            json!({ "type": "residential" })
        );
    }

    #[test]
    fn test_residential_proxy_with_location() {
        assert_eq!(
            proxy_settings(&["--proxy", "residential", "--exit-country", "GB"]),
            json!({ "type": "residential", "country": "GB" })
        );
        assert_eq!(
            proxy_settings(&[
                "--proxy",
                "residential",
                "--exit-country",
                "US",
                "--exit-region",
                "US-CA"
            ]),
            json!({ "type": "residential", "country": "US", "region": "US-CA" })
        );
        assert_eq!(
            proxy_settings(&[
                "--proxy",
                "residential",
                "--exit-country",
                "GB",
                "--exit-city",
                "London"
            ]),
            json!({ "type": "residential", "country": "GB", "city": "London" })
        );
        assert_eq!(
            proxy_settings(&[
                "--proxy",
                "residential",
                "--exit-country",
                "US",
                "--exit-postal-code",
                "90210"
            ]),
            json!({ "type": "residential", "country": "US", "postalCode": "90210" })
        );
    }

    #[test]
    fn test_exit_area_requires_country() {
        for area in ["--exit-region", "--exit-city", "--exit-postal-code"] {
            assert!(
                parse_args(&["--proxy", "residential", area, "x"]).is_err(),
                "{area} was accepted without --exit-country"
            );
        }
    }

    #[test]
    fn test_only_one_exit_area() {
        for (first, second) in [
            ("--exit-region", "--exit-city"),
            ("--exit-region", "--exit-postal-code"),
            ("--exit-city", "--exit-postal-code"),
        ] {
            assert!(
                parse_args(&[
                    "--proxy",
                    "residential",
                    "--exit-country",
                    "US",
                    first,
                    "x",
                    second,
                    "y"
                ])
                .is_err(),
                "{first} and {second} were both accepted"
            );
        }
    }

    #[test]
    fn test_exit_location_requires_residential() {
        for proxy in [
            &[][..],
            &["--proxy", "datacenter"][..],
            &["--proxy", "https://user:pass@proxy.example.com:443"][..],
        ] {
            let args = parse_args(&[proxy, &["--exit-country", "GB"][..]].concat()).unwrap();
            assert!(
                matches!(
                    args.into_request(),
                    Err(BrowserTokensError::ExitLocationRequiresResidential)
                ),
                "{proxy:?} was accepted with --exit-country"
            );
        }
    }

    #[test]
    fn test_unknown_proxy_keyword_names_the_options() {
        let error = parse_args(&["--proxy", "residental"])
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("expected residential, datacenter or"),
            "{error}"
        );
    }

    #[test]
    fn test_summary_describes_managed_proxies() {
        let summary =
            |extra: &[&str]| summarize(&parse_args(extra).unwrap().into_request().unwrap());

        assert!(summary(&["--proxy", "datacenter"]).ends_with("proxy: datacenter"));
        assert!(
            summary(&["--proxy", "residential"]).ends_with("proxy: residential (default country)")
        );
        assert!(summary(&[
            "--proxy",
            "residential",
            "--exit-country",
            "GB",
            "--exit-city",
            "London"
        ])
        .ends_with("proxy: residential (GB, London)"));
    }
}
