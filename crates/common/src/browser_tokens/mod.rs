use serde::{Deserialize, Serialize};
use std::num::NonZeroU64;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct BrowserTokenData {
    pub category: String,
    pub id: String,
    pub value: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct BrowserTokenPermission {
    pub action: String,
    pub target: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ProxyScheme {
    Http,
    Https,
}

/// Egress proxy configuration, tagged by `type`. Only custom proxies are supported by the API today.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum ProxySettings {
    Custom(CustomProxy),
}

/// A proxy run by the customer
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct CustomProxy {
    pub scheme: ProxyScheme,
    pub username: String,
    pub password: String,
    pub hostname: String,
    pub port: u16,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CreateBrowserTokens {
    pub data: Vec<BrowserTokenData>,
    pub permissions: Vec<BrowserTokenPermission>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl: Option<NonZeroU64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxy_settings: Option<ProxySettings>,
}
