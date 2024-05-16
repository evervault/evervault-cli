use serde::{Deserialize, Serialize};

#[derive(Deserialize, Debug, Clone, Serialize)]
pub struct RelaySelections {
    r#type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    role: Option<String>,
    selector: String,
}

#[derive(Deserialize, Debug, Clone, Serialize)]
pub struct RelayAction {
    action: String,
    selections: Vec<RelaySelections>,
}

#[derive(Deserialize, Debug, Serialize)]
pub struct RelayResponse {
    method: String,
    path: String,
    relay: String,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct RelayRoutes {
    method: Option<String>,
    path: String,
    request: Option<Vec<RelayAction>>,
    response: Option<Vec<RelayAction>>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Relays {
    pub data: Vec<Relay>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Relay {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub destination_domain: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evervault_domain: Option<String>,
    pub encrypt_empty_strings: bool,
    pub authentication: Option<String>,
    pub routes: Vec<RelayRoutes>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateRelay {
    pub encrypt_empty_strings: bool,
    pub authentication: Option<String>,
    pub routes: Vec<RelayRoutes>,
}
