use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router, Server};
use rust_crypto::backend::{CryptoClient as _, Datatype};
use serde_json::Value;

type CryptoClient = rust_crypto::backend::ies_secp256r1_openssl::Client;
fn create_key_pair() -> CryptoClient {
    let keypair = rust_crypto::backend::ies_secp256r1_openssl::EcKey::generate_key_pair().unwrap();
    rust_crypto::backend::ies_secp256r1_openssl::Client::new(keypair)
}

pub async fn run_mock_crypto_api(port: u16) {
    let addr = format!("127.0.0.1:{port}");
    let session_key_pair = create_key_pair();
    let router = Router::new()
        .route(
            "/encrypt",
            post({
                let client = session_key_pair.clone();
                move |body| encryption_handler(body, client)
            }),
        )
        .route(
            "/decrypt",
            post({
                let client = session_key_pair.clone();
                move |body| decryption_handler(body, client)
            }),
        )
        .route("/attestation-doc", post(attestation_handler));

    println!("Starting mock crypto api on port: {port}");
    Server::bind(&addr.parse().unwrap())
        .serve(router.into_make_service())
        .await
        .expect("Could not start crypto api");
}

fn encrypt(client: &CryptoClient, value: &mut Value) {
    if value.is_object() {
        value
            .as_object_mut()
            .unwrap()
            .values_mut()
            .for_each(|val| encrypt(client, val));
    } else if value.is_array() {
        value
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .for_each(|val| encrypt(client, val));
    } else {
        let mut val = value.clone();
        let to_encrypt = convert_value_to_string(value);
        let encrypted_data_result = client
            .encrypt(to_encrypt, Datatype::try_from(&mut val).unwrap(), true)
            .unwrap();
        *value = Value::String(encrypted_data_result);
    }
}

fn decrypt(client: &CryptoClient, value: &mut Value) {
    if value.is_object() {
        value
            .as_object_mut()
            .unwrap()
            .values_mut()
            .for_each(|val| decrypt(client, val));
    } else if value.is_array() {
        value
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .for_each(|val| decrypt(client, val));
    } else if value.is_string() {
        // all encrypted values are strings
        let to_decrypt = convert_value_to_string(value); // convert from serde value string to std string
        if let Ok(decrypted) = client.decrypt(to_decrypt) {
            *value = decrypted;
        }
    }
}

fn convert_value_to_string(value: &Value) -> String {
    value
        .as_str()
        .map(|val| val.to_string())
        .unwrap_or_else(|| serde_json::to_string(&value).unwrap())
}

async fn encryption_handler(Json(mut payload): Json<Value>, client: CryptoClient) -> Json<Value> {
    encrypt(&client, &mut payload);
    Json(payload)
}

async fn decryption_handler(Json(mut payload): Json<Value>, client: CryptoClient) -> Json<Value> {
    decrypt(&client, &mut payload);
    Json(payload)
}

fn default_pcr_measure() -> String {
    "000".to_string()
}

async fn attestation_handler() -> Response {
    let pcr0 = std::env::var("PCR0")
        .ok()
        .unwrap_or_else(default_pcr_measure);
    let pcr1 = std::env::var("PCR1")
        .ok()
        .unwrap_or_else(default_pcr_measure);
    let pcr2 = std::env::var("PCR2")
        .ok()
        .unwrap_or_else(default_pcr_measure);
    let pcr8 = std::env::var("PCR8")
        .ok()
        .unwrap_or_else(default_pcr_measure);
    let ad = serde_json::json!({
      "Measurements": {
        "PCR0": pcr0,
        "PCR1": pcr1,
        "PCR2": pcr2,
        "PCR8": pcr8
      }
    });
    match serde_cbor::to_vec(&ad) {
        Ok(attestation_doc) => attestation_doc.into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}
