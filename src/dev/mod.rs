use rust_crypto::backend::{CryptoClient as _, Datatype};
use serde_json::Value;
use tide::http::mime;
/// Create a local mock crypto API for development
use tide::Request;

type CryptoClient = rust_crypto::backend::ies_secp256r1_openssl::Client;
fn create_key_pair() -> CryptoClient {
    let keypair = rust_crypto::backend::ies_secp256r1_openssl::EcKey::generate_key_pair().unwrap();
    rust_crypto::backend::ies_secp256r1_openssl::Client::new(keypair)
}

pub async fn run_mock_crypto_api(port: u16) {
    let addr = format!("127.0.0.1:{port}");
    let crypto_api = get_server();
    println!("Starting mock crypto api on port: {port}");
    crypto_api
        .listen(&addr)
        .await
        .expect("Could not start crypto api");
}

fn get_server() -> tide::Server<rust_crypto::backend::ies_secp256r1_openssl::Client> {
    let session_key_pair = create_key_pair();
    let mut app = tide::with_state(session_key_pair);
    app.at("/encrypt").post(encryption_handler);
    app.at("/decrypt").post(decryption_handler);
    app.at("/attestation-doc").post(attestation_handler);
    app
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
        let to_encrypt = convert_value_to_string(&value);
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
        let to_decrypt = convert_value_to_string(&value); // convert from serde value string to std string
        println!("Going to decrypt: {to_decrypt:?}");
        if let Ok(decrypted) = client.decrypt(to_decrypt) {
            println!("Decrypted: {decrypted:?}");
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

async fn encryption_handler(mut request: Request<CryptoClient>) -> tide::Result {
    let client = request.state().clone();
    if let Ok(mut payload) = request.body_json().await {
        encrypt(&client, &mut payload);
        let res = tide::Response::builder(200)
            .content_type(mime::JSON)
            .body(payload)
            .build();
        Ok(res)
    } else {
        let res = tide::Response::builder(400)
            .content_type(mime::JSON)
            .body(
                serde_json::json!({ "message": "Failed to parse encrypt request payload as JSON" }),
            )
            .build();
        Ok(res)
    }
}

async fn decryption_handler(mut request: Request<CryptoClient>) -> tide::Result {
    let client = request.state().clone();
    if let Ok(mut payload) = request.body_json().await {
        decrypt(&client, &mut payload);
        let res = tide::Response::builder(200)
            .content_type(mime::JSON)
            .body(payload)
            .build();
        Ok(res)
    } else {
        let res = tide::Response::builder(400)
            .content_type(mime::JSON)
            .body(
                serde_json::json!({ "message": "Failed to parse decrypt request payload as JSON" }),
            )
            .build();
        Ok(res)
    }
}

async fn attestation_handler(_: Request<CryptoClient>) -> tide::Result {
    let pcr0 = std::env::var("PCR0").expect("No key given");
    let pcr1 = std::env::var("PCR1").expect("No cert given");
    let pcr2 = std::env::var("PCR2").expect("No key given");
    let pcr8 = std::env::var("PCR8").expect("No cert given");
    let ad = serde_json::json!({
      "Measurements": {
        "PCR0": pcr0,
        "PCR1": pcr1,
        "PCR2": pcr2,
        "PCR8": pcr8
      }
    });
    match serde_cbor::to_vec(&ad) {
        Ok(attestation_doc) => {
            let res = tide::Response::builder(200).body(attestation_doc).build();
            Ok(res)
        }
        Err(_) => {
            let res = tide::Response::builder(500)
        .content_type(mime::JSON)
        .body(serde_json::json!({ "message": "An internal error occurred while generating a mock attestation document" }))
        .build();
            Ok(res)
        }
    }
}
