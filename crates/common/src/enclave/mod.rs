pub mod types;

pub fn get_runtime_version() -> String {
    env!("ENCLAVE_RUNTIME_VERSION").to_string()
}

pub fn get_runtime_major_version() -> String {
    env!("ENCLAVE_RUNTIME_VERSION")
        .split('.')
        .next()
        .expect("infallible")
        .to_string()
}
