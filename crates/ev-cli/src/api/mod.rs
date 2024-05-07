#[macro_export]
macro_rules! get_api_key {
    () => {
        match std::env::var("EV_API_KEY") {
            Ok(api_key) => api_key,
            Err(_) => {
                log::error!(
                    "No API Key given. Set the EV_API_KEY environment variable to authenticate."
                );
                return exitcode::NOUSER;
            }
        }
    };
}
