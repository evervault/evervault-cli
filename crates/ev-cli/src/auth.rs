pub fn get_auth() -> (String, String) {
    match (std::env::var("EV_APP_UUID"), std::env::var("EV_API_KEY")) {
        (Ok(app_uuid), Ok(api_key)) => (app_uuid, api_key),
        (Err(_), Err(_)) => {
            log::error!(
                "No App UUID or API key found. Make sure you have correctly set the \
                     EV_APP_UUID and EV_API_KEY environment variables. See \
                     https://docs.evervault.com/sdks/cli for more information."
            );
            std::process::exit(crate::errors::NOUSER);
        }
        (_, Err(_)) => {
            log::error!(
                "No API Key found. Make sure you have correctly set the EV_API_KEY \
                     environment variable. See https://docs.evervault.com/sdks/cli for more \
                     information."
            );
            std::process::exit(crate::errors::NOUSER);
        }
        (Err(_), _) => {
            log::error!(
                "No App UUID found. Make sure you have correctly set the EV_APP_UUID \
                     environment variable. See https://docs.evervault.com/sdks/cli for more \
                     information."
            );
            std::process::exit(crate::errors::NOUSER);
        }
    }
}
