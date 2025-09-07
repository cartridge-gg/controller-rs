use account_sdk::{
    errors::ControllerError,
    graphql::{
        run_query,
        session::{subscribe_create_session, SubscribeCreateSession},
    },
};
use wasm_bindgen::{prelude::wasm_bindgen, JsError};

use crate::types::{session::JsSubscribeSessionResult, JsFelt};

pub type Result<T> = std::result::Result<T, JsError>;

pub fn set_panic_hook() {
    // When the `console_error_panic_hook` feature is enabled, we can call the
    // `set_panic_hook` function at least once during initialization, and then
    // we will get better error messages if our code ever panics.
    //
    // For more details see
    // https://github.com/rustwasm/console_error_panic_hook#readme
    #[cfg(feature = "console_error_panic_hook")]
    console_error_panic_hook::set_once();
}

/// Subscribes to the creation of a session for a given controller, session_key_guid and cartridge api url.
/// The goal of this function is to know from any place when the register session flow has been completed, and to
/// get the authorization.
#[wasm_bindgen(js_name = subscribeCreateSession)]
pub async fn subscribe_create_session(
    app_id: String,
    session_key_guid: JsFelt,
    cartridge_api_url: String,
) -> Result<JsSubscribeSessionResult> {
    web_sys::console::log_1(&format!("Hello world").into());
    run_query::<SubscribeCreateSession>(
        subscribe_create_session::Variables {
            app_id,
            session_key_guid: *session_key_guid.as_felt(),
        },
        cartridge_api_url,
    )
    .await
    .map_err(Into::<JsError>::into)?
    .subscribe_create_session
    .ok_or(ControllerError::InvalidResponseData("Missing data".to_string()).into())
    .map(JsSubscribeSessionResult)
}
