use account_sdk::errors::ControllerError;
use starknet_crypto::Felt;
use wasm_bindgen::{prelude::wasm_bindgen, JsError};

use crate::{
    types::{session::JsSubscribeSessionResult, signer::Signer, JsFelt},
    Result,
};

/// Subscribes to the creation of a session for a given controller, session_key_guid and cartridge api url.
/// The goal of this function is to know from any place when the register session flow has been completed, and to
/// get the authorization.
#[wasm_bindgen(js_name = subscribeCreateSession)]
pub async fn subscribe_create_session(
    session_key_guid: JsFelt,
    cartridge_api_url: String,
) -> Result<JsSubscribeSessionResult> {
    account_sdk::session::subscribe_create_session(*session_key_guid.as_felt(), cartridge_api_url)
        .await
        .map_err(Into::<JsError>::into)?
        .subscribe_create_session
        .ok_or(ControllerError::InvalidResponseData("Missing data".to_string()).into())
        .map(JsSubscribeSessionResult)
}

#[wasm_bindgen(js_name = signerToGuid)]
pub fn signer_to_guid(signer: Signer) -> JsFelt {
    let signer: account_sdk::signers::Signer = signer.try_into().unwrap();
    let felt: Felt = signer.into();
    felt.into()
}
