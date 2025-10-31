use account_sdk::controller::Controller;
use account_sdk::errors::ControllerError;
use account_sdk::graphql::login::{
    begin_login, finalize_login, BeginLogin, BeginLoginResult, FinalizeLogin,
};
use account_sdk::graphql::run_query;
use account_sdk::signers::webauthn::sign_raw;
use account_sdk::signers::Signer;
use account_sdk::storage::selectors::Selectors;
use account_sdk::storage::{ControllerMetadata, StorageBackend};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

use serde_json::json;
use starknet_crypto::Felt;
use url::Url;
use wasm_bindgen::prelude::*;

use crate::account::{CartridgeAccount, CartridgeAccountWithMeta};
use crate::errors::JsControllerError;
use crate::types::owner::Owner;
use crate::types::session::AuthorizedSession;
use crate::types::signer::try_find_webauthn_signer_in_signer_signature;
use crate::types::JsFelt;

#[wasm_bindgen]
pub struct ControllerFactory;

#[wasm_bindgen]
impl ControllerFactory {
    #[allow(clippy::new_ret_no_self, clippy::too_many_arguments)]
    #[wasm_bindgen(js_name = fromStorage)]
    pub async fn from_storage(
        app_id: String,
        cartridge_api_url: String,
    ) -> crate::account::Result<Option<CartridgeAccountWithMeta>> {
        CartridgeAccount::from_storage(app_id, cartridge_api_url).await
    }

    #[allow(clippy::new_ret_no_self, clippy::too_many_arguments)]
    #[wasm_bindgen(js_name = login)]
    pub async fn login(
        app_id: String,
        username: String,
        class_hash: JsFelt,
        rpc_url: String,
        address: JsFelt,
        owner: Owner,
        cartridge_api_url: String,
        session_expires_at_s: u64,
        is_controller_registered: Option<bool>,
        create_wildcard_session: Option<bool>,
    ) -> crate::account::Result<LoginResult> {
        let class_hash_felt: Felt = class_hash.try_into()?;
        let rpc_url: Url = Url::parse(&rpc_url)?;
        let address_felt: Felt = address.try_into()?;
        let mut controller = Controller::new(
            app_id.clone(),
            username,
            class_hash_felt,
            rpc_url,
            owner.clone().into(),
            address_felt,
            None,
        )
        .await
        .map_err(|e| JsError::new(&e.to_string()))?;

        // Create wildcard session if requested (defaults to true for backward compatibility)
        let session_account = if create_wildcard_session.unwrap_or(true) {
            Some(
                controller
                    .create_wildcard_session(session_expires_at_s)
                    .await?,
            )
        } else {
            None
        };

        // Update WebAuthn signer if applicable
        if let Some(ref session) = session_account {
            if owner.is_signer() && owner.signer.as_ref().unwrap().is_webauthns() {
                let webauthn_signer = try_find_webauthn_signer_in_signer_signature(
                    owner.signer.unwrap().webauthns.unwrap(),
                    session.session_authorization.clone(),
                )?;
                controller.owner = account_sdk::signers::Owner::Signer(
                    account_sdk::signers::Signer::Webauthn(webauthn_signer.clone().try_into()?),
                );
            }
        }

        // Register session with Cartridge if controller is registered and session was created
        if let Some(ref session) = session_account {
            if is_controller_registered.unwrap_or(false) {
                let controller_response = controller
                    .register_session_with_cartridge(
                        &session.session,
                        &session.session_authorization,
                        cartridge_api_url.clone(),
                    )
                    .await;

                if let Err(e) = controller_response {
                    let address = controller.address;
                    let app_id = controller.app_id.clone();
                    let chain_id = controller.chain_id;

                    controller
                        .storage
                        .remove(&Selectors::session(&address, &app_id, &chain_id))
                        .map_err(|e| JsControllerError::from(ControllerError::StorageError(e)))?;

                    return Err(JsControllerError::from(e).into());
                }
            }
        }

        controller
            .storage
            .set_controller(
                app_id.as_str(),
                &controller.chain_id,
                address_felt,
                ControllerMetadata::from(&controller),
            )
            .expect("Should store controller");

        let account_with_meta = CartridgeAccountWithMeta::new(controller, cartridge_api_url);
        let authorized_session: Option<AuthorizedSession> = session_account.map(|s| s.into());
        Ok(LoginResult {
            account: account_with_meta,
            session: authorized_session,
        })
    }

    /// This should only be used with webauthn signers
    #[allow(clippy::new_ret_no_self, clippy::too_many_arguments)]
    #[wasm_bindgen(js_name = apiLogin)]
    pub async fn api_login(
        app_id: String,
        username: String,
        class_hash: JsFelt,
        rpc_url: String,
        address: JsFelt,
        owner: Owner,
        cartridge_api_url: String,
    ) -> crate::account::Result<CartridgeAccountWithMeta> {
        let query_ret = run_query::<BeginLogin>(
            begin_login::Variables {
                username: username.clone(),
            },
            cartridge_api_url.clone(),
        )
        .await?;

        let begin_login_result: BeginLoginResult = serde_json::from_value(query_ret.begin_login)
            .map_err(|e| ControllerError::ConversionError(e.to_string()))?;

        let mut controller = Controller::new(
            app_id.clone(),
            username,
            *class_hash.as_felt(),
            Url::parse(&rpc_url)?,
            owner.into(),
            *address.as_felt(),
            None,
        )
        .await
        .map_err(|e| JsError::new(&e.to_string()))?;

        let assertion = if let account_sdk::signers::Owner::Signer(Signer::Webauthns(signers)) =
            &controller.owner
        {
            let challenge_bytes = URL_SAFE_NO_PAD
                .decode(&begin_login_result.public_key.challenge)
                .map_err(|e| ControllerError::ConversionError(e.to_string()))?;

            let assertion = sign_raw(signers, challenge_bytes).await.map_err(|err| {
                ControllerError::SignError(account_sdk::signers::SignError::Device(err))
            })?;

            let signer_used = signers
                .iter()
                .find(|s| s.credential_id == assertion.raw_id)
                .ok_or(ControllerError::SignError(
                    account_sdk::signers::SignError::Device(
                        account_sdk::signers::DeviceError::BadAssertion(
                            "Couldn't find the signer of the assertion".to_string(),
                        ),
                    ),
                ))?;
            controller.owner =
                account_sdk::signers::Owner::Signer(Signer::Webauthn(signer_used.clone()));
            assertion
        } else {
            return Err(ControllerError::SignError(
                account_sdk::signers::SignError::AccountOwnerCannotSign,
            )
            .into());
        };

        let finalize_login_ret = run_query::<FinalizeLogin>(
            finalize_login::Variables {
                credentials: serde_json::to_string(&json!({
                    "id": assertion.id,
                    "type": assertion.type_,
                    "rawId": URL_SAFE_NO_PAD.encode(&assertion.raw_id),
                    "clientExtensionResults": assertion.extensions,
                    "response": {
                        "authenticatorData": URL_SAFE_NO_PAD.encode(
                            &assertion.response.authenticator_data
                        ),
                        "clientDataJSON": URL_SAFE_NO_PAD.encode(
                            &assertion.response.client_data_json
                        ),
                        "signature": URL_SAFE_NO_PAD.encode(
                            &assertion.response.signature
                        ),
                    },
                }))
                .map_err(|e| ControllerError::ConversionError(e.to_string()))?,
            },
            cartridge_api_url.clone(),
        )
        .await?;

        if finalize_login_ret.finalize_login.is_empty() {
            return Err(ControllerError::InvalidResponseData(
                "Empty signed token string on FinalizeLogin".to_string(),
            )
            .into());
        }

        controller
            .storage
            .set_controller(
                app_id.as_str(),
                &controller.chain_id,
                *address.as_felt(),
                ControllerMetadata::from(&controller),
            )
            .expect("Should store controller");

        Ok(CartridgeAccountWithMeta::new(controller, cartridge_api_url))
    }
}

#[wasm_bindgen]
pub struct LoginResult {
    account: CartridgeAccountWithMeta,
    session: Option<AuthorizedSession>,
}

#[wasm_bindgen]
impl LoginResult {
    #[wasm_bindgen(js_name = intoValues)]
    pub fn into_values(self) -> web_sys::js_sys::Array {
        let array = web_sys::js_sys::Array::new();
        array.push(&JsValue::from(self.account));
        if let Some(session) = self.session {
            array.push(&JsValue::from(session));
        } else {
            array.push(&JsValue::undefined());
        }
        array
    }
}
