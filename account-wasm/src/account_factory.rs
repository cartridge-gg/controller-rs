use account_sdk::controller::Controller;
use account_sdk::errors::ControllerError;
use account_sdk::storage::selectors::Selectors;
use account_sdk::storage::{ControllerMetadata, StorageBackend};

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
pub struct ControllerBuilderFactory;

#[wasm_bindgen]
impl ControllerBuilderFactory {
    pub fn from_storage(
        app_id: String,
        cartridge_api_url: String,
    ) -> crate::account::Result<Option<CartridgeAccountWithMeta>> {
        CartridgeAccount::from_storage(app_id, cartridge_api_url)
    }

    #[allow(clippy::new_ret_no_self, clippy::too_many_arguments)]
    #[wasm_bindgen(js_name = login)]
    pub async fn login(
        app_id: String,
        username: String,
        class_hash: JsFelt,
        rpc_url: String,
        chain_id: JsFelt,
        address: JsFelt,
        owner: Owner,
        cartridge_api_url: String,
        session_expires_at_s: u64,
        is_controller_registered: Option<bool>,
    ) -> crate::account::Result<LoginResult> {
        let class_hash_felt: Felt = class_hash.try_into()?;
        let chain_id_felt: Felt = chain_id.try_into()?;
        let rpc_url: Url = Url::parse(&rpc_url)?;
        let address_felt: Felt = address.try_into()?;
        let mut controller = Controller::new(
            app_id.clone(),
            username,
            class_hash_felt,
            rpc_url,
            owner.clone().into(),
            address_felt,
            chain_id_felt,
        );
        let session_account = controller
            .create_wildcard_session(session_expires_at_s)
            .await?;

        if owner.is_signer() && owner.signer.as_ref().unwrap().is_webauthns() {
            let webauthn_signer = try_find_webauthn_signer_in_signer_signature(
                owner.signer.unwrap().webauthns.unwrap(),
                session_account.session_authorization.clone(),
            )?;
            controller.owner = account_sdk::signers::Owner::Signer(
                account_sdk::signers::Signer::Webauthn(webauthn_signer.clone().try_into()?),
            );
        }

        if is_controller_registered.unwrap_or(false) {
            let controller_response = controller
                .register_session_with_cartridge(
                    &session_account.session,
                    &session_account.session_authorization,
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

        controller
            .storage
            .set_controller(
                app_id.as_str(),
                &chain_id_felt,
                address_felt,
                ControllerMetadata::from(&controller),
            )
            .expect("Should store controller");

        let account_with_meta = CartridgeAccountWithMeta::new(controller, cartridge_api_url);
        let authorized_session: AuthorizedSession = session_account.into();
        Ok(LoginResult {
            account: account_with_meta,
            session: authorized_session,
        })
    }
}

#[wasm_bindgen]
pub struct LoginResult {
    account: CartridgeAccountWithMeta,
    session: AuthorizedSession,
}

#[wasm_bindgen]
impl LoginResult {
    #[wasm_bindgen(js_name = intoValues)]
    pub fn into_values(self) -> web_sys::js_sys::Array {
        let array = web_sys::js_sys::Array::new();
        array.push(&JsValue::from(self.account));
        array.push(&JsValue::from(self.session));
        array
    }
}
