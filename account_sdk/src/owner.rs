use serde::{Deserialize, Serialize};
use starknet::core::{types::InvokeTransactionResult, utils::parse_cairo_short_string};
use starknet_crypto::Felt;

use crate::{
    controller::Controller,
    errors::ControllerError,
    execute_from_outside::FeeSource,
    graphql::owner::add_owner::SignerInput,
    signers::{NewOwnerSigner, Owner, Signer},
};

impl Controller {
    #[cfg(feature = "webauthn")]
    #[cfg(target_arch = "wasm32")]
    pub async fn do_passkey_creation_popup_flow(
        &mut self,
        rp_id: String,
    ) -> Result<(Signer, SignerInput), ControllerError> {
        use base64::Engine;
        use wasm_bindgen::prelude::*;
        use wasm_bindgen::JsCast;

        use crate::signers::webauthn::pub_key_to_cose_key;
        use crate::signers::webauthn::WebauthnSigner;

        let window = web_sys::window().ok_or_else(|| {
            ControllerError::InvalidResponseData("Couldn't find window".to_string())
        })?;

        let params = vec![
            ("name", urlencoding::encode(&self.username).to_string()),
            ("appId", urlencoding::encode(&self.app_id).to_string()),
            ("action", "add-signer".to_string()),
        ];

        let query_string = params
            .into_iter()
            .map(|(key, value)| format!("{}={}", key, value))
            .collect::<Vec<_>>()
            .join("&");

        let url = if rp_id.contains("localhost") {
            format!("http://{rp_id}:3001/authenticate?{query_string}")
        } else {
            format!("https://{rp_id}/authenticate?{query_string}")
        };

        let popup = window
            .open_with_url_and_target_and_features(&url, "_blank", "")
            .map_err(|e| {
                ControllerError::InvalidResponseData(format!("Failed to open popup: {e:?}"))
            })?;

        if popup.is_none() {
            return Err(ControllerError::InvalidResponseData(
                "Failed to open popup".to_string(),
            ));
        }

        let _ = popup.unwrap();

        let (tx, rx) = futures::channel::oneshot::channel();
        let tx = std::rc::Rc::new(std::cell::RefCell::new(Some(tx)));

        let rp_id_clone = rp_id.clone();
        let closure: Closure<dyn Fn(web_sys::MessageEvent)> =
            Closure::new(move |event: web_sys::MessageEvent| {
                let data = event.data();
                let origin = event.origin();
                if !origin.contains(rp_id_clone.as_str()) {
                    return;
                }

                if let Ok(message_event) = serde_wasm_bindgen::from_value::<WasmMessageEvent>(data)
                {
                    if message_event.target != "passkey-creation-popup" {
                        return;
                    }

                    if let Some(tx) = tx.borrow_mut().take() {
                        let _ = tx.send(message_event.payload);
                    }
                }
            });

        window
            .add_event_listener_with_callback("message", closure.as_ref().unchecked_ref())
            .map_err(|e| {
                ControllerError::InvalidResponseData(format!("Failed to add event listener: {e:?}"))
            })?;

        let result = rx.await.map_err(|_| {
            ControllerError::InvalidResponseData(
                "Failed to receive passkey creation result".to_string(),
            )
        })?;

        window
            .remove_event_listener_with_callback("message", closure.as_ref().unchecked_ref())
            .map_err(|e| {
                ControllerError::InvalidResponseData(format!(
                    "Failed to remove event listener: {e:?}"
                ))
            })?;

        closure.forget();

        let credential: serde_json::Value =
            serde_json::from_str(&result.credential).map_err(|e| {
                ControllerError::InvalidResponseData(format!(
                    "Failed to parse credential JSON: {e}"
                ))
            })?;

        let public_key_hex = credential["publicKey"].as_str().ok_or_else(|| {
            ControllerError::InvalidResponseData("Couldn't find public key".to_string())
        })?;

        let public_key = hex::decode(public_key_hex)
            .map_err(|e| {
                ControllerError::InvalidResponseData(format!(
                    "Failed to decode public key hex: {e}"
                ))
            })?
            .try_into()
            .map_err(|_| {
                ControllerError::InvalidResponseData("Public key has invalid length".to_string())
            })?;

        let cose_key = pub_key_to_cose_key(public_key);
        let credential_id_str = credential["id"].as_str().ok_or_else(|| {
            ControllerError::InvalidResponseData("Couldn't find credential ID".to_string())
        })?;

        let credential_id_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(credential_id_str)
            .map_err(|e| {
                ControllerError::InvalidResponseData(format!(
                    "Failed to decode credential ID base64: {e}"
                ))
            })?;

        let webauthn_signer = WebauthnSigner::new(rp_id, credential_id_bytes.into(), cose_key);

        Ok((Signer::Webauthn(webauthn_signer), result))
    }

    #[cfg(feature = "webauthn")]
    pub async fn create_passkey(
        &mut self,
        rp_id: String,
        #[allow(unused)] allow_popup: bool,
    ) -> Result<(Signer, SignerInput), ControllerError> {
        use crate::signers::generate_add_owner_tx_hash;
        use crate::signers::webauthn::WebauthnSigner;

        #[cfg(target_arch = "wasm32")]
        {
            let navigator = web_sys::window()
                .ok_or_else(|| {
                    ControllerError::InvalidResponseData("Couldn't find window".to_string())
                })?
                .navigator();
            let user_agent = navigator.user_agent().map_err(|e| {
                ControllerError::InvalidResponseData(format!("Failed to get user agent: {:?}", e))
            })?;
            let is_safari = !user_agent.to_lowercase().contains("chrome")
                && !user_agent.to_lowercase().contains("android")
                && user_agent.to_lowercase().contains("safari");
            let is_safari = true;

            if is_safari && allow_popup {
                return self.do_passkey_creation_popup_flow(rp_id).await;
            }
        }

        let challenge = generate_add_owner_tx_hash(&self.chain_id, &self.address).to_bytes_be();

        let ret = WebauthnSigner::register(rp_id.clone(), self.username.clone(), &challenge)
            .await
            .map_err(|e| {
                ControllerError::InvalidResponseData(format!("Failed to register passkey: {e}"))
            });

        #[cfg(target_arch = "wasm32")]
        if let Err(e) = ret {
            let error_needs_popup = e
                .to_string()
                .contains("Invalid 'sameOriginWithAncestors' value")
                || e.to_string().contains("document which is same-origin");

            if allow_popup && error_needs_popup {
                return self.do_passkey_creation_popup_flow(rp_id).await;
            }

            return Err(e);
        };

        let (signer, register_ret) = ret.unwrap();
        let signer_input = SignerInput {
            type_: crate::graphql::owner::add_owner::SignerType::webauthn,
            credential: serde_json::json!({
                "id": signer.credential_id,
                "publicKey": hex::encode(signer.pub_key_bytes().map_err(|e| {
                    ControllerError::InvalidResponseData(format!("Failed to get public key: {e}"))
                })?),
                "rawId": register_ret.raw_id,
                "type": register_ret.type_,
                "response": {
                    "clientDataJSON": register_ret.response.client_data_json,
                    "attestationObject": register_ret.response.attestation_object,
                }
            })
            .to_string(),
        };
        Ok((Signer::Webauthn(signer), signer_input))
    }

    pub async fn add_owner(
        &mut self,
        signer: Signer,
    ) -> Result<InvokeTransactionResult, ControllerError> {
        let new_owner = Owner::Signer(signer.clone());
        let signature = new_owner
            .sign_new_owner(&self.chain_id, &self.address)
            .await?;

        let call = self
            .contract()
            .add_owner_getcall(&signer.clone().into(), &signature);

        let result = self
            .execute_from_outside_v3(vec![call], Some(FeeSource::Paymaster))
            .await?;

        Ok(result)
    }

    pub async fn add_owner_with_cartridge(
        &mut self,
        signer: crate::graphql::owner::add_owner::SignerInput,
        signer_guid: Felt,
        cartridge_api_url: String,
    ) -> Result<(), ControllerError> {
        let input = crate::graphql::owner::AddOwnerInput {
            username: self.username.clone(),
            chain_id: parse_cairo_short_string(&self.chain_id).map_err(|e| {
                ControllerError::InvalidResponseData(format!("Failed to parse chain ID: {e}"))
            })?,
            signer_guid,
            owner: signer,
        };

        let _ = crate::graphql::owner::add_owner(input, cartridge_api_url).await?;

        Ok(())
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct WasmMessageEvent {
    target: String,
    payload: SignerInput,
}
