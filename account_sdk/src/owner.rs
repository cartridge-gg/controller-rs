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
    pub async fn add_owner(
        &mut self,
        signer: Signer,
        #[allow(unused_variables)] cartridge_api_url: String,
    ) -> Result<(InvokeTransactionResult, Signer, Option<SignerInput>), ControllerError> {
        #[cfg(not(feature = "webauthn"))]
        let (signer, signer_input) = (signer, None);

        #[cfg(feature = "webauthn")]
        let (signer, signer_input) = match signer {
            Signer::Webauthn(signer) => {
                use crate::signers::webauthn::WebauthnSigner;
                use base64::engine::general_purpose::STANDARD_NO_PAD;
                use base64::Engine;

                let begin_registration =
                    crate::graphql::registration::begin_registration::begin_registration(
                        crate::graphql::registration::begin_registration::BeginRegistrationInput {
                            username: self.username.clone(),
                        },
                        cartridge_api_url,
                    )
                    .await?;

                let challenge_str = begin_registration.begin_registration["publicKey"]["challenge"]
                    .as_str()
                    .ok_or(ControllerError::InvalidResponseData(
                        "Missing challenge".to_string(),
                    ))?;
                let challenge_bytes = STANDARD_NO_PAD.decode(challenge_str).map_err(|e| {
                    ControllerError::InvalidResponseData(format!(
                        "Failed to decode challenge: {}",
                        e
                    ))
                })?;

                let (signer, register_ret) =
                    WebauthnSigner::register(signer.rp_id, self.username.clone(), &challenge_bytes)
                        .await
                        .map_err(|e| {
                            ControllerError::InvalidResponseData(format!(
                                "Failed to register: {}",
                                e
                            ))
                        })?;

                let signer_input = Some(SignerInput {
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
                });
                (Signer::Webauthn(signer), signer_input)
            }
            _ => (signer, None),
        };

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

        Ok((result, signer, signer_input))
    }

    pub async fn add_owner_with_cartridge(
        &mut self,
        signer: crate::graphql::owner::add_owner::SignerInput,
        signer_guid: Felt,
        cartridge_api_url: String,
    ) -> Result<(), ControllerError> {
        let input = crate::graphql::owner::AddOwnerInput {
            username: self.username.clone(),
            chain_id: parse_cairo_short_string(&self.chain_id).unwrap(),
            signer_guid,
            owner: signer,
        };

        let _ = crate::graphql::owner::add_owner(input, cartridge_api_url).await?;

        Ok(())
    }
}
