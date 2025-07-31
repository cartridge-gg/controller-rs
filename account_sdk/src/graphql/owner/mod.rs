use std::str::FromStr;

use crate::api::Client;
use crate::errors::ControllerError;
use crate::signers::eip191::Eip191Signer;
use crate::signers::Signer;
use anyhow::Result;
use graphql_client::GraphQLQuery;
use starknet::core::types::EthAddress;
use starknet_crypto::Felt;

#[allow(clippy::upper_case_acronyms)]
type JSON = String;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "schema.json",
    query_path = "src/graphql/owner/add-owner.graphql",
    variables_derives = "Debug, Clone, PartialEq, Eq, Deserialize",
    response_derives = "Debug, Clone, PartialEq, Eq, Deserialize"
)]
pub struct AddOwner;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "schema.json",
    query_path = "src/graphql/owner/remove-owner.graphql",
    variables_derives = "Debug, Clone, PartialEq, Eq, Deserialize",
    response_derives = "Debug, Clone, PartialEq, Eq, Deserialize"
)]
pub struct RemoveOwner;

pub struct AddOwnerInput {
    pub username: String,
    pub chain_id: String,
    pub signer_guid: Felt,
    pub owner: add_owner::SignerInput,
}

pub struct RemoveOwnerInput {
    pub username: String,
    pub chain_id: String,
    pub signer_guid: Felt,
    pub owner: remove_owner::SignerInput,
}

pub async fn add_owner(
    input: AddOwnerInput,
    cartridge_api_url: String,
) -> Result<add_owner::ResponseData, ControllerError> {
    let client = Client::new(cartridge_api_url);

    let request_body = AddOwner::build_query(add_owner::Variables {
        username: input.username,
        chain_id: input.chain_id,
        signer_guid: input.signer_guid,
        owner: input.owner,
    });

    client.query(&request_body).await
}

pub async fn remove_owner(
    input: RemoveOwnerInput,
    cartridge_api_url: String,
) -> Result<remove_owner::ResponseData, ControllerError> {
    let client = Client::new(cartridge_api_url);

    let request_body = RemoveOwner::build_query(remove_owner::Variables {
        username: input.username,
        chain_id: input.chain_id,
        signer_guid: input.signer_guid,
        owner: input.owner,
    });

    client.query(&request_body).await
}

impl TryFrom<remove_owner::SignerInput> for Signer {
    type Error = ControllerError;

    fn try_from(value: remove_owner::SignerInput) -> Result<Self, ControllerError> {
        match value.type_ {
            remove_owner::SignerType::eip191 => {
                let eth_signer: serde_json::Value = serde_json::from_str(&value.credential)
                    .map_err(|e| ControllerError::InvalidOwner(e.to_string()))?;
                let address = eth_signer
                    .get("ethAddress")
                    .unwrap()
                    .as_str()
                    .ok_or_else(|| {
                        ControllerError::InvalidOwner("eth address is not a string".to_string())
                    })?;
                let address = EthAddress::from_str(address)
                    .map_err(|e| ControllerError::InvalidOwner(e.to_string()))?;
                #[cfg(not(target_arch = "wasm32"))]
                {
                    let signing_key =
                        alloy_signer::k256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng);
                    Ok(Self::Eip191(Eip191Signer {
                        address,
                        signing_key,
                    }))
                }
                #[cfg(target_arch = "wasm32")]
                Ok(Self::Eip191(Eip191Signer { address }))
            }
            remove_owner::SignerType::webauthn => {
                #[cfg(not(feature = "webauthn"))]
                panic!("webauthn is not enabled");

                #[cfg(feature = "webauthn")]
                {
                    use base64::Engine;
                    use coset::{CborSerializable, CoseKey};

                    let webauthn_signer: serde_json::Value =
                        serde_json::from_str(&value.credential)
                            .map_err(|e| ControllerError::InvalidOwner(e.to_string()))?;
                    let credential_id =
                        webauthn_signer.get("id").unwrap().as_str().ok_or_else(|| {
                            ControllerError::InvalidOwner(
                                "credential id is not a string".to_string(),
                            )
                        })?;
                    let public_key_base_64 = webauthn_signer
                        .get("publicKey")
                        .unwrap()
                        .as_str()
                        .ok_or_else(|| {
                            ControllerError::InvalidOwner("public key is not a string".to_string())
                        })?;
                    let cose_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
                        .decode(public_key_base_64)
                        .map_err(|e| {
                            ControllerError::InvalidOwner(format!(
                                "Failed to decode public key base64: {e}"
                            ))
                        })?;
                    let pub_key = CoseKey::from_slice(&cose_bytes).map_err(|e| {
                        ControllerError::InvalidOwner(format!("Failed to parse COSE key: {e}"))
                    })?;
                    let rp_id = webauthn_signer
                        .get("rpId")
                        .unwrap()
                        .as_str()
                        .ok_or_else(|| {
                            ControllerError::InvalidOwner("rpId is not a string".to_string())
                        })?;
                    let credential_id_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
                        .decode(credential_id)
                        .map_err(|e| {
                            ControllerError::InvalidResponseData(format!(
                                "Failed to decode credential ID base64: {e}"
                            ))
                        })?;
                    let webauthn_signer = crate::signers::webauthn::WebauthnSigner::new(
                        rp_id.to_string(),
                        credential_id_bytes.into(),
                        pub_key,
                    );
                    Ok(Self::Webauthn(webauthn_signer))
                }
            }
            remove_owner::SignerType::starknet => todo!(),
            remove_owner::SignerType::siws => todo!(),
            remove_owner::SignerType::starknet_account => todo!(),
            remove_owner::SignerType::secp256k1 => todo!(),
            remove_owner::SignerType::secp256r1 => todo!(),
            remove_owner::SignerType::Other(_) => todo!(),
        }
    }
}

impl From<String> for remove_owner::SignerType {
    fn from(value: String) -> Self {
        match value.as_str() {
            "eip191" => Self::eip191,
            "webauthn" => Self::webauthn,
            "starknet" => Self::starknet,
            "siws" => Self::siws,
            "starknet_account" => Self::starknet_account,
            "secp256k1" => Self::secp256k1,
            "secp256r1" => Self::secp256r1,
            "other" => Self::Other(value),
            _ => todo!(),
        }
    }
}

impl From<String> for add_owner::SignerType {
    fn from(value: String) -> Self {
        match value.as_str() {
            "eip191" => Self::eip191,
            "webauthn" => Self::webauthn,
            "starknet" => Self::starknet,
            "siws" => Self::siws,
            "starknet_account" => Self::starknet_account,
            "secp256k1" => Self::secp256k1,
            "secp256r1" => Self::secp256r1,
            "other" => Self::Other(value),
            _ => todo!(),
        }
    }
}
