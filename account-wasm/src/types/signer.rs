use std::str::FromStr;

use account_sdk::signers::webauthn::CredentialID;
use base64::engine::general_purpose;
use base64::Engine;
use coset::CborSerializable;
use coset::CoseKey;
use serde::{Deserialize, Serialize};
use starknet::core::types::EthAddress;
use starknet::signers::SigningKey;
use tsify_next::Tsify;
use wasm_bindgen::prelude::*;

use super::EncodingError;
use super::JsFelt;

#[allow(non_snake_case)]
#[derive(Tsify, Serialize, Deserialize, Debug, Clone)]
#[tsify(into_wasm_abi, from_wasm_abi)]
#[serde(rename_all = "camelCase")]
pub struct WebauthnSigner {
    pub rp_id: String,
    pub credential_id: String,
    pub public_key: String,
}

#[allow(non_snake_case)]
#[derive(Tsify, Serialize, Deserialize, Debug, Clone)]
#[tsify(into_wasm_abi, from_wasm_abi)]
#[serde(rename_all = "camelCase")]
pub struct StarknetSigner {
    pub private_key: JsFelt,
}

#[allow(non_snake_case)]
#[derive(Tsify, Serialize, Deserialize, Debug, Clone)]
#[tsify(into_wasm_abi, from_wasm_abi)]
#[serde(rename_all = "camelCase")]
pub struct Eip191Signer {
    pub address: String,
}

#[allow(non_snake_case)]
#[derive(Tsify, Serialize, Deserialize, Debug, Clone)]
#[tsify(into_wasm_abi, from_wasm_abi)]
#[serde(rename_all = "camelCase")]
pub struct Signer {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub webauthns: Option<Vec<WebauthnSigner>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub webauthn: Option<WebauthnSigner>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub starknet: Option<StarknetSigner>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eip191: Option<Eip191Signer>,
}

impl TryFrom<WebauthnSigner> for account_sdk::signers::webauthn::WebauthnSigner {
    type Error = EncodingError;

    fn try_from(webauthn: WebauthnSigner) -> Result<Self, Self::Error> {
        let credential_id_bytes = general_purpose::URL_SAFE_NO_PAD
            .decode(webauthn.credential_id)
            .map_err(|_| {
                EncodingError::Serialization(serde_wasm_bindgen::Error::new(
                    "Invalid credential_id",
                ))
            })?;
        let credential_id = CredentialID::from(credential_id_bytes);
        let cose_bytes = general_purpose::URL_SAFE_NO_PAD
            .decode(webauthn.public_key)
            .map_err(|_| {
                EncodingError::Serialization(serde_wasm_bindgen::Error::new("Invalid public_key"))
            })?;
        let cose = CoseKey::from_slice(&cose_bytes).map_err(|_| {
            EncodingError::Serialization(serde_wasm_bindgen::Error::new("Invalid CoseKey"))
        })?;

        Ok(Self::new(webauthn.rp_id, credential_id, cose))
    }
}

impl TryFrom<StarknetSigner> for SigningKey {
    type Error = EncodingError;

    fn try_from(starknet: StarknetSigner) -> Result<Self, Self::Error> {
        Ok(SigningKey::from_secret_scalar(
            starknet.private_key.try_into()?,
        ))
    }
}

impl TryFrom<Eip191Signer> for account_sdk::signers::eip191::Eip191Signer {
    type Error = EncodingError;

    fn try_from(eip191: Eip191Signer) -> Result<Self, Self::Error> {
        Ok(Self {
            address: EthAddress::from_str(&eip191.address).unwrap(),
            #[cfg(not(target_arch = "wasm32"))]
            signing_key: alloy_signer::k256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng),
        })
    }
}

impl TryFrom<Signer> for account_sdk::signers::Signer {
    type Error = EncodingError;

    fn try_from(signer: Signer) -> Result<Self, Self::Error> {
        if let Some(webauthn) = signer.webauthn {
            Ok(Self::Webauthn(webauthn.try_into()?))
        } else if let Some(starknet) = signer.starknet {
            Ok(Self::Starknet(starknet.try_into()?))
        } else if let Some(eip191) = signer.eip191 {
            Ok(Self::Eip191(eip191.try_into()?))
        } else {
            Err(EncodingError::Serialization(
                serde_wasm_bindgen::Error::new("Missing signer data"),
            ))
        }
    }
}

impl From<account_sdk::signers::Signer> for Signer {
    fn from(signer: account_sdk::signers::Signer) -> Self {
        match signer {
            account_sdk::signers::Signer::Webauthn(s) => Self {
                webauthns: None,
                webauthn: Some(s.into()),
                starknet: None,
                eip191: None,
            },
            account_sdk::signers::Signer::Starknet(s) => Self {
                webauthns: None,
                webauthn: None,
                starknet: Some(s.into()),
                eip191: None,
            },
            account_sdk::signers::Signer::Eip191(s) => Self {
                webauthns: None,
                webauthn: None,
                starknet: None,
                eip191: Some(s.into()),
            },
            account_sdk::signers::Signer::Webauthns(s) => Self {
                webauthns: Some(s.into_iter().map(Into::into).collect()),
                webauthn: None,
                starknet: None,
                eip191: None,
            },
        }
    }
}

impl From<account_sdk::signers::webauthn::WebauthnSigner> for WebauthnSigner {
    fn from(signer: account_sdk::signers::webauthn::WebauthnSigner) -> Self {
        Self {
            rp_id: signer.rp_id,
            credential_id: general_purpose::URL_SAFE_NO_PAD.encode(signer.credential_id),
            public_key: general_purpose::URL_SAFE_NO_PAD.encode(
                signer
                    .pub_key
                    .to_vec()
                    .expect("Failed to serialize CoseKey"),
            ),
        }
    }
}

impl From<SigningKey> for StarknetSigner {
    fn from(key: SigningKey) -> Self {
        Self {
            private_key: key.secret_scalar().into(),
        }
    }
}

impl From<account_sdk::signers::eip191::Eip191Signer> for Eip191Signer {
    fn from(signer: account_sdk::signers::eip191::Eip191Signer) -> Self {
        Self {
            address: format!("0x{}", hex::encode(signer.address().as_bytes())),
        }
    }
}

#[allow(non_snake_case)]
#[derive(Tsify, Serialize, Deserialize, Debug, Clone)]
#[tsify(into_wasm_abi, from_wasm_abi)]
#[serde(rename_all = "camelCase")]
pub struct JsSignerInput(pub account_sdk::graphql::owner::add_owner::SignerInput);

impl From<JsSignerInput> for account_sdk::graphql::owner::add_owner::SignerInput {
    fn from(value: JsSignerInput) -> Self {
        value.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_webauthn_signer_conversion() {
        let test_signer = WebauthnSigner {
            rp_id: "test.com".to_string(),
            credential_id: "AAAA".to_string(),
            public_key: "pQECAyYgASFYIJV5jMYfVzTzGFNhtxKQ_BqYgqmqM0FT-B_vXE-fYZlIIlgg4that9Bxz0nL7KhQJqRxh3Tn6zqvyGG_QH9Z8-Jgz8g".to_string(),
        };

        // Convert to SDK type
        let sdk_signer: account_sdk::signers::webauthn::WebauthnSigner =
            test_signer.clone().try_into().unwrap();

        // Convert back to WASM type
        let wasm_signer: WebauthnSigner = sdk_signer.into();

        // Verify fields match
        assert_eq!(test_signer.rp_id, wasm_signer.rp_id);
        assert_eq!(test_signer.credential_id, wasm_signer.credential_id);
        assert_eq!(test_signer.public_key, wasm_signer.public_key);
    }
}
