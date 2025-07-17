use account_sdk::signers::Owner as SdkOwner;
use serde::{Deserialize, Serialize};
use tsify_next::Tsify;
use wasm_bindgen::prelude::*;

use crate::types::{call::JsCall, signer::JsSignerInput};

use super::{signer::Signer, JsFelt};

#[allow(non_snake_case)]
#[derive(Tsify, Serialize, Deserialize, Debug, Clone)]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub struct Owner {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signer: Option<Signer>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account: Option<JsFelt>,
}

impl From<Owner> for SdkOwner {
    fn from(owner: Owner) -> Self {
        if let Some(signer) = owner.signer {
            SdkOwner::Signer(signer.try_into().unwrap())
        } else if let Some(account) = owner.account {
            SdkOwner::Account(account.try_into().unwrap())
        } else {
            panic!("Missing owner data")
        }
    }
}

impl From<SdkOwner> for Owner {
    fn from(owner: SdkOwner) -> Self {
        match owner {
            SdkOwner::Signer(signer) => Self {
                signer: Some(signer.into()),
                account: None,
            },
            SdkOwner::Account(address) => Self {
                signer: None,
                account: Some(address.into()),
            },
        }
    }
}

#[allow(non_snake_case)]
#[derive(Tsify, Serialize, Deserialize, Debug, Clone)]
#[tsify(into_wasm_abi, from_wasm_abi)]
#[serde(rename_all = "camelCase")]
pub struct CreatePasskeyOwnerResult {
    pub call: JsCall,
    pub signer_input: JsSignerInput,
    pub signer_guid: JsFelt,
}
