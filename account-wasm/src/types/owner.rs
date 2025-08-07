use account_sdk::signers::Owner as SdkOwner;
use serde::{Deserialize, Serialize};
use tsify_next::Tsify;
use wasm_bindgen::prelude::*;

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

impl Owner {
    pub fn is_empty(&self) -> bool {
        self.signer.is_none() && self.account.is_none()
    }

    pub fn is_signer(&self) -> bool {
        self.signer.is_some() && self.account.is_none()
    }

    pub fn is_account(&self) -> bool {
        self.signer.is_none() && self.account.is_some()
    }

    pub fn is_signer_and_account(&self) -> bool {
        self.signer.is_some() && self.account.is_some()
    }
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
