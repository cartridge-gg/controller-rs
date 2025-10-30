use account_sdk::signers::Owner as SdkOwner;
use serde::{Deserialize, Serialize};
use tsify_next::Tsify;
use wasm_bindgen::prelude::*;

use crate::errors::JsControllerError;

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

// Keep From implementation for backward compatibility, but use try_into_sdk_owner internally
impl From<Owner> for SdkOwner {
    fn from(owner: Owner) -> Self {
        owner.try_into_sdk_owner().expect("Owner conversion should not fail - this is a bug, please use try_into_sdk_owner instead")
    }
}

impl Owner {
    /// Safely convert Owner to SdkOwner, returning an error instead of panicking
    pub fn try_into_sdk_owner(self) -> Result<SdkOwner, JsControllerError> {
        if let Some(signer) = self.signer {
            Ok(SdkOwner::Signer(signer.try_into()?))
        } else if let Some(account) = self.account {
            // Felt to ContractAddress conversion is infallible
            Ok(SdkOwner::Account((*account.as_felt()).into()))
        } else {
            Err(JsControllerError {
                code: crate::errors::ErrorCode::InvalidOwner,
                message: "Owner must have either signer or account data".to_string(),
                data: None,
            })
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
