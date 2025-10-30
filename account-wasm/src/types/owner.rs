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
            Ok(SdkOwner::Account(*account.as_felt()))
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::signer::{Signer, StarknetSigner};
    use crate::types::JsFelt;
    use starknet_types_core::felt::Felt;

    #[test]
    fn test_owner_try_into_sdk_owner_with_signer() {
        // Test successful conversion with signer
        let signer = Signer {
            webauthns: None,
            webauthn: None,
            starknet: Some(StarknetSigner {
                private_key: JsFelt(Felt::from(123u64)),
            }),
            eip191: None,
        };
        let owner = Owner {
            signer: Some(signer),
            account: None,
        };

        let result = owner.try_into_sdk_owner();
        assert!(result.is_ok());
    }

    #[test]
    fn test_owner_try_into_sdk_owner_with_account() {
        // Test successful conversion with account
        let account = JsFelt(Felt::from(456u64));
        let owner = Owner {
            signer: None,
            account: Some(account),
        };

        let result = owner.try_into_sdk_owner();
        assert!(result.is_ok());

        if let Ok(SdkOwner::Account(addr)) = result {
            assert_eq!(addr, Felt::from(456u64));
        } else {
            panic!("Expected Account variant");
        }
    }

    #[test]
    fn test_owner_try_into_sdk_owner_empty_fails() {
        // Test that empty owner returns error instead of panicking
        let owner = Owner {
            signer: None,
            account: None,
        };

        let result = owner.try_into_sdk_owner();
        assert!(result.is_err());

        if let Err(error) = result {
            assert!(matches!(error.code, crate::errors::ErrorCode::InvalidOwner));
            assert_eq!(
                error.message,
                "Owner must have either signer or account data"
            );
        }
    }

    #[test]
    fn test_owner_helper_methods() {
        // Test is_empty
        let empty_owner = Owner {
            signer: None,
            account: None,
        };
        assert!(empty_owner.is_empty());

        // Test is_signer
        let signer_owner = Owner {
            signer: Some(Signer {
                webauthns: None,
                webauthn: None,
                starknet: Some(StarknetSigner {
                    private_key: JsFelt(Felt::from(1u64)),
                }),
                eip191: None,
            }),
            account: None,
        };
        assert!(signer_owner.is_signer());
        assert!(!signer_owner.is_account());

        // Test is_account
        let account_owner = Owner {
            signer: None,
            account: Some(JsFelt(Felt::from(2u64))),
        };
        assert!(account_owner.is_account());
        assert!(!account_owner.is_signer());

        // Test is_signer_and_account
        let both_owner = Owner {
            signer: Some(Signer {
                webauthns: None,
                webauthn: None,
                starknet: Some(StarknetSigner {
                    private_key: JsFelt(Felt::from(1u64)),
                }),
                eip191: None,
            }),
            account: Some(JsFelt(Felt::from(2u64))),
        };
        assert!(both_owner.is_signer_and_account());
    }
}
