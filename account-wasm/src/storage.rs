use serde::{Deserialize, Serialize};
use starknet_types_core::felt::Felt;
use wasm_bindgen::JsError;
use web_sys::window;

use crate::types::policy::Policy;

type Result<T> = std::result::Result<T, JsError>;

const POLICY_STORAGE_PREFIX: &str = "@cartridge/policies/";

#[derive(Serialize, Deserialize)]
pub struct StoredPolicies {
    policies: Vec<Policy>,
}

#[derive(Clone)]
pub struct PolicyStorage {
    storage_key: String,
}

impl PolicyStorage {
    #[allow(dead_code)]
    pub fn new(address: &Felt, chain_id: &Felt) -> Self {
        let storage_key = format!("@cartridge/policies/0x{address:x}/0x{chain_id:x}");
        Self { storage_key }
    }

    pub fn new_with_app_id(address: &Felt, app_id: &str, chain_id: &Felt) -> Self {
        let storage_key = format!(
            "@cartridge/policies/0x{address:x}/{}/0x{chain_id:x}",
            urlencoding::encode(app_id),
        );
        Self { storage_key }
    }

    pub fn store(&self, policies: Vec<Policy>) -> Result<()> {
        // Store all policies including approval policies for comparison
        if let Some(window) = window() {
            if let Ok(Some(storage)) = window.local_storage() {
                let stored = StoredPolicies { policies };
                if let Ok(json) = serde_json::to_string(&stored) {
                    storage
                        .set_item(&self.storage_key, &json)
                        .map_err(|_| JsError::new("Failed to store policies"))?;
                }
            }
        }
        Ok(())
    }

    /// Clears all policy entries from `window.localStorage` (all addresses/app_ids/chains).
    pub fn clear_all() -> Result<()> {
        if let Some(window) = window() {
            if let Ok(Some(storage)) = window.local_storage() {
                let length = storage
                    .length()
                    .map_err(|_| JsError::new("Failed to get localStorage length"))?;

                // Collect keys first; removing while iterating by index can skip entries.
                let mut keys = Vec::new();
                for i in 0..length {
                    if let Ok(Some(key)) = storage.key(i) {
                        keys.push(key);
                    }
                }

                for key in keys {
                    if key.starts_with(POLICY_STORAGE_PREFIX) {
                        storage
                            .remove_item(&key)
                            .map_err(|_| JsError::new("Failed to remove policy from localStorage"))?;
                    }
                }
            }
        }
        Ok(())
    }

    pub fn get(&self) -> Result<Option<StoredPolicies>> {
        if let Some(window) = window() {
            if let Ok(Some(storage)) = window.local_storage() {
                if let Ok(Some(json)) = storage.get_item(&self.storage_key) {
                    return Ok(serde_json::from_str(&json).ok());
                }
            }
        }
        Ok(None)
    }

    pub fn is_requested(&self, policies: &[Policy]) -> Result<bool> {
        Ok(self
            .get()?
            .map(|stored| check_is_requested(&stored.policies, policies))
            .unwrap_or(false))
    }

    pub fn is_authorized(&self, policies: &[Policy]) -> Result<bool> {
        Ok(self
            .get()?
            .map(|stored| check_is_authorized(&stored.policies, policies))
            .unwrap_or(false))
    }
}

fn check_policies<F>(stored_policies: &[Policy], policies: &[Policy], check_fn: F) -> bool
where
    F: Fn(&Policy, &Policy) -> bool,
{
    policies
        .iter()
        .all(|p| stored_policies.iter().any(|stored_p| check_fn(stored_p, p)))
}

fn check_is_requested(stored_policies: &[Policy], policies: &[Policy]) -> bool {
    check_policies(stored_policies, policies, |stored, requested| {
        stored.is_requested(requested)
    })
}

pub(crate) fn check_is_authorized(stored_policies: &[Policy], policies: &[Policy]) -> bool {
    check_policies(stored_policies, policies, |stored, requested| {
        match (stored, requested) {
            (Policy::Call(stored_call), Policy::Call(requested_call)) => {
                // Target and method must match
                stored_call.target == requested_call.target &&
                stored_call.method == requested_call.method &&
                // The stored policy must explicitly authorize (Some(true))
                stored_call.authorized == Some(true)
                // Ignore the requested policy's authorized field
            }
            (Policy::TypedData(stored_td), Policy::TypedData(requested_td)) => {
                stored_td.scope_hash == requested_td.scope_hash
                    && stored_td.authorized == Some(true)
                // Ignore the requested policy's authorized field
            }
            // Approval policies are always considered authorized when they match
            (Policy::Approval(stored_approval), Policy::Approval(requested_approval)) => {
                stored_approval.target == requested_approval.target
                    && stored_approval.spender == requested_approval.spender
                    && stored_approval.amount == requested_approval.amount
            }
            _ => false,
        }
    })
}

#[cfg(test)]
mod policy_check_tests {
    use crate::types::policy::CallPolicy;
    use crate::types::JsFelt;
    use starknet::{
        core::types::{Call, Felt},
        macros::felt,
    };
    use std::str::FromStr;

    use super::*;

    #[test]
    fn test_check_is_requested() {
        let policy1 = Policy::Call(CallPolicy {
            target: JsFelt(felt!("0x1234")),
            method: JsFelt(felt!("0x5678")),
            authorized: None,
        });
        let policy2 = Policy::Call(CallPolicy {
            target: JsFelt(felt!("0x1234")),
            method: JsFelt(felt!("0x5678")),
            authorized: Some(true),
        });
        let policy3 = Policy::Call(CallPolicy {
            target: JsFelt(felt!("0x9999")),
            method: JsFelt(felt!("0x5678")),
            authorized: None,
        });

        let stored = vec![policy1.clone()];

        // Test exact match
        assert!(check_is_requested(&stored, &[policy1.clone()]));

        // Test authorized policy matches non-authorized request
        assert!(check_is_requested(&stored, &[policy2]));

        // Test non-matching policy
        assert!(!check_is_requested(&stored, &[policy3]));

        // Test multiple policies - should now pass since we allow duplicates
        assert!(check_is_requested(
            &stored,
            &[policy1.clone(), policy1.clone()]
        ));

        // Test duplicate requested policies with multiple stored - should pass
        let stored_multiple = vec![policy1.clone(), policy1.clone()];
        assert!(check_is_requested(
            &stored_multiple,
            &[policy1.clone(), policy1.clone()]
        ));
    }

    #[test]
    fn test_check_is_authorized() {
        let policy1 = Policy::Call(CallPolicy {
            target: JsFelt(felt!("0x1234")),
            method: JsFelt(felt!("0x5678")),
            authorized: Some(true),
        });
        let policy2 = Policy::Call(CallPolicy {
            target: JsFelt(felt!("0x1234")),
            method: JsFelt(felt!("0x5678")),
            authorized: None,
        });
        let policy3 = Policy::Call(CallPolicy {
            target: JsFelt(felt!("0x9999")),
            method: JsFelt(felt!("0x5678")),
            authorized: Some(true),
        });

        let stored = vec![policy1.clone()];

        // Test exact match
        assert!(check_is_authorized(&stored, &[policy1.clone()]));

        // Test unauthorized policy doesn't match authorized
        assert!(check_is_authorized(&stored, &[policy2]));

        // Test non-matching policy
        assert!(!check_is_authorized(&stored, &[policy3]));

        // Test multiple policies
        assert!(check_is_authorized(
            &stored,
            &[policy1.clone(), policy1.clone()]
        ));

        // Test duplicate authorized policies - this should pass after our fix
        let stored_multiple = vec![policy1.clone(), policy1.clone()];
        assert!(check_is_authorized(
            &stored_multiple,
            &[policy1.clone(), policy1.clone()]
        ));
    }

    #[test]
    fn test_check_is_authorized_from_call() {
        // Create a policy and store it
        let stored_policy = Policy::Call(CallPolicy {
            target: JsFelt(felt!("0x1234")),
            method: JsFelt(felt!("0x5678")),
            authorized: Some(true),
        });

        let stored = vec![stored_policy];

        // Create a Call that matches the stored policy
        let call = Call {
            to: Felt::from_str("0x1234").unwrap(),
            selector: Felt::from_str("0x5678").unwrap(),
            calldata: vec![],
        };

        // Create Policy from Call
        let policy_from_call = Policy::from_call(&call);

        // Test that the policy created from Call is authorized
        assert!(check_is_authorized(&stored, &[policy_from_call]));

        // Create a Call that doesn't match the stored policy
        let non_matching_call = Call {
            to: Felt::from_str("0x9999").unwrap(),
            selector: Felt::from_str("0x5678").unwrap(),
            calldata: vec![],
        };

        // Create Policy from Call
        let non_matching_policy = Policy::from_call(&non_matching_call);

        // Test that the policy created from non-matching Call is not authorized
        assert!(!check_is_authorized(&stored, &[non_matching_policy]));
    }
}

#[cfg(all(test, target_arch = "wasm32"))]
mod tests {
    use super::*;
    use crate::types::{
        policy::{
            get_approve_selector, get_increase_allowance_selector, ApprovalPolicy, CallPolicy,
            TypedDataPolicy,
        },
        JsFelt,
    };
    use starknet::{core::types::Felt, macros::felt};
    use wasm_bindgen_test::*;

    #[wasm_bindgen_test]
    fn test_policy_storage_is_requested() {
        let storage = PolicyStorage::new_with_app_id(&Felt::from(1), "test_app", &Felt::from(1));

        // Create some test policies
        let policy1 = Policy::Call(CallPolicy {
            target: JsFelt(felt!("0x1234")),
            method: JsFelt(felt!("0x5678")),
            authorized: None,
        });
        let policy2 = Policy::Call(CallPolicy {
            target: JsFelt(felt!("0x1234")),
            method: JsFelt(felt!("0x5678")),
            authorized: Some(true),
        });
        let policy3 = Policy::Call(CallPolicy {
            target: JsFelt(felt!("0x9999")), // Different target
            method: JsFelt(felt!("0x5678")),
            authorized: None,
        });

        // Store some policies
        storage.store(vec![policy1.clone()]).unwrap();

        // Test exact match
        assert!(storage.is_requested(&[policy1.clone()]).unwrap());

        // Test authorized policy matches non-authorized request
        assert!(storage.is_requested(&[policy2.clone()]).unwrap());

        // Test non-matching policy
        assert!(!storage.is_requested(&[policy3]).unwrap());

        // Test multiple policies - both match the same stored policy so this should pass
        assert!(storage
            .is_requested(&[policy1.clone(), policy2.clone()])
            .unwrap());
    }

    #[wasm_bindgen_test]
    fn test_policy_storage_is_authorized() {
        let storage = PolicyStorage::new_with_app_id(&Felt::from(1), "test_app", &Felt::from(1));

        // Create some test policies
        let policy1 = Policy::Call(CallPolicy {
            target: JsFelt(felt!("0x1234")),
            method: JsFelt(felt!("0x5678")),
            authorized: Some(true),
        });
        let policy2 = Policy::Call(CallPolicy {
            target: JsFelt(felt!("0x1234")),
            method: JsFelt(felt!("0x5678")),
            authorized: None,
        });
        let policy3 = Policy::TypedData(TypedDataPolicy {
            scope_hash: JsFelt(felt!("0x1234")),
            authorized: Some(true),
        });
        let policy4 = Policy::Approval(ApprovalPolicy {
            target: JsFelt(felt!("0x1234")),
            spender: JsFelt(felt!("0x5678")),
            amount: JsFelt(felt!("1000")),
        });

        // Store authorized policies
        storage
            .store(vec![policy1.clone(), policy3.clone()])
            .unwrap();

        // Test authorized policy
        assert!(storage.is_authorized(&[policy1.clone()]).unwrap());

        // Test unauthorized policy - it should still be authorized because policy1 authorizes the same target/method
        assert!(storage.is_authorized(&[policy2]).unwrap());

        // Test authorized TypedData policy - should be authorized since it was stored with authorized: true
        assert!(storage.is_authorized(&[policy3.clone()]).unwrap());

        // Test approval policy is not authorized
        assert!(!storage.is_authorized(&[policy4.clone()]).unwrap());

        // Test multiple policies
        assert!(storage.is_authorized(&[policy1, policy3]).unwrap());
    }

    #[wasm_bindgen_test]
    fn test_approve_policy_filtering() {
        let storage = PolicyStorage::new_with_app_id(&Felt::from(1), "test_app", &Felt::from(1));

        // Create an Approval policy (new type)
        let approval_policy = Policy::Approval(ApprovalPolicy {
            target: JsFelt(felt!("0x1234")),
            spender: JsFelt(felt!("0x5678")),
            amount: JsFelt(felt!("1000")),
        });

        // Create a legacy approve policy using Call
        let legacy_approve_policy = Policy::Call(CallPolicy {
            target: JsFelt(felt!("0x1234")),
            method: JsFelt(get_approve_selector()),
            authorized: Some(true),
        });

        // Create a regular policy
        let regular_policy = Policy::Call(CallPolicy {
            target: JsFelt(felt!("0x1234")),
            method: JsFelt(felt!("0xABCD")),
            authorized: Some(true),
        });

        // Store all policies
        storage
            .store(vec![
                approval_policy.clone(),
                legacy_approve_policy.clone(),
                regular_policy.clone(),
            ])
            .unwrap();

        // Verify that only the regular policy is stored (approve policies should be filtered out)
        let stored = storage.get().unwrap().unwrap();
        assert_eq!(stored.policies.len(), 3);

        // Verify the approve policies are not in storage
        assert!(storage.is_requested(&[approval_policy]).unwrap());
        assert!(storage.is_requested(&[legacy_approve_policy]).unwrap());
        assert!(storage.is_requested(&[regular_policy]).unwrap());
    }

    #[wasm_bindgen_test]
    fn test_forbidden_policies() {
        // Test that increaseAllowance policies are detected as forbidden
        let increase_allowance_policy = Policy::Call(CallPolicy {
            target: JsFelt(felt!("0x1234")),
            method: JsFelt(get_increase_allowance_selector()),
            authorized: Some(true),
        });

        assert!(increase_allowance_policy.is_forbidden_policy());
        assert!(!increase_allowance_policy.is_approve_policy());

        // Test that approve Call policies are NOT detected as approve policies (for incremental migration)
        let approve_policy = Policy::Call(CallPolicy {
            target: JsFelt(felt!("0x1234")),
            method: JsFelt(get_approve_selector()),
            authorized: Some(true),
        });

        assert!(!approve_policy.is_approve_policy());
        assert!(!approve_policy.is_forbidden_policy());

        // Test that regular policies are neither approve nor forbidden
        let regular_policy = Policy::Call(CallPolicy {
            target: JsFelt(felt!("0x1234")),
            method: JsFelt(felt!("0x5678")),
            authorized: Some(true),
        });

        assert!(!regular_policy.is_approve_policy());
        assert!(!regular_policy.is_forbidden_policy());

        // Test the new Approval policy type
        let approval_policy = Policy::Approval(ApprovalPolicy {
            target: JsFelt(felt!("0x1234")),
            spender: JsFelt(felt!("0x5678")),
            amount: JsFelt(felt!("1000")),
        });

        assert!(approval_policy.is_approve_policy());
        assert!(!approval_policy.is_forbidden_policy());
    }
}
