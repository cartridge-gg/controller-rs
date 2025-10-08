use serde::{Deserialize, Serialize};
use tsify_next::Tsify;
use wasm_bindgen::prelude::*;

use account_sdk::account::session::policy::{
    CallPolicy as SdkCallPolicy, Policy as SdkPolicy, TypedDataPolicy as SdkTypedDataPolicy,
};

use super::{EncodingError, JsFelt};
use account_sdk::typed_data::hash_components;
use starknet::core::types::{Call, TypedData};
use starknet::core::utils::get_selector_from_name;
use starknet_crypto::{poseidon_hash, Felt};

#[derive(Tsify, Serialize, Deserialize, Debug, Clone, PartialEq)]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub struct CallPolicy {
    pub target: JsFelt,
    pub method: JsFelt,
    #[tsify(optional)]
    pub authorized: Option<bool>,
}

#[derive(Tsify, Serialize, Deserialize, Debug, Clone, PartialEq)]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub struct TypedDataPolicy {
    pub scope_hash: JsFelt,
    #[tsify(optional)]
    pub authorized: Option<bool>,
}

#[derive(Tsify, Serialize, Deserialize, Debug, Clone, PartialEq)]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub struct ApprovalPolicy {
    pub target: JsFelt,
    pub spender: JsFelt,
    pub amount: JsFelt,
}

#[allow(non_snake_case)]
#[derive(Tsify, Serialize, Deserialize, Debug, Clone, PartialEq)]
#[tsify(into_wasm_abi, from_wasm_abi)]
#[serde(untagged)]
pub enum Policy {
    Call(CallPolicy),
    TypedData(TypedDataPolicy),
    Approval(ApprovalPolicy),
}

impl Policy {
    pub fn is_requested(&self, policy: &Policy) -> bool {
        match (self, policy) {
            (Policy::Call(self_call), Policy::Call(policy_call)) => {
                self_call.target == policy_call.target && self_call.method == policy_call.method
            }
            (Policy::TypedData(self_td), Policy::TypedData(policy_td)) => {
                self_td.scope_hash == policy_td.scope_hash
            }
            (Policy::Approval(self_approval), Policy::Approval(policy_approval)) => {
                self_approval.target == policy_approval.target
                    && self_approval.spender == policy_approval.spender
                    && self_approval.amount == policy_approval.amount
            }
            _ => false,
        }
    }

    pub fn is_authorized(&self, policy: &Policy) -> bool {
        match (self, policy) {
            (Policy::Call(self_call), Policy::Call(policy_call)) => {
                self_call.target == policy_call.target
                    && self_call.method == policy_call.method
                    && self_call.authorized.unwrap_or(false)
            }
            (Policy::TypedData(self_td), Policy::TypedData(policy_td)) => {
                self_td.scope_hash == policy_td.scope_hash && self_td.authorized.unwrap_or(false)
            }
            // Approval policies are always considered authorized (they don't have an authorized field)
            (Policy::Approval(self_approval), Policy::Approval(policy_approval)) => {
                self_approval.target == policy_approval.target
                    && self_approval.spender == policy_approval.spender
                    && self_approval.amount == policy_approval.amount
            }
            _ => false,
        }
    }
}

impl TryFrom<JsValue> for Policy {
    type Error = EncodingError;

    fn try_from(value: JsValue) -> Result<Self, Self::Error> {
        Ok(serde_wasm_bindgen::from_value(value)?)
    }
}

impl TryFrom<Policy> for SdkPolicy {
    type Error = EncodingError;

    fn try_from(value: Policy) -> Result<Self, Self::Error> {
        match value {
            Policy::Call(CallPolicy {
                target,
                method,
                authorized,
            }) => Ok(SdkPolicy::Call(SdkCallPolicy {
                contract_address: target.try_into()?,
                selector: method.try_into()?,
                authorized,
            })),
            Policy::TypedData(TypedDataPolicy {
                scope_hash,
                authorized,
            }) => Ok(SdkPolicy::TypedData(SdkTypedDataPolicy {
                scope_hash: scope_hash.try_into()?,
                authorized,
            })),
            // Convert Approval policies to Call policies with approve selector
            Policy::Approval(ApprovalPolicy { target, .. }) => Ok(SdkPolicy::Call(SdkCallPolicy {
                contract_address: target.try_into()?,
                selector: get_approve_selector(),
                authorized: Some(true),
            })),
        }
    }
}

impl From<SdkPolicy> for Policy {
    fn from(value: SdkPolicy) -> Self {
        match value {
            SdkPolicy::Call(call_policy) => Policy::Call(CallPolicy {
                target: call_policy.contract_address.into(),
                method: call_policy.selector.into(),
                authorized: call_policy.authorized,
            }),
            SdkPolicy::TypedData(typed_data_policy) => Policy::TypedData(TypedDataPolicy {
                scope_hash: typed_data_policy.scope_hash.into(),
                authorized: typed_data_policy.authorized,
            }),
        }
    }
}

impl Policy {
    pub fn from_call(call: &Call) -> Self {
        Self::Call(CallPolicy {
            target: call.to.into(),
            method: call.selector.into(),
            authorized: Some(true),
        })
    }

    pub fn from_typed_data(typed_data: &TypedData) -> Result<Self, JsError> {
        let hash_parts = hash_components(typed_data)?;
        let scope_hash = poseidon_hash(hash_parts.domain_separator_hash, hash_parts.type_hash);

        Ok(Self::TypedData(TypedDataPolicy {
            scope_hash: scope_hash.into(),
            authorized: Some(true),
        }))
    }

    /// Check if this policy is for the "approve" entrypoint
    pub fn is_approve_policy(&self) -> bool {
        match self {
            Policy::Call(call_policy) => call_policy.method == get_approve_selector().into(),
            Policy::Approval(_) => true,
            _ => false,
        }
    }

    /// Check if this policy is for a forbidden entrypoint (increaseAllowance, increase_allowance)
    pub fn is_forbidden_policy(&self) -> bool {
        match self {
            Policy::Call(call_policy) => {
                let selector = call_policy.method.as_felt();
                *selector == get_increase_allowance_selector()
                    || *selector == get_increase_allowance_snake_case_selector()
            }
            // Approval policies are not forbidden
            Policy::Approval(_) => false,
            _ => false,
        }
    }
}

/// Get the selector for the "approve" entrypoint
pub fn get_approve_selector() -> Felt {
    // The selector for "approve" is calculated as the starknet keccak of the function name
    get_selector_from_name("approve").expect("Failed to compute approve selector")
}

/// Get the selector for the "increaseAllowance" entrypoint
pub fn get_increase_allowance_selector() -> Felt {
    get_selector_from_name("increaseAllowance")
        .expect("Failed to compute increaseAllowance selector")
}

/// Get the selector for the "increase_allowance" entrypoint (snake_case variant)
pub fn get_increase_allowance_snake_case_selector() -> Felt {
    get_selector_from_name("increase_allowance")
        .expect("Failed to compute increase_allowance selector")
}
