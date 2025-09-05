use account_sdk::abigen::controller::OutsideExecutionV3;
use serde::{Deserialize, Serialize};
use starknet::core::types::Call;
use starknet_types_core::felt::Felt;
use tsify_next::Tsify;
use wasm_bindgen::prelude::*;

use crate::types::call::JsCall;
use crate::types::JsFelt;

/// JavaScript-friendly OutsideExecution V3 structure
#[allow(non_snake_case)]
#[derive(Tsify, Serialize, Deserialize, Debug, Clone)]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub struct JsOutsideExecutionV3 {
    pub caller: JsFelt,
    pub execute_after: u64,
    pub execute_before: u64,
    pub calls: Vec<JsCall>,
    pub nonce: [JsFelt; 2], // [namespace, bitmask]
}

/// Result type for signExecuteFromOutside containing both the OutsideExecution and signature
#[allow(non_snake_case)]
#[derive(Tsify, Serialize, Deserialize, Debug, Clone)]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub struct JsSignedOutsideExecution {
    pub outside_execution: JsOutsideExecutionV3,
    pub signature: Vec<JsFelt>,
}

impl From<OutsideExecutionV3> for JsOutsideExecutionV3 {
    fn from(value: OutsideExecutionV3) -> Self {
        Self {
            caller: Felt::from(value.caller).into(),
            execute_after: value.execute_after,
            execute_before: value.execute_before,
            calls: value
                .calls
                .into_iter()
                .map(|call| {
                    JsCall::from(Call {
                        to: call.to.into(),
                        selector: call.selector,
                        calldata: call.calldata,
                    })
                })
                .collect(),
            nonce: [value.nonce.0.into(), Felt::from(value.nonce.1).into()],
        }
    }
}

impl TryFrom<JsOutsideExecutionV3> for OutsideExecutionV3 {
    type Error = crate::types::EncodingError;

    fn try_from(value: JsOutsideExecutionV3) -> Result<Self, Self::Error> {
        let calls: Vec<Call> = value
            .calls
            .into_iter()
            .map(TryInto::try_into)
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self {
            caller: Felt::try_from(value.caller)?.into(),
            execute_after: value.execute_after,
            execute_before: value.execute_before,
            calls: calls
                .into_iter()
                .map(|call| account_sdk::abigen::controller::Call {
                    to: call.to.into(),
                    selector: call.selector,
                    calldata: call.calldata,
                })
                .collect(),
            nonce: (
                Felt::try_from(value.nonce[0].clone())?,
                u128::try_from(Felt::try_from(value.nonce[1].clone())?).map_err(|_| {
                    crate::types::EncodingError::UnexpectedOption(
                        "Invalid nonce bitmask".to_string(),
                    )
                })?,
            ),
        })
    }
}
