//! Tests to verify our AVNU types are compatible with paymaster-rpc types
//!
//! Note: Due to different starknet-rs versions between controller-rs and paymaster,
//! we can't directly compare types. Instead, we verify JSON serialization compatibility.

use serde_json::json;
use starknet::core::types::Felt;

use crate::provider_avnu::{
    ExecuteRawRequest, ExecuteRawResponse, ExecuteRawTransactionParams, ExecutionParameters,
    DirectInvokeParams, FeeMode, TipPriority,
};

/// Test that our ExecuteRawRequest serializes to the expected JSON format
#[test]
fn test_execute_raw_request_json_format() {
    let request = ExecuteRawRequest {
        transaction: ExecuteRawTransactionParams::DirectInvoke {
            invoke: DirectInvokeParams {
                user_address: Felt::from(0x123u64),
                execute_from_outside_call: starknet::core::types::Call {
                    to: Felt::from(0x456u64),
                    selector: Felt::from(0x789u64),
                    calldata: vec![Felt::from(0x1u64), Felt::from(0x2u64)],
                },
            },
        },
        parameters: ExecutionParameters::V1 {
            fee_mode: FeeMode::Default {
                gas_token: Felt::from(0xabcu64),
                tip: TipPriority::Normal,
            },
            time_bounds: None,
        },
    };

    let json = serde_json::to_value(&request).unwrap();

    // Verify the structure matches what paymaster-rpc expects
    assert_eq!(json["transaction"]["type"], "invoke");
    assert!(json["transaction"]["invoke"]["user_address"].is_string());
    assert!(json["transaction"]["invoke"]["execute_from_outside_call"]["to"].is_string());
    assert_eq!(json["parameters"]["version"], "0x1");
    assert_eq!(json["parameters"]["fee_mode"]["mode"], "default");
    assert_eq!(json["parameters"]["fee_mode"]["tip"], "normal");
}

/// Test sponsored fee mode JSON format
#[test]
fn test_sponsored_fee_mode_json_format() {
    let request = ExecuteRawRequest {
        transaction: ExecuteRawTransactionParams::DirectInvoke {
            invoke: DirectInvokeParams {
                user_address: Felt::from(0x123u64),
                execute_from_outside_call: starknet::core::types::Call {
                    to: Felt::from(0x456u64),
                    selector: Felt::from(0x789u64),
                    calldata: vec![],
                },
            },
        },
        parameters: ExecutionParameters::V1 {
            fee_mode: FeeMode::Sponsored {
                tip: TipPriority::Normal,
            },
            time_bounds: None,
        },
    };

    let json = serde_json::to_value(&request).unwrap();

    assert_eq!(json["parameters"]["fee_mode"]["mode"], "sponsored");
    assert_eq!(json["parameters"]["fee_mode"]["tip"], "normal");
}

/// Test that we can deserialize a response in paymaster-rpc JSON format
#[test]
fn test_response_deserialization() {
    // This is the JSON format that paymaster-rpc returns
    let json = json!({
        "transaction_hash": "0x123",
        "tracking_id": "0x456"
    });

    let response: ExecuteRawResponse = serde_json::from_value(json).unwrap();

    assert_eq!(response.transaction_hash, Felt::from(0x123u64));
    assert_eq!(response.tracking_id, Felt::from(0x456u64));
}

/// Test round-trip serialization
#[test]
fn test_request_roundtrip() {
    let request = ExecuteRawRequest {
        transaction: ExecuteRawTransactionParams::DirectInvoke {
            invoke: DirectInvokeParams {
                user_address: Felt::from(0x123u64),
                execute_from_outside_call: starknet::core::types::Call {
                    to: Felt::from(0x456u64),
                    selector: Felt::from(0x789u64),
                    calldata: vec![Felt::ONE, Felt::TWO],
                },
            },
        },
        parameters: ExecutionParameters::V1 {
            fee_mode: FeeMode::Sponsored {
                tip: TipPriority::Normal,
            },
            time_bounds: None,
        },
    };

    let json = serde_json::to_string(&request).unwrap();
    let deserialized: ExecuteRawRequest = serde_json::from_str(&json).unwrap();

    // Verify key fields match
    match (&request.transaction, &deserialized.transaction) {
        (
            ExecuteRawTransactionParams::DirectInvoke { invoke: req },
            ExecuteRawTransactionParams::DirectInvoke { invoke: des },
        ) => {
            assert_eq!(req.user_address, des.user_address);
            assert_eq!(
                req.execute_from_outside_call.to,
                des.execute_from_outside_call.to
            );
        }
    }
}
