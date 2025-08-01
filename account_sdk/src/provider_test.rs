use serde_json::json;
use starknet::{
    core::types::StarknetError,
    providers::{jsonrpc::JsonRpcResponse, ProviderError},
};

use crate::find_error_message_in_execution_error;

use super::{ExecuteFromOutsideError, ExecuteFromOutsideResponse};

#[test]
fn test_starknet_rs_transaction_execution_error_parsing() {
    // Test to reproduce the issue where RPC errors are marshalled as ProviderError
    // instead of proper TransactionExecutionError when going through starknet-rs
    use starknet::providers::jsonrpc::JsonRpcError;

    let error_json = json!({
        "code": 41,
        "message": "Transaction execution error",
        "data": {
            "execution_error": "Transaction reverted: Transaction execution has failed:\n0: Error in the called contract (contract address: 0x013f1386e3d4267a1502d8ca782d34b63634d969d3c527a511814c2ef67b84c4, class hash: 0x0743c83c41ce99ad470aa308823f417b2141e02e04571f5c0004e743556e7faf, selector: 0x015d40a3d6ca2ac30f4031e42be28da9b056fef9bb7357ac5e85627ee876e5ad):\nExecution failed. Failure reason:\n(0x617267656e742f6d756c746963616c6c2d6661696c6564 ('argent/multicall-failed'), 0x2, 0x736561736f6e206973207374696c6c206f70656e6564 ('season is still opened'), 0x454e545259504f494e545f4641494c4544 ('ENTRYPOINT_FAILED')).\n"
        }
    });

    // Test how starknet-rs would parse this error directly
    let json_rpc_error: JsonRpcError = serde_json::from_value(error_json.clone()).unwrap();

    // Convert to StarknetError the way starknet-rs would
    let starknet_error_result = TryInto::<StarknetError>::try_into(&json_rpc_error);

    match starknet_error_result {
        Ok(StarknetError::TransactionExecutionError(data)) => {
            println!("SUCCESS: starknet-rs correctly parsed as TransactionExecutionError");
            println!("Execution error data: {:?}", data);
        }
        Ok(other_error) => {
            println!(
                "ERROR: starknet-rs parsed as different StarknetError: {:?}",
                other_error
            );
            panic!("Expected TransactionExecutionError, got: {:?}", other_error);
        }
        Err(e) => {
            println!(
                "ERROR: starknet-rs failed to parse as StarknetError: {:?}",
                e
            );
            println!(
                "This would result in ProviderError::Other instead of TransactionExecutionError"
            );
            panic!("Failed to parse as StarknetError: {:?}", e);
        }
    }
}

#[test]
fn test_json_rpc_error_to_outside_execution_error() {
    let json_response = json!({
        "id": 1,
        "jsonrpc": "2.0",
        "error": {
            "code": 41,
            "message": "Transaction execution error",
            "data": {"execution_error":"Transaction reverted: Transaction execution has failed:\n0: Error in the called contract (contract address: 0x057156ef71dcfb930a272923dcbdc54392b6676497fdc143042ee1d4a7a861c1, class hash: 0x00e2eb8f5672af4e6a4e8a8f1b44989685e668489b0a25437733756c5a34a1d6, selector: 0x015d40a3d6ca2ac30f4031e42be28da9b056fef9bb7357ac5e85627ee876e5ad):\nError at pc=0:4302:\nCairo traceback (most recent call last):\nUnknown location (pc=0:290)\nUnknown location (pc=0:3037)\nUnknown location (pc=0:4318)\n\n1: Error in the called contract (contract address: 0x01f067407dd965de6d8ccc49f5774ccf7523e3b0573c4e9531fb997ab1782ec3, class hash: 0x032e17891b6cc89e0c3595a3df7cee760b5993744dc8dfef2bd4d443e65c0f40, selector: 0x034cc13b274446654ca3233ed2c1620d4c5d1d32fd20b47146a3371064bdc57d):\nError at pc=0:17371:\nCairo traceback (most recent call last):\nUnknown location (pc=0:3273)\nUnknown location (pc=0:12736)\n\n2: Error in the called contract (contract address: 0x049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7, class hash: 0x02a8846878b6ad1f54f6ba46f5f40e11cee755c677f130b2c4b60566c9003f1f, selector: 0x0219209e083275171774dab1df80982e9df2096516f06319c5c6d71ae0a8480c):\nError at pc=0:1354:\nAn ASSERT_EQ instruction failed: 5:3 != 5:0.\n","transaction_index":0}
        }
    });

    let json_rpc_response: JsonRpcResponse<ExecuteFromOutsideResponse> =
        serde_json::from_value(json_response).unwrap();

    match json_rpc_response {
        JsonRpcResponse::Success { .. } => {
            panic!("Expected an error response, got success")
        }
        JsonRpcResponse::Error { error, .. } => {
            let paymaster_error = ExecuteFromOutsideError::from(error);
            match paymaster_error {
                ExecuteFromOutsideError::ProviderError(ProviderError::StarknetError(StarknetError::TransactionExecutionError(data))) => {
                    assert!(find_error_message_in_execution_error(&data.execution_error, "Transaction reverted: Transaction execution has failed"));
                    assert_eq!(data.transaction_index, 0);
                },
                _ => panic!("Expected PaymasterError::ProviderError(ProviderError::StarknetError(StarknetError::TransactionExecutionError))"),
            }
        }
    }
}
