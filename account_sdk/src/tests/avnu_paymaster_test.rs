//! Integration tests for AVNU Paymaster using the real paymaster RPC server.
//!
//! These tests verify sponsored transactions where the paymaster pays for gas fees.
//! Both owner and session signers are tested.
//!
//! ## Fee Modes
//!
//! The AVNU paymaster supports two fee modes:
//!
//! ### Sponsored Mode (tested here)
//! - The paymaster pays for gas fees
//! - Requires an API key that starts with 'paymaster_'
//! - The gas tank account (prefunded account in tests) covers the costs
//!
//! ### Default Mode (self-funded, not tested here)
//! - The user pays for gas fees via token transfer
//! - Requires:
//!   - User has sufficient gas token balance (STRK/ETH)
//!   - User has approved the forwarder contract to spend tokens
//!   - Proper fee estimation and transfer handling by the paymaster
//! - More complex to set up in local testing environment

use cainome::cairo_serde::{CairoSerde, ContractAddress, U256};
use starknet::{
    core::types::Call,
    macros::{felt, selector},
    signers::SigningKey,
};

use crate::{
    abigen::{controller::OutsideExecutionV3, erc_20::Erc20},
    account::{
        outside_execution::{OutsideExecution, OutsideExecutionAccount, OutsideExecutionCaller},
        session::policy::Policy,
    },
    artifacts::Version,
    provider_avnu::{
        AvnuPaymasterProvider, ExecuteRawRequest, ExecuteRawTransactionParams, ExecutionParameters,
        FeeMode, RawInvokeParams,
    },
    signers::{Owner, Signer},
    tests::{account::FEE_TOKEN_ADDRESS, runners::avnu_paymaster::AvnuPaymasterRunner},
    transaction_waiter::TransactionWaiter,
};

/// Helper to build an ExecuteRawRequest with sponsored fee mode
fn build_sponsored_request(
    signed: crate::account::outside_execution::SignedOutsideExecution,
) -> ExecuteRawRequest {
    let execute_from_outside_call: Call = signed.clone().into();

    ExecuteRawRequest {
        transaction: ExecuteRawTransactionParams::RawInvoke {
            invoke: RawInvokeParams {
                user_address: signed.contract_address,
                execute_from_outside_call,
                gas_token: None,
                max_gas_token_amount: None,
            },
        },
        parameters: ExecutionParameters::V1 {
            fee_mode: FeeMode::Sponsored,
            time_bounds: None,
        },
    }
}

/// Test executing a sponsored transaction with owner signer.
/// The paymaster pays for gas fees from the configured gas tank.
#[tokio::test]
async fn test_sponsored_owner_execute() {
    let runner = AvnuPaymasterRunner::new().await;

    let signer = Signer::new_starknet_random();
    let controller = runner
        .deploy_controller("username".to_owned(), Owner::Signer(signer), Version::LATEST)
        .await;

    let recipient = ContractAddress(felt!("0x18301129"));
    let transfer_amount = U256 {
        low: 0x10_u128,
        high: 0,
    };

    // Get initial balance of recipient
    let executor = runner.executor().await;
    let initial_balance = Erc20::new(*FEE_TOKEN_ADDRESS, &executor)
        .balanceOf(&recipient)
        .call()
        .await
        .unwrap();

    // Create the outside execution with a simple transfer
    let outside_execution = OutsideExecutionV3 {
        caller: OutsideExecutionCaller::Any.into(),
        execute_after: u64::MIN,
        execute_before: u64::MAX,
        calls: vec![crate::abigen::controller::Call {
            to: (*FEE_TOKEN_ADDRESS).into(),
            selector: selector!("transfer"),
            calldata: [
                <ContractAddress as CairoSerde>::cairo_serialize(&recipient),
                <U256 as CairoSerde>::cairo_serialize(&transfer_amount),
            ]
            .concat(),
        }],
        nonce: (SigningKey::from_random().secret_scalar(), 1),
    };

    // Sign the outside execution
    let signed = controller
        .sign_outside_execution(OutsideExecution::V3(outside_execution))
        .await
        .unwrap();

    // Build sponsored request
    let request = build_sponsored_request(signed);

    // Execute via AVNU paymaster with API key for sponsored transactions
    let avnu_provider =
        AvnuPaymasterProvider::with_api_key(runner.paymaster_url.clone(), "paymaster_test".into());
    let result = avnu_provider
        .execute_raw_transaction(request)
        .await
        .unwrap();

    // Wait for the transaction
    TransactionWaiter::new(result.transaction_hash, runner.client())
        .wait()
        .await
        .unwrap();

    // Verify the transfer occurred - balance should have increased by transfer_amount
    let final_balance = Erc20::new(*FEE_TOKEN_ADDRESS, &executor)
        .balanceOf(&recipient)
        .call()
        .await
        .unwrap();

    assert_eq!(
        final_balance.low - initial_balance.low,
        transfer_amount.low,
        "Transfer amount should match"
    );
}

/// Test executing a sponsored transaction with session signer.
/// The paymaster pays for gas fees from the configured gas tank.
#[tokio::test]
async fn test_sponsored_session_execute() {
    let runner = AvnuPaymasterRunner::new().await;

    let signer = Signer::new_starknet_random();
    let mut controller = runner
        .deploy_controller("username".to_owned(), Owner::Signer(signer), Version::LATEST)
        .await;

    let recipient = ContractAddress(felt!("0x18301130"));
    let transfer_amount = U256 {
        low: 0x5_u128,
        high: 0,
    };

    // Create a session with transfer policy
    let session_account = controller
        .create_session(
            vec![Policy::new_call(*FEE_TOKEN_ADDRESS, selector!("transfer"))],
            u64::MAX,
        )
        .await
        .unwrap();

    // Get initial balance of recipient
    let executor = runner.executor().await;
    let initial_balance = Erc20::new(*FEE_TOKEN_ADDRESS, &executor)
        .balanceOf(&recipient)
        .call()
        .await
        .unwrap();

    // Create the outside execution
    let outside_execution = OutsideExecutionV3 {
        caller: OutsideExecutionCaller::Any.into(),
        execute_after: u64::MIN,
        execute_before: u64::MAX,
        calls: vec![crate::abigen::controller::Call {
            to: (*FEE_TOKEN_ADDRESS).into(),
            selector: selector!("transfer"),
            calldata: [
                <ContractAddress as CairoSerde>::cairo_serialize(&recipient),
                <U256 as CairoSerde>::cairo_serialize(&transfer_amount),
            ]
            .concat(),
        }],
        nonce: (SigningKey::from_random().secret_scalar(), 1),
    };

    // Sign the outside execution with the session account
    let signed = session_account
        .sign_outside_execution(OutsideExecution::V3(outside_execution))
        .await
        .unwrap();

    // Build sponsored request
    let request = build_sponsored_request(signed);

    // Execute via AVNU paymaster
    let avnu_provider =
        AvnuPaymasterProvider::with_api_key(runner.paymaster_url.clone(), "paymaster_test".into());
    let result = avnu_provider
        .execute_raw_transaction(request)
        .await
        .unwrap();

    // Wait for the transaction
    TransactionWaiter::new(result.transaction_hash, runner.client())
        .wait()
        .await
        .unwrap();

    // Verify the transfer occurred
    let final_balance = Erc20::new(*FEE_TOKEN_ADDRESS, &executor)
        .balanceOf(&recipient)
        .call()
        .await
        .unwrap();

    assert_eq!(
        final_balance.low - initial_balance.low,
        transfer_amount.low,
        "Transfer amount should match"
    );
}
