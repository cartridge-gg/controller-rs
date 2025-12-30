use cainome::cairo_serde::{CairoSerde, ContractAddress, U256};
use starknet::{
    macros::{felt, selector},
    signers::SigningKey,
};

use crate::{
    abigen::{
        controller::{Call, OutsideExecutionV3},
        erc_20::Erc20,
    },
    account::{
        outside_execution::{OutsideExecution, OutsideExecutionAccount, OutsideExecutionCaller},
        session::policy::Policy,
    },
    artifacts::Version,
    provider_avnu::AvnuPaymasterProvider,
    signers::{Owner, Signer},
    tests::{
        account::FEE_TOKEN_ADDRESS,
        runners::{
            avnu::{build_execute_raw_request, create_avnu_proxy},
            katana::KatanaRunner,
        },
    },
    transaction_waiter::TransactionWaiter,
};

/// Test executing a transaction via the AVNU paymaster with owner signer
#[tokio::test]
async fn test_avnu_paymaster_owner_execute() {
    let runner = KatanaRunner::load();
    let (proxy_url, _handle) = create_avnu_proxy(&runner);

    let signer = Signer::new_starknet_random();
    let controller = runner
        .deploy_controller(
            "username".to_owned(),
            Owner::Signer(signer),
            Version::LATEST,
        )
        .await;

    let recipient = ContractAddress(felt!("0x18301129"));
    let amount = U256 {
        low: 0x10_u128,
        high: 0,
    };

    // Create the outside execution
    let outside_execution = OutsideExecutionV3 {
        caller: OutsideExecutionCaller::Any.into(),
        execute_after: u64::MIN,
        execute_before: u64::MAX,
        calls: vec![Call {
            to: (*FEE_TOKEN_ADDRESS).into(),
            selector: selector!("transfer"),
            calldata: [
                <ContractAddress as CairoSerde>::cairo_serialize(&recipient),
                <U256 as CairoSerde>::cairo_serialize(&amount),
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

    // Build the AVNU request
    let request = build_execute_raw_request(signed);

    // Execute via AVNU paymaster
    let avnu_provider = AvnuPaymasterProvider::new(proxy_url);
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
    let paymaster = runner.executor().await;
    assert_eq!(
        Erc20::new(*FEE_TOKEN_ADDRESS, &paymaster)
            .balanceOf(&recipient)
            .call()
            .await
            .unwrap(),
        amount
    );
}

/// Test executing a transaction via the AVNU paymaster with session signer
#[tokio::test]
async fn test_avnu_paymaster_session_execute() {
    let runner = KatanaRunner::load();
    let (proxy_url, _handle) = create_avnu_proxy(&runner);

    let signer = Signer::new_starknet_random();
    let mut controller = runner
        .deploy_controller(
            "username".to_owned(),
            Owner::Signer(signer),
            Version::LATEST,
        )
        .await;

    let recipient = ContractAddress(felt!("0x18301129"));
    let amount = U256 {
        low: 0x1_u128,
        high: 0,
    };

    // Create a session
    let session_account = controller
        .create_session(
            vec![Policy::new_call(*FEE_TOKEN_ADDRESS, selector!("transfer"))],
            u64::MAX,
        )
        .await
        .unwrap();

    // Create the outside execution
    let outside_execution = OutsideExecutionV3 {
        caller: OutsideExecutionCaller::Any.into(),
        execute_after: u64::MIN,
        execute_before: u64::MAX,
        calls: vec![Call {
            to: (*FEE_TOKEN_ADDRESS).into(),
            selector: selector!("transfer"),
            calldata: [
                <ContractAddress as CairoSerde>::cairo_serialize(&recipient),
                <U256 as CairoSerde>::cairo_serialize(&amount),
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

    // Build the AVNU request
    let request = build_execute_raw_request(signed);

    // Execute via AVNU paymaster
    let avnu_provider = AvnuPaymasterProvider::new(proxy_url);
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
    let paymaster = runner.executor().await;
    assert_eq!(
        Erc20::new(*FEE_TOKEN_ADDRESS, &paymaster)
            .balanceOf(&recipient)
            .call()
            .await
            .unwrap(),
        amount
    );
}
