//! Benchmark comparing gas usage between Avnu and Cartridge paymasters.
//!
//! This benchmark measures the actual gas fees paid for identical transactions
//! executed through both paymaster implementations.
//!
//! Run with: cargo bench --features avnu-paymaster --bench paymaster_gas

use std::time::Duration;

use cainome::cairo_serde::{CairoSerde, ContractAddress, U256};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use starknet::{
    accounts::ConnectedAccount,
    core::types::{Felt, TransactionReceipt, TransactionReceiptWithBlockInfo},
    macros::{felt, selector},
    signers::SigningKey,
};
use tokio::runtime::Runtime;

use account_sdk::{
    abigen::controller::OutsideExecutionV3,
    account::{
        outside_execution::{OutsideExecution, OutsideExecutionAccount, OutsideExecutionCaller},
        session::policy::Policy,
    },
    artifacts::Version,
    provider::CartridgeProvider,
    provider_avnu::{
        AvnuPaymasterProvider, ExecuteRawRequest, ExecuteRawTransactionParams, ExecutionParameters,
        FeeMode, RawInvokeParams,
    },
    signers::{Owner, Signer},
    tests::{
        account::FEE_TOKEN_ADDRESS,
        runners::{avnu_paymaster::AvnuPaymasterRunner, katana::KatanaRunner},
    },
    transaction_waiter::TransactionWaiter,
};

/// Gas metrics extracted from a transaction receipt
#[derive(Debug, Clone)]
struct GasMetrics {
    /// The actual fee paid (in wei/fri)
    actual_fee: u128,
    /// Transaction hash for reference
    tx_hash: Felt,
}

impl std::fmt::Display for GasMetrics {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "actual_fee: {} (tx: {:#x})",
            self.actual_fee, self.tx_hash
        )
    }
}

/// Extract gas metrics from a transaction receipt
fn extract_gas_metrics(receipt: &TransactionReceiptWithBlockInfo, tx_hash: Felt) -> GasMetrics {
    let actual_fee = match &receipt.receipt {
        TransactionReceipt::Invoke(r) => felt_to_u128(r.actual_fee.amount),
        TransactionReceipt::Deploy(r) => felt_to_u128(r.actual_fee.amount),
        TransactionReceipt::Declare(r) => felt_to_u128(r.actual_fee.amount),
        TransactionReceipt::L1Handler(r) => felt_to_u128(r.actual_fee.amount),
        TransactionReceipt::DeployAccount(r) => felt_to_u128(r.actual_fee.amount),
    };

    GasMetrics { actual_fee, tx_hash }
}

/// Convert Felt to u128 for easier comparison
fn felt_to_u128(felt: Felt) -> u128 {
    let bytes = felt.to_bytes_be();
    // Take the last 16 bytes for u128
    let mut arr = [0u8; 16];
    arr.copy_from_slice(&bytes[16..32]);
    u128::from_be_bytes(arr)
}

/// Helper to build an ExecuteRawRequest with sponsored fee mode for Avnu
fn build_sponsored_request(
    signed: account_sdk::account::outside_execution::SignedOutsideExecution,
) -> ExecuteRawRequest {
    let execute_from_outside_call: starknet::core::types::Call = signed.clone().into();

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

/// Execute a transfer via Avnu paymaster with owner signer
async fn execute_avnu_owner(runner: &AvnuPaymasterRunner) -> GasMetrics {
    let signer = Signer::new_starknet_random();
    let controller = runner
        .deploy_controller(
            format!("avnu_owner_{}", rand::random::<u32>()),
            Owner::Signer(signer),
            Version::LATEST,
        )
        .await;

    let recipient = ContractAddress(felt!("0x1234567890"));
    let transfer_amount = U256 {
        low: 0x10_u128,
        high: 0,
    };

    let outside_execution = OutsideExecutionV3 {
        caller: OutsideExecutionCaller::Any.into(),
        execute_after: u64::MIN,
        execute_before: u64::MAX,
        calls: vec![account_sdk::abigen::controller::Call {
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

    let signed = controller
        .sign_outside_execution(OutsideExecution::V3(outside_execution))
        .await
        .unwrap();

    let request = build_sponsored_request(signed);

    let avnu_provider =
        AvnuPaymasterProvider::with_api_key(runner.paymaster_url.clone(), "paymaster_test".into());
    let result = avnu_provider
        .execute_raw_transaction(request)
        .await
        .unwrap();

    let receipt = TransactionWaiter::new(result.transaction_hash, runner.client())
        .wait()
        .await
        .unwrap();

    extract_gas_metrics(&receipt, result.transaction_hash)
}

/// Execute a transfer via Avnu paymaster with session signer
async fn execute_avnu_session(runner: &AvnuPaymasterRunner) -> GasMetrics {
    let signer = Signer::new_starknet_random();
    let mut controller = runner
        .deploy_controller(
            format!("avnu_session_{}", rand::random::<u32>()),
            Owner::Signer(signer),
            Version::LATEST,
        )
        .await;

    let recipient = ContractAddress(felt!("0x1234567891"));
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

    let outside_execution = OutsideExecutionV3 {
        caller: OutsideExecutionCaller::Any.into(),
        execute_after: u64::MIN,
        execute_before: u64::MAX,
        calls: vec![account_sdk::abigen::controller::Call {
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

    let signed = session_account
        .sign_outside_execution(OutsideExecution::V3(outside_execution))
        .await
        .unwrap();

    let request = build_sponsored_request(signed);

    let avnu_provider =
        AvnuPaymasterProvider::with_api_key(runner.paymaster_url.clone(), "paymaster_test".into());
    let result = avnu_provider
        .execute_raw_transaction(request)
        .await
        .unwrap();

    let receipt = TransactionWaiter::new(result.transaction_hash, runner.client())
        .wait()
        .await
        .unwrap();

    extract_gas_metrics(&receipt, result.transaction_hash)
}

/// Execute a transfer via Cartridge paymaster with owner signer
async fn execute_cartridge_owner(runner: &KatanaRunner) -> GasMetrics {
    let signer = Signer::new_starknet_random();
    let mut controller = runner
        .deploy_controller(
            format!("cartridge_owner_{}", rand::random::<u32>()),
            Owner::Signer(signer),
            Version::LATEST,
        )
        .await;

    let recipient = ContractAddress(felt!("0x1234567890"));
    let transfer_amount = U256 {
        low: 0x10_u128,
        high: 0,
    };

    let calls = vec![starknet::core::types::Call {
        to: *FEE_TOKEN_ADDRESS,
        selector: selector!("transfer"),
        calldata: [
            <ContractAddress as CairoSerde>::cairo_serialize(&recipient),
            <U256 as CairoSerde>::cairo_serialize(&transfer_amount),
        ]
        .concat(),
    }];

    let tx = controller
        .execute_from_outside_v3(calls, None)
        .await
        .unwrap();

    let receipt = TransactionWaiter::new(tx.transaction_hash, runner.client())
        .wait()
        .await
        .unwrap();

    extract_gas_metrics(&receipt, tx.transaction_hash)
}

/// Execute a transfer via Cartridge paymaster with session signer
async fn execute_cartridge_session(runner: &KatanaRunner) -> GasMetrics {
    let signer = Signer::new_starknet_random();
    let mut controller = runner
        .deploy_controller(
            format!("cartridge_session_{}", rand::random::<u32>()),
            Owner::Signer(signer),
            Version::LATEST,
        )
        .await;

    let recipient = ContractAddress(felt!("0x1234567891"));
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

    let outside_execution = OutsideExecutionV3 {
        caller: OutsideExecutionCaller::Any.into(),
        execute_after: u64::MIN,
        execute_before: u64::MAX,
        calls: vec![account_sdk::abigen::controller::Call {
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

    // Sign with session account (not owner) to properly benchmark session signing
    let signed = session_account
        .sign_outside_execution(OutsideExecution::V3(outside_execution.clone()))
        .await
        .unwrap();

    // Submit via Cartridge paymaster provider
    let tx = controller
        .provider()
        .add_execute_outside_transaction(
            OutsideExecution::V3(outside_execution),
            controller.address,
            signed.signature,
            None,
        )
        .await
        .unwrap();

    let receipt = TransactionWaiter::new(tx.transaction_hash, runner.client())
        .wait()
        .await
        .unwrap();

    extract_gas_metrics(&receipt, tx.transaction_hash)
}

/// Benchmark comparing gas usage between Avnu and Cartridge paymasters
fn paymaster_gas_benchmark(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    // Initialize runners once (this is expensive)
    // Both runners need to be initialized inside the runtime context
    // because KatanaRunner spawns a tokio task for the CartridgeProxy
    println!("Initializing runners...");
    let (avnu_runner, cartridge_runner) = rt.block_on(async {
        println!("Initializing Avnu paymaster runner...");
        let avnu = AvnuPaymasterRunner::new().await;
        println!("Avnu runner initialized");

        println!("Initializing Katana runner for Cartridge paymaster...");
        let cartridge = KatanaRunner::load();
        println!("Cartridge runner initialized");

        (avnu, cartridge)
    });

    let mut group = c.benchmark_group("paymaster_gas_comparison");

    // Configure for fewer samples since each iteration is expensive (deploys contracts)
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(60));

    // Benchmark Avnu paymaster with owner signer
    group.bench_function(BenchmarkId::new("avnu", "owner"), |b| {
        b.to_async(&rt).iter(|| async {
            let metrics = execute_avnu_owner(&avnu_runner).await;
            println!("  Avnu owner: {}", metrics);
            metrics.actual_fee
        });
    });

    // Benchmark Avnu paymaster with session signer
    group.bench_function(BenchmarkId::new("avnu", "session"), |b| {
        b.to_async(&rt).iter(|| async {
            let metrics = execute_avnu_session(&avnu_runner).await;
            println!("  Avnu session: {}", metrics);
            metrics.actual_fee
        });
    });

    // Benchmark Cartridge paymaster with owner signer
    group.bench_function(BenchmarkId::new("cartridge", "owner"), |b| {
        b.to_async(&rt).iter(|| async {
            let metrics = execute_cartridge_owner(&cartridge_runner).await;
            println!("  Cartridge owner: {}", metrics);
            metrics.actual_fee
        });
    });

    // Benchmark Cartridge paymaster with session signer
    group.bench_function(BenchmarkId::new("cartridge", "session"), |b| {
        b.to_async(&rt).iter(|| async {
            let metrics = execute_cartridge_session(&cartridge_runner).await;
            println!("  Cartridge session: {}", metrics);
            metrics.actual_fee
        });
    });

    group.finish();
}

criterion_group!(benches, paymaster_gas_benchmark);
criterion_main!(benches);
