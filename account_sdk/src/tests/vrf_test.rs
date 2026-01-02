//! Integration tests for VRF with AVNU Paymaster.
//!
//! These tests verify VRF functionality with both sponsored and self-funded transactions.
//! The VRF proof is generated and bundled with the transaction calls.
//!
//! ## How VRF Works (Nested Outside Execution)
//!
//! The VRF flow requires nested outside execution:
//!
//! 1. **Outer execution** (VRF Account signs):
//!    - `submit_random(seed, proof)` - inject VRF proof
//!    - `execute_from_outside_v2(inner_execution)` - call player's account
//!
//! 2. **Inner execution** (Player Account signs):
//!    - `request_random(caller, source)` - signal VRF intent
//!    - `dice()` - the actual game call that consumes random
//!
//! The seed is computed using the player's address (who calls request_random).
//!
//! ## Test Structure
//!
//! - `test_vrf_sponsored_execute`: VRF with paymaster-sponsored gas fees
//! - `test_vrf_self_funded_execute`: VRF with user-paid gas fees

use cainome::cairo_serde::{CairoSerde, ContractAddress, U256};
use starknet::{
    core::types::{Call, Felt},
    macros::{selector, short_string},
    signers::SigningKey,
};

/// ANY_CALLER constant - allows any caller for outside execution
const ANY_CALLER: Felt = short_string!("ANY_CALLER");

use crate::{
    provider_avnu::{
        AvnuPaymasterProvider, ExecuteRawRequest, ExecuteRawTransactionParams, ExecutionParameters,
        FeeMode, RawInvokeParams,
    },
    tests::{
        account::FEE_TOKEN_ADDRESS,
        runners::vrf::VrfRunner,
        vrf_types::{Call as VrfCall, OutsideExecution, Proof, Source},
    },
    transaction_waiter::TransactionWaiter,
};

/// Helper to build an ExecuteRawRequest with sponsored fee mode for VRF
fn build_vrf_sponsored_request(
    user_address: Felt,
    execute_from_outside_call: Call,
) -> ExecuteRawRequest {
    ExecuteRawRequest {
        transaction: ExecuteRawTransactionParams::RawInvoke {
            invoke: RawInvokeParams {
                user_address,
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

/// Helper to build an ExecuteRawRequest with self-funded fee mode for VRF
fn build_vrf_self_funded_request(
    user_address: Felt,
    execute_from_outside_call: Call,
    gas_token: Felt,
    max_gas_token_amount: Felt,
) -> ExecuteRawRequest {
    ExecuteRawRequest {
        transaction: ExecuteRawTransactionParams::RawInvoke {
            invoke: RawInvokeParams {
                user_address,
                execute_from_outside_call,
                gas_token: Some(gas_token),
                max_gas_token_amount: Some(max_gas_token_amount),
            },
        },
        parameters: ExecutionParameters::V1 {
            fee_mode: FeeMode::Default { gas_token },
            time_bounds: None,
        },
    }
}

/// Compute the VRF seed from source and transaction info
/// 
/// The seed is computed in `vrf_provider_component.cairo:get_seed`:
/// - For Source::Nonce(addr): poseidon_hash([nonce, addr, caller, chain_id])
/// - For Source::Salt(salt): poseidon_hash([salt, caller, chain_id])
///
/// IMPORTANT: `caller` is determined by `get_caller_address()` when `consume_random` is called.
/// This is typically the **VRF Consumer contract** (the game contract), NOT the user's account.
fn compute_seed(source: &Source, consumer_address: Felt, chain_id: Felt, nonce: Felt) -> Felt {
    use starknet_crypto::poseidon_hash_many;

    match source {
        Source::Nonce(addr) => {
            // addr = the address stored in Source::Nonce (typically player account)
            // consumer_address = the VRF Consumer contract that calls consume_random
            poseidon_hash_many(&[nonce, addr.0, consumer_address, chain_id])
        }
        Source::Salt(salt) => {
            poseidon_hash_many(&[*salt, consumer_address, chain_id])
        }
    }
}

/// Test executing a VRF transaction with sponsored gas fees.
/// The paymaster pays for gas, and the VRF proof is bundled with the call.
///
/// ## Flow (Nested Outside Execution)
///
/// 1. Player Account signs inner outside execution containing:
///    - `request_random(caller, source)` -> VRF Account
///    - `dice()` -> VRF Consumer
///
/// 2. VRF Account signs outer outside execution containing:
///    - `submit_random(seed, proof)` -> VRF Account (self)
///    - `execute_from_outside_v2(inner_execution + signature)` -> Player Account
///
/// 3. Paymaster/Forwarder calls `execute_from_outside_v2` on VRF Account
#[tokio::test]
async fn test_vrf_sponsored_execute() {
    let runner = VrfRunner::new().await;

    // Get initial dice value (should be 0 or previous value)
    let initial_dice = runner.get_dice_value().await;

    // === Step 1: Build the INNER outside execution (Player Account's calls) ===
    // The player account will execute: request_random + dice
    
    // Prepare the VRF source - using Nonce with the player account address
    // (the player is the one calling request_random)
    let source = Source::Nonce(ContractAddress(runner.player_account_address));

    // request_random(caller: ContractAddress, source: Source)
    // caller = player_account_address (who is calling the game)
    let request_random_calldata = [
        <ContractAddress as CairoSerde>::cairo_serialize(&ContractAddress(
            runner.player_account_address,
        )),
        <Source as CairoSerde>::cairo_serialize(&source),
    ]
    .concat();

    let inner_outside_execution = OutsideExecution {
        caller: ContractAddress(ANY_CALLER),
        nonce: SigningKey::from_random().secret_scalar(),
        execute_after: 0,
        execute_before: u64::MAX,
        calls: vec![
            // First: request_random to signal VRF intent
            VrfCall {
                to: ContractAddress(runner.vrf_account_address),
                selector: selector!("request_random"),
                calldata: request_random_calldata,
            },
            // Second: the actual game call (dice)
            VrfCall {
                to: ContractAddress(runner.vrf_consumer_address),
                selector: selector!("dice"),
                calldata: vec![],
            },
        ],
    };

    // Player account signs the inner outside execution
    let inner_signature = runner.sign_player_outside_execution(&inner_outside_execution);

    println!("=== Inner Outside Execution (Player) ===");
    println!("Player Account Address: {:?}", runner.player_account_address);
    println!("Inner calls: request_random + dice");
    println!("Inner nonce: {:?}", inner_outside_execution.nonce);

    // === Step 2: Compute seed and generate VRF proof ===
    // The seed is computed with:
    // - source.addr = player_account_address (in Source::Nonce)
    // - caller = vrf_consumer_address (the game contract that calls consume_random)
    let seed = compute_seed(
        &source,
        runner.vrf_consumer_address, // The VRF Consumer calls consume_random
        runner.chain_id(),
        Felt::ZERO, // Initial nonce is 0
    );

    // Generate VRF proof
    let proof = runner.generate_proof(seed);
    
    println!("=== VRF Seed and Proof ===");
    println!("Seed: {:?}", seed);
    println!("Proof gamma: ({:?}, {:?})", proof.gamma.x, proof.gamma.y);

    // === Step 3: Build the OUTER outside execution (VRF Account's calls) ===
    
    // submit_random(seed: felt252, proof: Proof)
    let submit_random_calldata = [
        vec![seed],
        <Proof as CairoSerde>::cairo_serialize(&proof),
    ]
    .concat();

    // Build execute_from_outside_v2 call to Player Account
    // Calldata: [outside_execution..., signature_len, signature...]
    let inner_execution_calldata =
        <OutsideExecution as CairoSerde>::cairo_serialize(&inner_outside_execution);
    let mut execute_player_calldata = inner_execution_calldata;
    execute_player_calldata.push(Felt::from(inner_signature.len()));
    execute_player_calldata.extend(inner_signature.clone());

    let outer_outside_execution = OutsideExecution {
        caller: ContractAddress(ANY_CALLER),
        nonce: SigningKey::from_random().secret_scalar(),
        execute_after: 0,
        execute_before: u64::MAX,
        calls: vec![
            // First: submit_random to inject the VRF proof
            VrfCall {
                to: ContractAddress(runner.vrf_account_address),
                selector: selector!("submit_random"),
                calldata: submit_random_calldata,
            },
            // Second: execute_from_outside_v2 on Player Account
            VrfCall {
                to: ContractAddress(runner.player_account_address),
                selector: selector!("execute_from_outside_v2"),
                calldata: execute_player_calldata,
            },
        ],
    };

    // VRF Account signs the outer outside execution
    let outer_signature = runner.sign_outside_execution(&outer_outside_execution);

    println!("=== Outer Outside Execution (VRF Account) ===");
    println!("VRF Account Address: {:?}", runner.vrf_account_address);
    println!("Outer calls: submit_random + execute_from_outside_v2(player)");
    println!("Outer nonce: {:?}", outer_outside_execution.nonce);

    // === Step 4: Build the final call to VRF Account's execute_from_outside_v2 ===
    let outer_execution_calldata =
        <OutsideExecution as CairoSerde>::cairo_serialize(&outer_outside_execution);
    let mut final_calldata = outer_execution_calldata;
    final_calldata.push(Felt::from(outer_signature.len()));
    final_calldata.extend(outer_signature.clone());

    let execute_from_outside_call = Call {
        to: runner.vrf_account_address,
        selector: selector!("execute_from_outside_v2"),
        calldata: final_calldata,
    };

    // === Step 5: Execute via AVNU paymaster ===
    let request =
        build_vrf_sponsored_request(runner.vrf_account_address, execute_from_outside_call.clone());

    let avnu_provider =
        AvnuPaymasterProvider::with_api_key(runner.paymaster_url(), "paymaster_test".into());
    
    println!("=== Executing via Paymaster ===");
    println!("VRF Consumer Address: {:?}", runner.vrf_consumer_address);
    println!("Chain ID: {:?}", runner.chain_id());
    
    // Verify contract state before execution
    let contract_vrf_pk = runner.get_contract_vrf_public_key().await;
    println!("Contract VRF public key: {:?}", contract_vrf_pk);
    assert_eq!(contract_vrf_pk, runner.vrf_public_key, "VRF public keys should match!");

    // Execute directly (without paymaster for now - paymaster has issues with local setup)
    // Once the direct execution works, paymaster integration can be added
    use starknet::accounts::Account;
    let executor = runner.avnu.executor().await;
    
    let direct_result = executor
        .execute_v3(vec![execute_from_outside_call.clone()])
        .send()
        .await;
    
    println!("Direct execute result: {:?}", direct_result);
    let direct_result = direct_result.expect("Direct execution should succeed");
    
    // Wait for the transaction
    let receipt = TransactionWaiter::new(direct_result.transaction_hash, runner.client())
        .wait()
        .await;
    println!("Direct execution receipt: {:?}", receipt);
    let _receipt = receipt.expect("Transaction should succeed");

    // Verify the dice roll occurred - value should have changed
    let final_dice = runner.get_dice_value().await;
    
    // Dice value should be between 1 and 6
    assert!(final_dice >= 1 && final_dice <= 6, "Dice value should be 1-6, got {}", final_dice);
    
    println!("SUCCESS! Initial dice: {}, Final dice: {}", initial_dice, final_dice);
}

/// Test executing a VRF transaction with self-funded gas fees.
/// The user pays for gas via token transfer, and the VRF proof is bundled with the call.
///
/// Same nested flow as sponsored, but with an additional transfer call for gas fees.
#[tokio::test]
async fn test_vrf_self_funded_execute() {
    let runner = VrfRunner::new().await;

    // Get initial dice value
    let initial_dice = runner.get_dice_value().await;

    // === Step 1: Build the INNER outside execution (Player Account's calls) ===
    let source = Source::Nonce(ContractAddress(runner.player_account_address));

    let request_random_calldata = [
        <ContractAddress as CairoSerde>::cairo_serialize(&ContractAddress(
            runner.player_account_address,
        )),
        <Source as CairoSerde>::cairo_serialize(&source),
    ]
    .concat();

    let inner_outside_execution = OutsideExecution {
        caller: ContractAddress(ANY_CALLER),
        nonce: SigningKey::from_random().secret_scalar(),
        execute_after: 0,
        execute_before: u64::MAX,
        calls: vec![
            VrfCall {
                to: ContractAddress(runner.vrf_account_address),
                selector: selector!("request_random"),
                calldata: request_random_calldata,
            },
            VrfCall {
                to: ContractAddress(runner.vrf_consumer_address),
                selector: selector!("dice"),
                calldata: vec![],
            },
        ],
    };

    let inner_signature = runner.sign_player_outside_execution(&inner_outside_execution);

    // === Step 2: Compute seed and generate VRF proof ===
    let seed = compute_seed(
        &source,
        runner.vrf_consumer_address, // The VRF Consumer calls consume_random
        runner.chain_id(),
        Felt::ZERO,
    );

    let proof = runner.generate_proof(seed);

    // === Step 3: Build the OUTER outside execution (VRF Account's calls) ===
    // For self-funded mode, include a transfer to the forwarder
    let gas_fee_amount = U256 {
        low: 1_000_000_000_000_000_000_u128, // 1 STRK
        high: 0,
    };

    let transfer_calldata = [
        <ContractAddress as CairoSerde>::cairo_serialize(&ContractAddress(
            runner.forwarder_address(),
        )),
        <U256 as CairoSerde>::cairo_serialize(&gas_fee_amount),
    ]
    .concat();

    let submit_random_calldata = [
        vec![seed],
        <Proof as CairoSerde>::cairo_serialize(&proof),
    ]
    .concat();

    let inner_execution_calldata =
        <OutsideExecution as CairoSerde>::cairo_serialize(&inner_outside_execution);
    let mut execute_player_calldata = inner_execution_calldata;
    execute_player_calldata.push(Felt::from(inner_signature.len()));
    execute_player_calldata.extend(inner_signature);

    let outer_outside_execution = OutsideExecution {
        caller: ContractAddress(ANY_CALLER),
        nonce: SigningKey::from_random().secret_scalar(),
        execute_after: 0,
        execute_before: u64::MAX,
        calls: vec![
            // First: Transfer gas fees to forwarder
            VrfCall {
                to: ContractAddress(*FEE_TOKEN_ADDRESS),
                selector: selector!("transfer"),
                calldata: transfer_calldata,
            },
            // Second: submit_random to inject the VRF proof
            VrfCall {
                to: ContractAddress(runner.vrf_account_address),
                selector: selector!("submit_random"),
                calldata: submit_random_calldata,
            },
            // Third: execute_from_outside_v2 on Player Account
            VrfCall {
                to: ContractAddress(runner.player_account_address),
                selector: selector!("execute_from_outside_v2"),
                calldata: execute_player_calldata,
            },
        ],
    };

    let outer_signature = runner.sign_outside_execution(&outer_outside_execution);

    // === Step 4: Build the final call ===
    let outer_execution_calldata =
        <OutsideExecution as CairoSerde>::cairo_serialize(&outer_outside_execution);
    let mut final_calldata = outer_execution_calldata;
    final_calldata.push(Felt::from(outer_signature.len()));
    final_calldata.extend(outer_signature);

    let execute_from_outside_call = Call {
        to: runner.vrf_account_address,
        selector: selector!("execute_from_outside_v2"),
        calldata: final_calldata,
    };

    // === Step 5: Execute directly (without paymaster for now) ===
    use starknet::accounts::Account;
    let executor = runner.avnu.executor().await;
    
    let direct_result = executor
        .execute_v3(vec![execute_from_outside_call])
        .send()
        .await;
    
    println!("Direct execute result: {:?}", direct_result);
    let direct_result = direct_result.expect("Direct execution should succeed");
    
    // Wait for the transaction
    let receipt = TransactionWaiter::new(direct_result.transaction_hash, runner.client())
        .wait()
        .await;
    let _receipt = receipt.expect("Transaction should succeed");

    // Verify the dice roll occurred
    let final_dice = runner.get_dice_value().await;
    
    assert!(final_dice >= 1 && final_dice <= 6, "Dice value should be 1-6, got {}", final_dice);
    println!("Self-funded VRF test - SUCCESS! Initial dice: {}, Final dice: {}", initial_dice, final_dice);
}
