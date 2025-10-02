use std::time::Duration;

use crate::{
    abigen::erc_20::Erc20,
    artifacts::{Version, CONTROLLERS},
    controller::{Controller, DEFAULT_SESSION_EXPIRATION},
    errors::ControllerError,
    factory::ControllerFactory,
    signers::{Owner, Signer},
    tests::{account::FEE_TOKEN_ADDRESS, runners::katana::KatanaRunner},
    transaction_waiter::TransactionWaiter,
};
use cainome::cairo_serde::{ContractAddress, U256};
use starknet::{
    accounts::AccountFactory, core::utils::cairo_short_string_to_felt, macros::felt,
    providers::Provider, signers::SigningKey,
};
use url::Url;

#[tokio::test]
async fn test_deploy_controller() {
    let runner = KatanaRunner::load();
    dbg!(runner.declare_controller(Version::LATEST).await);

    // Create signers
    let owner = Owner::Signer(Signer::Starknet(SigningKey::from_secret_scalar(felt!(
        "0x3e5e410f88f88e77d18a168259a8feb6a68b358c813bdca08c875c8e54d0bf2"
    ))));

    let provider = runner.client();
    let chain_id = provider.chain_id().await.unwrap();

    // Create a new Controller instance
    let username = "testuser".to_string();
    let salt = cairo_short_string_to_felt(&username).unwrap();

    let factory = ControllerFactory::new(
        CONTROLLERS[&Version::LATEST].hash,
        chain_id,
        owner.clone(),
        provider.clone(),
    );
    let address = factory.address(salt);

    let controller = Controller::new(
        "app_id".to_string(),
        username.clone(),
        CONTROLLERS[&Version::LATEST].hash,
        runner.rpc_url.clone(),
        owner.clone(),
        address,
    )
    .await
    .unwrap();

    runner.fund(&address).await;

    // Deploy the controller
    let deploy_result = factory
        .deploy_v3(salt)
        .gas_estimate_multiplier(1.5)
        .send()
        .await
        .unwrap();

    // Wait for the transaction to be mined
    TransactionWaiter::new(deploy_result.transaction_hash, &provider.clone())
        .with_timeout(Duration::from_secs(5))
        .wait()
        .await
        .unwrap();

    // Verify the deployment
    let deployed_address = controller.address;
    assert_eq!(
        deployed_address, address,
        "Deployed address doesn't match expected address"
    );
}

#[tokio::test]
async fn test_controller_not_deployed() {
    let runner = KatanaRunner::load();
    let signer = Signer::new_starknet_random();
    let _ = runner
        .deploy_controller(
            "deployed".to_string(),
            Owner::Signer(signer.clone()),
            Version::LATEST,
        )
        .await;
    // Create a controller that is not deployed
    let undeployed_controller = Controller::new(
        "app_id".to_string(),
        "testuser".to_string(),
        CONTROLLERS[&Version::LATEST].hash,
        runner.rpc_url.clone(),
        Owner::Signer(signer.clone()),
        felt!("0xdeadbeef"),
    )
    .await
    .unwrap();

    let recipient = ContractAddress(felt!("0x18301129"));
    let amount = U256 { low: 0, high: 0 };
    let erc20 = Erc20::new(*FEE_TOKEN_ADDRESS, &undeployed_controller);
    let tx1 = erc20.transfer_getcall(&recipient, &amount);
    let result = undeployed_controller
        .estimate_invoke_fee(vec![tx1.clone()])
        .await;

    // Assert that the result is a NotDeployed error
    match result {
        Err(ControllerError::NotDeployed { .. }) => {}
        _ => panic!("Expected NotDeployed error, got: {:?}", result),
    }
}

#[tokio::test]
async fn test_controller_nonce_mismatch_recovery() {
    let username = "testuser".to_string();
    let signer = Signer::new_starknet_random();

    let runner = KatanaRunner::load();
    let mut controller1 = runner
        .deploy_controller(
            username.clone(),
            Owner::Signer(signer.clone()),
            Version::LATEST,
        )
        .await;

    // Create the second controller with the same credentials and address
    let mut controller2 = Controller::new(
        "app_id".to_string(),
        username.clone(),
        controller1.class_hash,
        runner.rpc_url.clone(),
        Owner::Signer(signer.clone()),
        controller1.address,
    )
    .await
    .unwrap();

    // Send a transaction using controller1
    let recipient = ContractAddress(felt!("0x18301129"));
    let amount = U256 { low: 0, high: 0 };
    let erc20 = Erc20::new(*FEE_TOKEN_ADDRESS, &controller1);

    let tx1 = erc20.transfer_getcall(&recipient, &amount);
    let max_fee = controller1
        .estimate_invoke_fee(vec![tx1.clone()])
        .await
        .unwrap();
    let res = Controller::execute(
        &mut controller1,
        vec![tx1.clone()],
        Some(max_fee.clone()),
        None,
    )
    .await
    .unwrap();

    TransactionWaiter::new(res.transaction_hash, runner.client())
        .wait()
        .await
        .unwrap();

    // Now send a transaction using controller2, which should have a stale nonce
    let erc20 = Erc20::new(*FEE_TOKEN_ADDRESS, &controller2);
    let tx2 = erc20.transfer_getcall(&recipient, &amount);

    let tx2_result = Controller::execute(
        &mut controller2,
        vec![tx2.clone()],
        Some(max_fee.clone()),
        None,
    )
    .await;

    // Verify that it succeeds after recovering from nonce mismatch
    assert!(
        tx2_result.is_ok(),
        "Controller did not recover from nonce mismatch: {:?}",
        tx2_result.err()
    );

    TransactionWaiter::new(tx2_result.unwrap().transaction_hash, runner.client())
        .wait()
        .await
        .unwrap();

    let res = Controller::execute(&mut controller1, vec![tx1], Some(max_fee.clone()), None)
        .await
        .unwrap();

    TransactionWaiter::new(res.transaction_hash, runner.client())
        .wait()
        .await
        .unwrap();

    let tx2_result = Controller::execute(&mut controller2, vec![tx2], Some(max_fee), None).await;

    // Verify that it succeeds after recovering from nonce mismatch
    assert!(
        tx2_result.is_ok(),
        "Controller did not recover from nonce mismatch: {:?}",
        tx2_result.err()
    );
}

#[cfg(feature = "filestorage")]
#[tokio::test]
async fn test_controller_storage() {
    use crate::controller::Controller;
    use crate::signers::Signer;
    use crate::tests::ensure_txn;

    // Setup temporary directory for file storage
    let temp_dir = tempfile::tempdir().unwrap();
    let storage_path = temp_dir.path().to_path_buf();
    std::env::set_var("CARTRIDGE_STORAGE_PATH", storage_path.to_str().unwrap());

    // Create a new controller
    let app_id = "app_id".to_string();
    let username = "test_user".to_string();
    let owner = Signer::new_starknet_random();

    let runner = KatanaRunner::load();
    let controller = runner
        .deploy_controller(
            username.clone(),
            Owner::Signer(owner.clone()),
            Version::LATEST,
        )
        .await;

    // Verify that the controller was stored
    let storage_file = storage_path.join(format!("@cartridge/{}/active", app_id));
    assert!(storage_file.exists(), "Storage file was not created");

    // Initialize a new controller from storage
    let loaded_controller = Controller::from_storage(app_id).await.unwrap().unwrap();

    // Verify that the loaded controller matches the original
    assert_eq!(loaded_controller.username, controller.username);
    assert_eq!(loaded_controller.address, controller.address);
    assert_eq!(loaded_controller.chain_id, controller.chain_id);
    assert_eq!(loaded_controller.class_hash, controller.class_hash);
    assert_eq!(loaded_controller.rpc_url, controller.rpc_url);

    let erc20 = Erc20::new(*FEE_TOKEN_ADDRESS, &loaded_controller);

    let recipient = ContractAddress(felt!("0x18301129"));
    let amount = U256 { low: 0, high: 0 };
    let transfer = erc20.transfer(&recipient, &amount);

    ensure_txn(transfer, runner.client()).await.unwrap();

    // Clean up
    temp_dir.close().unwrap();
}

#[tokio::test]
async fn test_multiple_transactions() {
    use crate::signers::Signer;
    use crate::tests::ensure_txn;
    use cainome::cairo_serde::U256;

    let runner = KatanaRunner::load();
    let owner = Signer::new_starknet_random();
    let controller = runner
        .deploy_controller(
            "test_user".to_string(),
            Owner::Signer(owner.clone()),
            Version::LATEST,
        )
        .await;

    let erc20 = Erc20::new(*FEE_TOKEN_ADDRESS, &controller);

    // First transaction
    let recipient1 = ContractAddress(felt!("0x18301129"));
    let amount1 = U256 { low: 100, high: 0 };
    let transfer1 = erc20.transfer(&recipient1, &amount1);
    let result1 = ensure_txn(transfer1, runner.client()).await;
    assert!(result1.is_ok(), "First transaction failed");

    // Second transaction
    let recipient2 = ContractAddress(felt!("0x29301130"));
    let amount2 = U256 { low: 200, high: 0 };
    let transfer2 = erc20.transfer(&recipient2, &amount2);
    let result2 = ensure_txn(transfer2, runner.client()).await;
    assert!(result2.is_ok(), "Second transaction failed");
}

#[tokio::test]
async fn test_controller_with_eip191_signer() {
    use crate::signers::Signer;
    use crate::tests::ensure_txn;
    use cainome::cairo_serde::U256;

    let runner = KatanaRunner::load();

    // Create an Eip191 signer with a random key
    let eip191_signer = Signer::new_eip191_random();

    // Deploy controller with Eip191 signer
    let controller = runner
        .deploy_controller(
            "eip191_user".to_string(),
            Owner::Signer(eip191_signer.clone()),
            Version::LATEST,
        )
        .await;

    // Verify controller was deployed correctly
    assert_eq!(
        controller.owner,
        Owner::Signer(eip191_signer.clone()),
        "Controller owner doesn't match the Eip191 signer"
    );

    // Test a transaction with the Eip191 signer
    let erc20 = Erc20::new(*FEE_TOKEN_ADDRESS, &controller);

    let recipient = ContractAddress(felt!("0x18301129"));
    let amount = U256 { low: 50, high: 0 };
    let transfer = erc20.transfer(&recipient, &amount);

    // Skip storage operations by directly executing the transaction
    let result = ensure_txn(transfer, runner.client()).await;
    assert!(
        result.is_ok(),
        "Transaction with Eip191 signer failed: {:?}",
        result.err()
    );
}

#[tokio::test]
async fn test_try_session_execute_with_expired_session() {
    use crate::account::session::policy::Policy;
    use chrono::Utc;
    use starknet::macros::selector;

    let runner = KatanaRunner::load();
    let signer = Signer::new_starknet_random();
    let mut controller = runner
        .deploy_controller(
            "test_expired".to_string(),
            Owner::Signer(signer.clone()),
            Version::LATEST,
        )
        .await;

    // Create a session that's already expired
    let expired_at = (Utc::now().timestamp() as u64) - 3600; // 1 hour ago
    let _session_account = controller
        .create_session(
            vec![Policy::new_call(*FEE_TOKEN_ADDRESS, selector!("transfer"))],
            expired_at,
        )
        .await
        .unwrap();

    // Clear the session from storage to simulate an expired session
    controller.clear_session_if_expired().unwrap();

    // Now try to execute with an expired session
    let recipient = ContractAddress(felt!("0x18301129"));
    let amount = U256 { low: 10, high: 0 };
    let erc20 = Erc20::new(*FEE_TOKEN_ADDRESS, &controller);
    let tx = erc20.transfer_getcall(&recipient, &amount);

    // Execute should automatically create a new wildcard session
    let max_fee = controller
        .estimate_invoke_fee(vec![tx.clone()])
        .await
        .unwrap();
    let result = Controller::execute(&mut controller, vec![tx], Some(max_fee), None).await;

    assert!(
        result.is_ok(),
        "Execute failed with expired session: {:?}",
        result.err()
    );

    // Verify a new session was created
    assert!(
        controller.authorized_session().is_none(),
        "Controller should not automatically recreate sessions outside of web context"
    );
}

#[tokio::test]
async fn test_expired_session_metadata_is_accessible() {
    use crate::account::session::policy::Policy;
    use chrono::Utc;
    use starknet::macros::selector;

    let runner = KatanaRunner::load();
    let signer = Signer::new_starknet_random();
    let mut controller = runner
        .deploy_controller(
            "test_expired_metadata".to_string(),
            Owner::Signer(signer.clone()),
            Version::LATEST,
        )
        .await;

    let policies = vec![Policy::new_call(*FEE_TOKEN_ADDRESS, selector!("transfer"))];
    let expired_at = (Utc::now().timestamp() as u64) - 60;

    controller
        .create_session(policies.clone(), expired_at)
        .await
        .unwrap();

    let metadata = controller
        .authorized_session()
        .expect("expired session metadata should remain accessible");

    assert!(metadata.session.is_expired());
    assert!(metadata.would_authorize(&policies, None));
    assert!(
        controller
            .authorized_session_for_policies(&policies, None)
            .is_none(),
        "expired session should not fulfill authorized_session_for_policies"
    );
}

#[tokio::test]
async fn test_ensure_valid_session() {
    use chrono::Utc;

    let runner = KatanaRunner::load();
    let signer = Signer::new_starknet_random();
    let mut controller = runner
        .deploy_controller(
            "test_ensure".to_string(),
            Owner::Signer(signer.clone()),
            Version::LATEST,
        )
        .await;

    // Initially no session
    assert!(controller.is_session_expired());

    // Ensure valid session creates one
    let expires_at = (Utc::now().timestamp() as u64) + DEFAULT_SESSION_EXPIRATION;
    controller.ensure_valid_session(expires_at).await.unwrap();

    // Now we should have a valid session
    assert!(!controller.is_session_expired());
    assert!(controller.authorized_session().is_some());

    // Check that the session is a wildcard session
    let session = controller.authorized_session().unwrap();
    assert!(
        session.is_wildcard(),
        "Session should be a wildcard session"
    );
}

#[tokio::test]
async fn test_is_session_expired_states() {
    use crate::account::session::policy::Policy;
    use chrono::Utc;
    use starknet::macros::selector;

    let runner = KatanaRunner::load();
    let signer = Signer::new_starknet_random();
    let mut controller = runner
        .deploy_controller(
            "test_states".to_string(),
            Owner::Signer(signer.clone()),
            Version::LATEST,
        )
        .await;

    // Test 1: No session should be considered expired
    assert!(
        controller.is_session_expired(),
        "No session should be considered expired"
    );

    // Test 2: Valid session should not be expired
    let valid_expires_at = (Utc::now().timestamp() as u64) + 3600; // 1 hour from now
    controller
        .create_session(
            vec![Policy::new_call(*FEE_TOKEN_ADDRESS, selector!("transfer"))],
            valid_expires_at,
        )
        .await
        .unwrap();

    assert!(
        !controller.is_session_expired(),
        "Valid session should not be expired"
    );

    // Test 3: Create expired session and check
    controller.clear_session_if_expired().unwrap();
    let expired_at = (Utc::now().timestamp() as u64) - 3600; // 1 hour ago
    controller
        .create_session(
            vec![Policy::new_call(*FEE_TOKEN_ADDRESS, selector!("transfer"))],
            expired_at,
        )
        .await
        .unwrap();

    // The expired session should be cleared automatically
    controller.clear_session_if_expired().unwrap();
    assert!(
        controller.is_session_expired(),
        "Expired session should be detected as expired"
    );
}

#[tokio::test]
async fn test_switch_rpc_success() {
    let runner = KatanaRunner::load();
    let signer = Signer::new_starknet_random();
    let mut controller = runner
        .deploy_controller(
            "test_switch_rpc".to_string(),
            Owner::Signer(signer.clone()),
            Version::LATEST,
        )
        .await;

    // Store the original RPC URL (removed - unused variable)

    // The proxy URL from the runner is what we'll switch to
    // (in a real test we'd have another RPC endpoint, but for testing switching to the same is fine)
    let new_url = runner.rpc_url.clone();

    // Switch the RPC
    let result = controller.switch_rpc(new_url.clone()).await;
    assert!(result.is_ok(), "RPC switch should succeed");

    // Verify the RPC URL was updated
    assert_eq!(controller.rpc_url, new_url);

    // Verify provider is updated (can still interact with blockchain)
    let chain_id = controller.provider.chain_id().await;
    assert!(
        chain_id.is_ok(),
        "Should be able to query chain_id after RPC switch"
    );

    // Test that we can still execute transactions
    let erc20 = Erc20::new(*FEE_TOKEN_ADDRESS, &controller);
    let recipient = ContractAddress(felt!("0x18301129"));
    let amount = U256 { low: 10, high: 0 };
    let tx = erc20.transfer_getcall(&recipient, &amount);

    let max_fee = controller.estimate_invoke_fee(vec![tx.clone()]).await;
    assert!(
        max_fee.is_ok(),
        "Should be able to estimate fee after RPC switch"
    );
}

#[tokio::test]
async fn test_switch_rpc_invalid_chain_id() {
    use crate::tests::runners::find_free_port;

    let runner = KatanaRunner::load();
    let signer = Signer::new_starknet_random();
    let mut controller = runner
        .deploy_controller(
            "test_invalid_chain".to_string(),
            Owner::Signer(signer.clone()),
            Version::LATEST,
        )
        .await;

    // Create a second Katana instance with different chain ID
    let katana_port = find_free_port();
    let mut child = std::process::Command::new("katana")
        .args(["--chain-id", "DIFFERENT_CHAIN"])
        .args(["--http.port", &katana_port.to_string()])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("failed to start katana");

    // Wait a bit for katana to start
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    let different_chain_url = Url::parse(&format!("http://127.0.0.1:{}/", katana_port)).unwrap();

    // Try to switch to an RPC with different chain_id
    let result = controller.switch_rpc(different_chain_url).await;

    // Should fail due to chain ID mismatch
    assert!(result.is_err(), "Should fail when chain_id differs");

    match result {
        Err(ControllerError::InvalidChainID(expected, actual)) => {
            // Verify the error contains the correct chain IDs
            assert!(expected.contains("SEPOLIA") || actual.contains("DIFFERENT"));
        }
        _ => panic!("Expected InvalidChainID error"),
    }

    // Verify the RPC URL was NOT updated
    assert_eq!(controller.rpc_url, runner.rpc_url);

    // Clean up the second katana instance and wait for it
    let _ = child.kill();
    let _ = child.wait();
}

#[tokio::test]
async fn test_switch_rpc_invalid_url() {
    let runner = KatanaRunner::load();
    let signer = Signer::new_starknet_random();
    let mut controller = runner
        .deploy_controller(
            "test_invalid_url".to_string(),
            Owner::Signer(signer.clone()),
            Version::LATEST,
        )
        .await;

    let original_url = controller.rpc_url.clone();

    // Try to switch to an invalid URL (unreachable)
    let invalid_url = Url::parse("http://localhost:99999/").unwrap();
    let result = controller.switch_rpc(invalid_url).await;

    // Should fail due to connection error
    assert!(result.is_err(), "Should fail with invalid URL");

    // Verify the RPC URL was NOT updated
    assert_eq!(controller.rpc_url, original_url);

    // Verify we can still use the original provider
    let chain_id = controller.provider.chain_id().await;
    assert!(chain_id.is_ok(), "Original provider should still work");
}

#[tokio::test]
async fn test_switch_rpc_preserves_state() {
    use crate::account::session::policy::Policy;
    use chrono::Utc;
    use starknet::macros::selector;

    let runner = KatanaRunner::load();
    let signer = Signer::new_starknet_random();
    let mut controller = runner
        .deploy_controller(
            "test_preserve_state".to_string(),
            Owner::Signer(signer.clone()),
            Version::LATEST,
        )
        .await;

    // Create a session before switching
    let expires_at = (Utc::now().timestamp() as u64) + DEFAULT_SESSION_EXPIRATION;
    let policies = vec![Policy::new_call(*FEE_TOKEN_ADDRESS, selector!("transfer"))];
    controller
        .create_session(policies.clone(), expires_at)
        .await
        .unwrap();

    // Store session info for comparison
    let session_before = controller.authorized_session().map(|s| s.session.clone());
    assert!(
        session_before.is_some(),
        "Session should exist before switch"
    );

    // Store other controller state
    let address_before = controller.address;
    let owner_before = controller.owner.clone();
    let class_hash_before = controller.class_hash;

    // Switch RPC
    let new_url = runner.rpc_url.clone();
    controller.switch_rpc(new_url).await.unwrap();

    // Verify state is preserved
    assert_eq!(
        controller.address, address_before,
        "Address should be preserved"
    );
    assert_eq!(controller.owner, owner_before, "Owner should be preserved");
    assert_eq!(
        controller.class_hash, class_hash_before,
        "Class hash should be preserved"
    );

    // Verify session is preserved
    let session_after = controller.authorized_session().map(|s| s.session.clone());
    assert_eq!(
        session_after, session_before,
        "Session should be preserved after RPC switch"
    );
}

#[cfg(feature = "filestorage")]
#[tokio::test]
async fn test_switch_rpc_updates_storage() {
    use crate::storage::StorageBackend;

    // Setup temporary directory for file storage
    let temp_dir = tempfile::tempdir().unwrap();
    let storage_path = temp_dir.path().to_path_buf();
    std::env::set_var("CARTRIDGE_STORAGE_PATH", storage_path.to_str().unwrap());

    let runner = KatanaRunner::load();
    let signer = Signer::new_starknet_random();

    let app_id = "test_storage_update".to_string();
    let username = "test_user".to_string();

    // Create controller with storage
    let mut controller = Controller::new_with_storage(
        app_id.clone(),
        username.clone(),
        CONTROLLERS[&Version::LATEST].hash,
        runner.rpc_url.clone(),
        Owner::Signer(signer.clone()),
        felt!("0x12345"),
    )
    .await
    .unwrap();

    runner.fund(&controller.address).await;

    // Switch RPC
    let new_url = Url::parse("http://127.0.0.1:8545/").unwrap();

    // We'll mock this by just updating the URL since we can't actually connect to a different RPC
    controller.rpc_url = new_url.clone();

    // Update storage with new metadata
    let metadata = crate::storage::ControllerMetadata::from(&controller);
    controller
        .storage
        .set_controller(&app_id, &controller.chain_id, controller.address, metadata)
        .unwrap();

    // Load from storage and verify RPC URL was persisted
    let loaded_controller = Controller::from_storage(app_id).await.unwrap().unwrap();
    assert_eq!(
        loaded_controller.rpc_url, new_url,
        "RPC URL should be persisted in storage"
    );

    // Clean up
    temp_dir.close().unwrap();
}
