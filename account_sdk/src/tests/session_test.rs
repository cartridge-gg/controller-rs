use starknet::core::types::ExecutionResult;

use crate::{
    artifacts::Version,
    hash::MessageHashRev1,
    session::RevokableSession,
    signers::{Owner, Signer},
    tests::runners::katana::KatanaRunner,
    transaction_waiter::TransactionWaiter,
};

#[tokio::test]
pub async fn test_session_revokation() {
    let owner = Owner::Signer(Signer::new_starknet_random());
    let runner = KatanaRunner::load();
    let mut controller = runner
        .deploy_controller("username".to_owned(), owner.clone(), Version::LATEST)
        .await;

    let session = controller.create_session(vec![], u64::MAX).await.unwrap();

    let transaction_result = controller
        .revoke_sessions(vec![RevokableSession {
            chain_id: controller.chain_id,
            session_hash: session
                .session
                .inner
                .get_message_hash_rev_1(controller.chain_id, controller.address),
        }])
        .await
        .unwrap();

    let transaction_receipt =
        TransactionWaiter::new(transaction_result.transaction_hash, runner.client())
            .wait()
            .await
            .unwrap();

    assert_eq!(
        *transaction_receipt.receipt.execution_result(),
        ExecutionResult::Succeeded
    );
}

#[tokio::test]
pub async fn test_wildcard_session_creation() {
    let owner = Owner::Signer(Signer::new_starknet_random());
    let runner = KatanaRunner::load();
    let mut controller = runner
        .deploy_controller("username".to_owned(), owner.clone(), Version::LATEST)
        .await;

    // Test that wildcard session can be created
    let session = controller.create_wildcard_session(u64::MAX).await.unwrap();

    // Verify the session is a wildcard session (no specific policies)
    assert!(session.session.is_wildcard());

    // Verify the session is stored and can be retrieved
    let stored_session = controller.authorized_session();
    assert!(stored_session.is_some());
    assert!(stored_session.unwrap().is_wildcard());
}

#[tokio::test]
pub async fn test_no_wildcard_session_when_not_requested() {
    let owner = Owner::Signer(Signer::new_starknet_random());
    let runner = KatanaRunner::load();
    let controller = runner
        .deploy_controller("username".to_owned(), owner.clone(), Version::LATEST)
        .await;

    // Verify no session exists when wildcard session creation is skipped
    let stored_session = controller.authorized_session();
    assert!(stored_session.is_none());
}

#[tokio::test]
pub async fn test_login_with_wildcard_session_and_execute() {
    use crate::abigen::erc_20::Erc20;
    use crate::tests::account::FEE_TOKEN_ADDRESS;
    use cainome::cairo_serde::{ContractAddress, U256};
    use starknet::core::types::ExecutionResult;

    let owner = Owner::Signer(Signer::new_starknet_random());
    let runner = KatanaRunner::load();

    // Step 1: Deploy controller (simulating account creation)
    let mut controller = runner
        .deploy_controller("test_login_user".to_owned(), owner.clone(), Version::LATEST)
        .await;

    // Step 2: Create wildcard session (simulating login with create_wildcard_session=true)
    let session = controller.create_wildcard_session(u64::MAX).await.unwrap();

    // Verify session was created and stored
    assert!(session.session.is_wildcard());
    let stored_session = controller.authorized_session();
    assert!(stored_session.is_some());
    assert!(stored_session.unwrap().is_wildcard());

    // Step 3: Execute a transaction using the session
    // Transfer some tokens to test execution
    let recipient = ContractAddress(starknet_crypto::Felt::from(0x1234u64));
    let amount = U256 {
        low: 100u128,
        high: 0,
    };

    let erc20 = Erc20::new(*FEE_TOKEN_ADDRESS, &controller);
    let tx_result = erc20.transfer(&recipient, &amount).send().await.unwrap();

    // Wait for transaction and verify success
    let receipt = TransactionWaiter::new(tx_result.transaction_hash, runner.client())
        .wait()
        .await
        .unwrap();

    assert_eq!(
        *receipt.receipt.execution_result(),
        ExecutionResult::Succeeded
    );
}

#[tokio::test]
pub async fn test_login_without_session_can_still_execute() {
    use crate::abigen::erc_20::Erc20;
    use crate::tests::account::FEE_TOKEN_ADDRESS;
    use cainome::cairo_serde::{ContractAddress, U256};
    use starknet::core::types::ExecutionResult;

    let owner = Owner::Signer(Signer::new_starknet_random());
    let runner = KatanaRunner::load();

    // Step 1: Deploy controller (simulating account creation)
    let controller = runner
        .deploy_controller(
            "test_no_session_user".to_owned(),
            owner.clone(),
            Version::LATEST,
        )
        .await;

    // Step 2: Skip wildcard session creation (simulating login with create_wildcard_session=false)
    // No session is created - this simulates the register_session flow
    let stored_session = controller.authorized_session();
    assert!(stored_session.is_none());

    // Step 3: Execute a transaction using the owner directly (no session)
    let recipient = ContractAddress(starknet_crypto::Felt::from(0x5678u64));
    let amount = U256 {
        low: 50u128,
        high: 0,
    };

    let erc20 = Erc20::new(*FEE_TOKEN_ADDRESS, &controller);
    let tx_result = erc20.transfer(&recipient, &amount).send().await.unwrap();

    // Wait for transaction and verify success
    let receipt = TransactionWaiter::new(tx_result.transaction_hash, runner.client())
        .wait()
        .await
        .unwrap();

    assert_eq!(
        *receipt.receipt.execution_result(),
        ExecutionResult::Succeeded
    );
}
