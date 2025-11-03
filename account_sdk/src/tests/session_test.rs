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
            app_id: controller.app_id.clone(),
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
