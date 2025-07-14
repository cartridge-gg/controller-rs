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
