use crate::{
    abigen::erc_20::Erc20,
    account::session::policy::Policy,
    artifacts::{Version, CONTROLLERS},
    controller::Controller,
    signers::{
        webauthn::WebauthnSigner, HashSigner, NewOwnerSigner, Owner, SessionPolicyError, SignError,
        Signer,
    },
    tests::{ensure_txn, runners::katana::KatanaRunner},
};
use cainome::cairo_serde::{ContractAddress, U256};
use starknet::{
    accounts::{Account, AccountError},
    macros::{felt, selector},
    providers::Provider,
};
use starknet_crypto::Felt;

use super::account::FEE_TOKEN_ADDRESS;

#[tokio::test]
async fn test_change_owner() {
    let signer = Signer::new_starknet_random();
    let owner = Owner::Signer(signer.clone());
    let runner = KatanaRunner::load();
    let controller = runner
        .deploy_controller("username".to_owned(), owner.clone(), Version::LATEST)
        .await;

    assert!(controller
        .contract()
        .is_owner(&owner.clone().into())
        .call()
        .await
        .unwrap());

    let new_signer = Signer::new_starknet_random();
    let new_signer_signature = new_signer
        .sign_new_owner(&controller.chain_id(), &controller.address())
        .await
        .unwrap();

    let add_owner = controller
        .contract()
        .add_owner_getcall(&new_signer.clone().into(), &new_signer_signature);
    let remove_owner = controller.contract().remove_owner_getcall(&signer.into());

    ensure_txn(
        controller.execute_v3(vec![add_owner, remove_owner]),
        runner.client(),
    )
    .await
    .unwrap();

    assert!(!controller
        .contract()
        .is_owner(&owner.into())
        .call()
        .await
        .unwrap());

    assert!(controller
        .contract()
        .is_owner(&new_signer.into())
        .call()
        .await
        .unwrap());
}

#[tokio::test]
async fn test_add_owner() {
    let signer = Signer::new_starknet_random();
    let runner = KatanaRunner::load();
    let mut controller = runner
        .deploy_controller(
            "username".to_owned(),
            Owner::Signer(signer.clone()),
            Version::LATEST,
        )
        .await;

    assert!(controller
        .contract()
        .is_owner(&signer.clone().into())
        .call()
        .await
        .unwrap());
    let new_signer = Signer::new_starknet_random();
    let new_signer_signature = new_signer
        .sign_new_owner(&controller.chain_id(), &controller.address())
        .await
        .unwrap();

    ensure_txn(
        controller
            .contract()
            .add_owner(&new_signer.clone().into(), &new_signer_signature),
        runner.client(),
    )
    .await
    .unwrap();

    assert!(controller
        .contract()
        .is_owner(&signer.clone().into())
        .call()
        .await
        .unwrap());

    assert!(controller
        .contract()
        .is_owner(&new_signer.clone().into())
        .call()
        .await
        .unwrap());

    controller.set_owner(Owner::Signer(new_signer.clone()));

    let new_new_signer = Signer::new_starknet_random();
    let new_signer_signature = new_new_signer
        .sign_new_owner(&controller.chain_id(), &controller.address())
        .await
        .unwrap();

    ensure_txn(
        controller
            .contract()
            .add_owner(&new_new_signer.clone().into(), &new_signer_signature),
        runner.client(),
    )
    .await
    .unwrap();

    assert!(controller
        .contract()
        .is_owner(&signer.into())
        .call()
        .await
        .unwrap());

    assert!(controller
        .contract()
        .is_owner(&new_signer.into())
        .call()
        .await
        .unwrap());

    assert!(controller
        .contract()
        .is_owner(&new_new_signer.into())
        .call()
        .await
        .unwrap());
}

#[tokio::test]
#[should_panic]
async fn test_change_owner_wrong_signature() {
    let signer = Signer::new_starknet_random();
    let runner = KatanaRunner::load();
    let controller = runner
        .deploy_controller(
            "username".to_owned(),
            Owner::Signer(signer.clone()),
            Version::LATEST,
        )
        .await;

    assert!(controller
        .contract()
        .is_owner(&signer.clone().into())
        .call()
        .await
        .unwrap());

    let new_signer = Signer::new_starknet_random();
    let old_guid = signer.into();

    // We sign the wrong thing thus the owner change should painc
    let new_signer_signature = (&new_signer as &dyn HashSigner)
        .sign(&old_guid)
        .await
        .unwrap();

    controller
        .contract()
        .add_owner(&new_signer.into(), &new_signer_signature)
        .gas_estimate_multiplier(1.5)
        .send()
        .await
        .unwrap();
}

#[tokio::test]
async fn test_change_owner_execute_after() {
    let signer = Signer::new_starknet_random();
    let runner = KatanaRunner::load();
    let mut controller = runner
        .deploy_controller(
            "username".to_owned(),
            Owner::Signer(signer.clone()),
            Version::LATEST,
        )
        .await;

    let new_signer = Signer::new_starknet_random();
    let new_signer_signature = new_signer
        .sign_new_owner(&controller.chain_id(), &controller.address())
        .await
        .unwrap();

    let add_owner = controller
        .contract()
        .add_owner_getcall(&new_signer.clone().into(), &new_signer_signature);
    let remove_owner = controller.contract().remove_owner_getcall(&signer.into());

    ensure_txn(
        controller.execute_v3(vec![add_owner, remove_owner]),
        runner.client(),
    )
    .await
    .unwrap();

    let recipient = felt!("0x18301129");
    let contract_erc20 = Erc20::new(*FEE_TOKEN_ADDRESS, &controller);

    // Old signature should fail
    let result = ensure_txn(
        contract_erc20.transfer(
            &ContractAddress(recipient),
            &U256 {
                low: 0x10_u128,
                high: 0,
            },
        ),
        runner.client(),
    )
    .await;

    assert!(result.is_err(), "Transaction should have failed");

    controller.set_owner(Owner::Signer(new_signer.clone()));

    let contract_erc20 = Erc20::new(*FEE_TOKEN_ADDRESS, &controller);

    ensure_txn(
        contract_erc20.transfer(
            &ContractAddress(recipient),
            &U256 {
                low: 0x10_u128,
                high: 0,
            },
        ),
        runner.client(),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn test_change_owner_invalidate_old_sessions() {
    let signer = Signer::new_starknet_random();
    let runner = KatanaRunner::load();
    let mut controller = runner
        .deploy_controller(
            "username".to_owned(),
            Owner::Signer(signer.clone()),
            Version::LATEST,
        )
        .await;

    let transfer_method = Policy::new_call(*FEE_TOKEN_ADDRESS, selector!("transfer"));

    let session_account = controller
        .create_session(vec![transfer_method.clone()], u64::MAX)
        .await
        .unwrap();

    let new_signer = Signer::new_starknet_random();

    let new_signer_signature = new_signer
        .sign_new_owner(&controller.chain_id(), &controller.address())
        .await
        .unwrap();

    let add_owner = controller
        .contract()
        .add_owner_getcall(&new_signer.clone().into(), &new_signer_signature);
    let remove_owner = controller.contract().remove_owner_getcall(&signer.into());

    ensure_txn(
        controller.execute_v3(vec![add_owner, remove_owner]),
        runner.client(),
    )
    .await
    .unwrap();

    let recipient = felt!("0x18301129");
    let contract_erc20 = Erc20::new(*FEE_TOKEN_ADDRESS, &session_account);

    // Old session should fail
    let result = ensure_txn(
        contract_erc20.transfer(
            &ContractAddress(recipient),
            &U256 {
                low: 0x10_u128,
                high: 0,
            },
        ),
        runner.client(),
    )
    .await;

    assert!(result.is_err(), "Transaction should have failed");

    let mut controller = Controller::new(
        "app_id".to_string(),
        "username".to_owned(),
        CONTROLLERS[&Version::LATEST].hash,
        runner.rpc_url.clone(),
        Owner::Signer(new_signer.clone()),
        controller.address(),
        runner.client().chain_id().await.unwrap(),
    );

    let session_account = controller
        .create_session(vec![transfer_method], u64::MAX)
        .await
        .unwrap();
    let contract_erc20 = Erc20::new(*FEE_TOKEN_ADDRESS, &session_account);

    // New session should work
    ensure_txn(
        contract_erc20.transfer(
            &ContractAddress(recipient),
            &U256 {
                low: 0x10_u128,
                high: 0,
            },
        ),
        runner.client(),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn test_call_unallowed_methods() {
    let (signer, _) = WebauthnSigner::register(
        "cartridge.gg".to_string(),
        "username".to_string(),
        "challenge".as_bytes(),
    )
    .await
    .unwrap();
    let signer = Signer::Webauthn(signer);

    let runner = KatanaRunner::load();
    let mut controller = runner
        .deploy_controller(
            "username".to_owned(),
            Owner::Signer(signer),
            Version::LATEST,
        )
        .await;

    let session_account = controller
        .create_session(
            vec![Policy::new_call(*FEE_TOKEN_ADDRESS, selector!("transfer"))],
            u64::MAX,
        )
        .await
        .unwrap();

    let contract = Erc20::new(*FEE_TOKEN_ADDRESS, &session_account);

    let address = ContractAddress(controller.address());
    let amount = U256 {
        high: 0,
        low: 0x10_u128,
    };

    // calling allowed method should succeed
    assert!(contract
        .transfer(&address, &amount)
        .gas_estimate_multiplier(1.5)
        .send()
        .await
        .is_ok());

    // Perform contract invocation that is not part of the allowed methods
    let error = contract
        .approve(&address, &amount)
        .gas_estimate_multiplier(1.5)
        .send()
        .await
        .unwrap_err();

    // calling unallowed method should fail with `SessionMethodNotAllowed` error
    let e @ AccountError::Signing(SignError::SessionPolicyNotAllowed(
        SessionPolicyError::MethodNotAllowed {
            selector,
            contract_address,
        },
    )) = error
    else {
        panic!("Expected `SessionMethodNotAllowed` error, got: {error:?}")
    };

    assert_eq!(selector!("approve"), selector);
    assert_eq!(contract.address, contract_address);
    assert!(e.to_string().contains("Not allowed to call method"));
}

#[tokio::test]
async fn test_external_owner() {
    let signer = Signer::new_starknet_random();
    let runner = KatanaRunner::load();
    let delegate_address = Felt::from_hex("0x1234").unwrap();
    let external_account = runner.executor().await;

    let controller = runner
        .deploy_controller(
            "username".to_owned(),
            Owner::Signer(signer),
            Version::LATEST,
        )
        .await;

    let external_controller =
        crate::abigen::controller::Controller::new(controller.address(), &external_account);

    // register_external_owner
    ensure_txn(
        controller
            .contract()
            .register_external_owner(&external_account.address().into()),
        runner.client(),
    )
    .await
    .unwrap();

    // external owner set_delegate_account
    ensure_txn(
        external_controller.set_delegate_account(&delegate_address.into()),
        runner.client(),
    )
    .await
    .unwrap();

    let delegate_account = controller.delegate_account().await;
    assert!(
        delegate_account.is_ok_and(|addr| addr == delegate_address),
        "should be delegate_address"
    );
}
