use core::panic;

use starknet::{
    core::{
        types::{StarknetError, TypedData},
        utils::get_selector_from_name,
    },
    macros::{selector, short_string},
    providers::ProviderError,
};
use starknet_crypto::{poseidon_hash, poseidon_hash_many, Felt};

use crate::{
    abigen::controller::ControllerReader,
    account::session::{policy::Policy, TypedData as AbiTypedData},
    artifacts::Version,
    signers::{Owner, Signer},
    tests::runners::katana::KatanaRunner,
    typed_data::hash_components,
};

const SESSION_TYPED_DATA_MAGIC: Felt = short_string!("session-typed-data");

pub async fn test_verify_session_off_chain_sig(owner: Owner) {
    let runner = KatanaRunner::load();
    let mut controller = runner
        .deploy_controller("username".to_owned(), owner, Version::LATEST)
        .await;

    let typed_data = (0..10)
        .map(|i| AbiTypedData {
            scope_hash: get_selector_from_name(&format!("Type{}", i)).unwrap(),
            typed_data_hash: poseidon_hash_many([&Felt::from(i), &Felt::from(i)]),
        })
        .collect::<Vec<_>>();

    let policies = typed_data.iter().map(Policy::from).collect::<Vec<_>>();

    let session_account = controller
        .create_session(policies.clone(), u64::MAX)
        .await
        .unwrap();

    let signature = session_account.sign_typed_data(&typed_data).await.unwrap();
    let contract_reader = ControllerReader::new(controller.address, runner.client());
    contract_reader
        .is_session_signature_valid(&typed_data, &signature)
        .call()
        .await
        .unwrap();
}

#[tokio::test]
#[cfg(feature = "webauthn")]
async fn test_verify_session_off_chain_sig_webauthn() {
    let (signer, _) = crate::signers::webauthn::WebauthnSigner::register(
        "cartridge.gg".to_string(),
        "username".to_string(),
        "challenge".as_bytes(),
    )
    .await
    .unwrap();
    let signer = Signer::Webauthn(signer);

    test_verify_session_off_chain_sig(Owner::Signer(signer)).await;
}

#[tokio::test]
async fn test_verify_ession_off_chain_sig_starknet() {
    test_verify_session_off_chain_sig(Owner::Signer(Signer::new_starknet_random())).await;
}

#[tokio::test]
pub async fn test_verify_session_off_chain_sig_invalid_policy() {
    let owner = Owner::Signer(Signer::new_starknet_random());
    let runner = KatanaRunner::load();
    let mut controller = runner
        .deploy_controller("username".to_owned(), owner, Version::LATEST)
        .await;

    let typed_data = vec![
        AbiTypedData {
            scope_hash: selector!("Some type hash"),
            typed_data_hash: poseidon_hash_many([&Felt::ZERO, &Felt::ZERO]),
        },
        AbiTypedData {
            scope_hash: selector!("Some other type hash"),
            typed_data_hash: poseidon_hash_many([&Felt::ZERO, &Felt::ZERO]),
        },
    ];

    let policies = typed_data.iter().map(Policy::from).collect::<Vec<_>>();

    let session_account = controller
        .create_session(policies.clone(), u64::MAX)
        .await
        .unwrap();

    let mut signature = session_account.sign_typed_data(&typed_data).await.unwrap();
    dbg!(&signature);
    signature.proofs[0][0] += Felt::ONE;
    let contract_reader = ControllerReader::new(controller.address, runner.client());
    if let Err(cainome::cairo_serde::Error::Provider(ProviderError::StarknetError(
        StarknetError::ContractError(c),
    ))) = contract_reader
        .is_session_signature_valid(&typed_data, &signature)
        .call()
        .await
    {
        let error_msg = format!("{:?}", c.revert_error);
        assert!(error_msg.contains("session/policy-check-failed"))
    } else {
        panic!("Expected ContractErrorData");
    }
}

#[tokio::test]
pub async fn test_session_off_chain_sig_via_controller() {
    let owner = Owner::Signer(Signer::new_starknet_random());
    let runner = KatanaRunner::load();
    let mut controller = runner
        .deploy_controller("username".to_owned(), owner.clone(), Version::LATEST)
        .await;

    let typed_data = serde_json::from_str::<TypedData>(
        r###"{
  "types": {
    "StarknetDomain": [
      { "name": "name", "type": "shortstring" },
      { "name": "version", "type": "shortstring" },
      { "name": "chainId", "type": "shortstring" },
      { "name": "revision", "type": "shortstring" }
    ],
    "Person": [
      { "name": "name", "type": "felt" },
      { "name": "wallet", "type": "felt" }
    ],
    "Mail": [
      { "name": "from", "type": "Person" },
      { "name": "to", "type": "Person" },
      { "name": "contents", "type": "felt" }
    ]
  },
  "primaryType": "Mail",
  "domain": {
    "name": "StarkNet Mail",
    "version": "1",
    "chainId": "1",
    "revision": "1"
  },
  "message": {
    "from": {
      "name": "Cow",
      "wallet": "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826"
    },
    "to": {
      "name": "Bob",
      "wallet": "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"
    },
    "contents": "Hello, Bob!"
  }
}"###,
    )
    .unwrap();

    let hashes = hash_components(&typed_data).unwrap();
    let final_hash = typed_data.message_hash(controller.address).unwrap();
    controller
        .create_session(
            vec![Policy::new_typed_data(poseidon_hash(
                hashes.domain_separator_hash,
                hashes.type_hash,
            ))],
            u64::MAX,
        )
        .await
        .unwrap();

    let signature = controller.sign_message(&typed_data).await.unwrap();
    assert_eq!(signature[0], SESSION_TYPED_DATA_MAGIC);

    let contract_reader = ControllerReader::new(controller.address, runner.client());
    let is_valid = contract_reader
        .is_valid_signature(&final_hash, &signature)
        .call()
        .await
        .unwrap();

    assert_ne!(is_valid, Felt::ZERO);

    let mut wildcard_controller = runner
        .deploy_controller("wildcard".to_owned(), owner, Version::LATEST)
        .await;
    let wildcard_hash = typed_data
        .message_hash(wildcard_controller.address)
        .unwrap();

    wildcard_controller
        .create_wildcard_session(u64::MAX)
        .await
        .unwrap();

    let signature = wildcard_controller.sign_message(&typed_data).await.unwrap();
    assert_eq!(signature[0], SESSION_TYPED_DATA_MAGIC);

    let contract_reader = ControllerReader::new(wildcard_controller.address, runner.client());
    let is_valid = contract_reader
        .is_valid_signature(&wildcard_hash, &signature)
        .call()
        .await
        .unwrap();

    assert_ne!(is_valid, Felt::ZERO);
}
