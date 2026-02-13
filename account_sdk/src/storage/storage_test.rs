#[cfg(test)]
mod tests {
    use crate::artifacts::Version;
    use crate::multi_chain::{ChainInfo, MultiChainMetadata};
    use crate::signers::{Owner, Signer};
    use crate::storage::inmemory::InMemoryBackend;
    use crate::storage::selectors::Selectors;
    use crate::storage::{
        clear_controller_storage, ActiveMetadata, StorageBackend, StorageError, StorageValue,
    };
    use crate::tests::runners::katana::KatanaRunner;
    use serde_json::json;
    use starknet::macros::felt;

    #[tokio::test]
    async fn test_storage_serialization_error() {
        let _app_id = "app_id".to_string();
        let runner = KatanaRunner::load();
        let mut controller = runner
            .deploy_controller(
                "username".to_string(),
                Owner::Signer(Signer::new_starknet_random()),
                Version::LATEST,
            )
            .await;

        // Create invalid JSON
        let corrupted_data = json!({
            "invalid_field": "invalid_value"
        })
        .to_string();

        // Store the corrupted data directly
        controller
            .storage
            .set_serialized(&Selectors::active(), &corrupted_data)
            .unwrap();

        // We want to test Controller::from_storage however it creates a new storage everytime, so instead we
        // test storage.controller to make sure it returns Serialization error
        let result = controller.storage.controller();
        assert!(matches!(result, Err(StorageError::Serialization(_))));
    }

    #[test]
    fn test_clear_controller_storage_is_scoped_and_updates_multi_chain_config() {
        let mut storage = InMemoryBackend::new();

        let address_a = felt!("0x111");
        let chain_a = felt!("0x1");
        let chain_a2 = felt!("0x2");
        let address_b = felt!("0x222");
        let chain_b = felt!("0x3");

        storage
            .set(
                &Selectors::account(&address_a, &chain_a),
                &StorageValue::String("account_a".to_string()),
            )
            .unwrap();
        storage
            .set(
                &Selectors::session(&address_a, &chain_a),
                &StorageValue::String("session_a".to_string()),
            )
            .unwrap();
        storage
            .set(
                &Selectors::deployment(&address_a, &chain_a),
                &StorageValue::String("deployment_a".to_string()),
            )
            .unwrap();

        storage
            .set(
                &Selectors::account(&address_a, &chain_a2),
                &StorageValue::String("account_a2".to_string()),
            )
            .unwrap();
        storage
            .set(
                "@cartridge/policies/0x111/0x1",
                &StorageValue::String("policies_a_chain_a".to_string()),
            )
            .unwrap();
        storage
            .set(
                "@cartridge/policies/0x222/0x3",
                &StorageValue::String("policies_b_chain_b".to_string()),
            )
            .unwrap();
        storage
            .set(
                "@cartridge/features",
                &StorageValue::String("features".to_string()),
            )
            .unwrap();
        storage
            .set(
                "@cartridge/https://x.cartridge.gg/active",
                &StorageValue::String("active-domain".to_string()),
            )
            .unwrap();
        storage
            .set(
                &Selectors::session(&address_a, &chain_a2),
                &StorageValue::String("session_a2".to_string()),
            )
            .unwrap();
        storage
            .set(
                &Selectors::deployment(&address_a, &chain_a2),
                &StorageValue::String("deployment_a2".to_string()),
            )
            .unwrap();

        storage
            .set(
                &Selectors::account(&address_b, &chain_b),
                &StorageValue::String("account_b".to_string()),
            )
            .unwrap();
        storage
            .set(
                &Selectors::session(&address_b, &chain_b),
                &StorageValue::String("session_b".to_string()),
            )
            .unwrap();
        storage
            .set(
                &Selectors::deployment(&address_b, &chain_b),
                &StorageValue::String("deployment_b".to_string()),
            )
            .unwrap();

        // Active points at A initially.
        storage
            .set(
                &Selectors::active(),
                &StorageValue::Active(ActiveMetadata {
                    address: address_a,
                    chain_id: chain_a,
                }),
            )
            .unwrap();

        // Multi-chain config includes both chains for A plus B.
        let cfg = MultiChainMetadata {
            username: "test_user".to_string(),
            chains: vec![
                ChainInfo {
                    chain_id: chain_a,
                    address: address_a,
                },
                ChainInfo {
                    chain_id: chain_a2,
                    address: address_a,
                },
                ChainInfo {
                    chain_id: chain_b,
                    address: address_b,
                },
            ],
        };
        let cfg_json = serde_json::to_string(&cfg).unwrap();
        storage
            .set(
                &Selectors::multi_chain_config(),
                &StorageValue::String(cfg_json),
            )
            .unwrap();

        clear_controller_storage(&mut storage, &address_a).unwrap();

        // A's entries are removed across all chains.
        assert!(storage
            .get(&Selectors::account(&address_a, &chain_a))
            .unwrap()
            .is_none());
        assert!(storage
            .get(&Selectors::session(&address_a, &chain_a))
            .unwrap()
            .is_none());
        assert!(storage
            .get(&Selectors::deployment(&address_a, &chain_a))
            .unwrap()
            .is_none());
        assert!(storage
            .get(&Selectors::account(&address_a, &chain_a2))
            .unwrap()
            .is_none());
        assert!(storage
            .get(&Selectors::session(&address_a, &chain_a2))
            .unwrap()
            .is_none());
        assert!(storage
            .get(&Selectors::deployment(&address_a, &chain_a2))
            .unwrap()
            .is_none());
        assert!(storage
            .get("@cartridge/policies/0x111/0x1")
            .unwrap()
            .is_none());
        assert!(storage
            .get("@cartridge/features")
            .unwrap()
            .is_none());
        assert!(storage
            .get("@cartridge/https://x.cartridge.gg/active")
            .unwrap()
            .is_none());

        // B's entries remain.
        assert!(storage
            .get(&Selectors::account(&address_b, &chain_b))
            .unwrap()
            .is_some());
        assert!(storage
            .get(&Selectors::session(&address_b, &chain_b))
            .unwrap()
            .is_some());
        assert!(storage
            .get(&Selectors::deployment(&address_b, &chain_b))
            .unwrap()
            .is_some());
        assert!(storage
            .get("@cartridge/policies/0x222/0x3")
            .unwrap()
            .is_some());

        // Active is removed because it pointed at A.
        assert!(storage.get(&Selectors::active()).unwrap().is_none());

        // Multi-chain config no longer includes A.
        match storage.get(&Selectors::multi_chain_config()).unwrap() {
            Some(StorageValue::String(cfg_json)) => {
                let cfg: MultiChainMetadata = serde_json::from_str(&cfg_json).unwrap();
                assert_eq!(cfg.chains.len(), 1);
                assert_eq!(cfg.chains[0].address, address_b);
                assert_eq!(cfg.chains[0].chain_id, chain_b);
            }
            other => panic!("unexpected multi-chain config storage value: {other:?}"),
        }
    }

    #[test]
    fn test_clear_controller_storage_does_not_remove_other_active_controller() {
        let mut storage = InMemoryBackend::new();

        let address_a = felt!("0x111");
        let chain_a = felt!("0x1");
        let chain_a2 = felt!("0x2");
        let address_b = felt!("0x222");
        let chain_b = felt!("0x3");

        storage
            .set(
                &Selectors::account(&address_a, &chain_a),
                &StorageValue::String("account_a".to_string()),
            )
            .unwrap();
        storage
            .set(
                &Selectors::account(&address_a, &chain_a2),
                &StorageValue::String("account_a2".to_string()),
            )
            .unwrap();
        storage
            .set(
                &Selectors::account(&address_b, &chain_b),
                &StorageValue::String("account_b".to_string()),
            )
            .unwrap();

        // Active points at B, so clearing A should not change it.
        storage
            .set(
                &Selectors::active(),
                &StorageValue::Active(ActiveMetadata {
                    address: address_b,
                    chain_id: chain_b,
                }),
            )
            .unwrap();

        clear_controller_storage(&mut storage, &address_a).unwrap();

        // A's entries are removed across all chains.
        assert!(storage
            .get(&Selectors::account(&address_a, &chain_a))
            .unwrap()
            .is_none());
        assert!(storage
            .get(&Selectors::account(&address_a, &chain_a2))
            .unwrap()
            .is_none());

        match storage.get(&Selectors::active()).unwrap() {
            Some(StorageValue::Active(active)) => {
                assert_eq!(active.address, address_b);
                assert_eq!(active.chain_id, chain_b);
            }
            other => panic!("unexpected active storage value: {other:?}"),
        }
    }
}
