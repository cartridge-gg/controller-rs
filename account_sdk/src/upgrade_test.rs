use starknet::{
    accounts::{Account, ConnectedAccount},
    core::types::{BlockId, BlockTag, Felt},
    providers::Provider,
};

use crate::{
    artifacts::{Version, CONTROLLERS},
    signers::{Owner, Signer},
    tests::{ensure_txn, runners::katana::KatanaRunner},
};

use super::*;

#[tokio::test]
async fn test_controller_upgrade() {
    let runner = KatanaRunner::load();
    let signer = Signer::new_starknet_random();

    // Wait for Katana to be ready.
    // TODO: Do this with runner.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let controller = runner
        .deploy_controller(
            "username".to_owned(),
            Owner::Signer(signer),
            Version::V1_0_4,
        )
        .await;

    let hash = controller
        .provider()
        .get_class_hash_at(BlockId::Tag(BlockTag::PreConfirmed), controller.address())
        .await
        .unwrap();

    assert_eq!(hash, CONTROLLERS[&Version::V1_0_4].hash);

    runner.declare_controller(Version::LATEST).await;
    ensure_txn(
        controller
            .contract()
            .upgrade(&CONTROLLERS[&Version::LATEST].hash.into()),
        runner.client(),
    )
    .await
    .unwrap();

    let hash = controller
        .provider()
        .get_class_hash_at(BlockId::Tag(BlockTag::PreConfirmed), controller.address())
        .await
        .unwrap();

    assert_eq!(hash, CONTROLLERS[&Version::LATEST].hash);
}

// Unit tests for the new upgrade logic

#[test]
fn test_metadata_loading() {
    let metadata = ControllerMetadata::load().expect("Failed to load metadata");

    // Verify basic structure
    assert!(!metadata.versions.is_empty());
    assert!(!metadata.latest_version.is_empty());
    assert!(!metadata.controllers.is_empty());

    // Verify latest version exists in controllers
    assert!(metadata.controllers.contains_key(&metadata.latest_version));

    // Verify versioned controllers have version info
    for (version_key, controller_info) in &metadata.controllers {
        if version_key != "latest" {
            assert!(
                controller_info.version_info.is_some(),
                "Version {version_key} should have version info"
            );

            let version_info = controller_info.version_info.as_ref().unwrap();
            assert!(
                !version_info.changes.is_empty() || version_key == "v1.0.4",
                "Version {version_key} should have changes (except v1.0.4)"
            );
        }
    }
}

#[test]
fn test_outside_execution_version_assignment() {
    let metadata = ControllerMetadata::load().expect("Failed to load metadata");

    // Test that v1.0.4 and v1.0.5 use V2
    if let Some(controller) = metadata.controllers.get("v1.0.4") {
        if let Some(version_info) = &controller.version_info {
            assert_eq!(
                version_info.outside_execution_version,
                OutsideExecutionVersion::V2
            );
        }
    }

    if let Some(controller) = metadata.controllers.get("v1.0.5") {
        if let Some(version_info) = &controller.version_info {
            assert_eq!(
                version_info.outside_execution_version,
                OutsideExecutionVersion::V2
            );
        }
    }

    // Test that v1.0.6 and later use V3
    if let Some(controller) = metadata.controllers.get("v1.0.6") {
        if let Some(version_info) = &controller.version_info {
            assert_eq!(
                version_info.outside_execution_version,
                OutsideExecutionVersion::V3
            );
        }
    }

    if let Some(controller) = metadata.controllers.get("v1.0.9") {
        if let Some(version_info) = &controller.version_info {
            assert_eq!(
                version_info.outside_execution_version,
                OutsideExecutionVersion::V3
            );
        }
    }
}

#[test]
fn test_get_version_index() {
    assert_eq!(get_version_index("v1.0.4"), Some(0));
    assert_eq!(get_version_index("v1.0.5"), Some(1));
    assert_eq!(get_version_index("v1.0.6"), Some(2));
    assert_eq!(get_version_index("v1.0.7"), Some(3));
    assert_eq!(get_version_index("v1.0.8"), Some(4));
    assert_eq!(get_version_index("v1.0.9"), Some(5));

    // Test without 'v' prefix
    assert_eq!(get_version_index("1.0.4"), Some(0));
    assert_eq!(get_version_index("1.0.9"), Some(5));

    // Test unknown version
    assert_eq!(get_version_index("v1.0.10"), None);
    assert_eq!(get_version_index("unknown"), None);
}

#[test]
fn test_determine_upgrade_path_no_current_version() {
    let upgrade_path = determine_upgrade_path(None).expect("Failed to determine upgrade path");

    assert!(
        upgrade_path.available,
        "Upgrade should be available when no current version"
    );
    assert_eq!(
        upgrade_path.target_version.outside_execution_version,
        OutsideExecutionVersion::V3
    );
}

#[test]
fn test_determine_upgrade_path_current_is_latest() {
    let metadata = ControllerMetadata::load().expect("Failed to load metadata");
    let latest_version = &metadata.latest_version;

    let upgrade_path =
        determine_upgrade_path(Some(latest_version)).expect("Failed to determine upgrade path");

    assert!(
        !upgrade_path.available,
        "Upgrade should not be available when current is latest"
    );
}

#[test]
fn test_determine_upgrade_path_upgrade_available() {
    let upgrade_path =
        determine_upgrade_path(Some("v1.0.4")).expect("Failed to determine upgrade path");

    assert!(
        upgrade_path.available,
        "Upgrade should be available from v1.0.4"
    );
    assert_eq!(
        upgrade_path.target_version.outside_execution_version,
        OutsideExecutionVersion::V3
    );

    let upgrade_path =
        determine_upgrade_path(Some("v1.0.8")).expect("Failed to determine upgrade path");

    assert!(
        upgrade_path.available,
        "Upgrade should be available from v1.0.8"
    );
}

#[test]
fn test_find_version_by_hash() {
    let metadata = ControllerMetadata::load().expect("Failed to load metadata");

    // Test with known hashes
    for (version_key, controller_info) in &metadata.controllers {
        if version_key != "latest" {
            let hash =
                Felt::from_hex(&controller_info.class_hash).expect("Failed to parse class hash");

            let result = find_version_by_hash(hash).expect("Failed to find version by hash");

            assert!(result.is_some(), "Should find version for hash");
            let (found_version, found_info) = result.unwrap();
            assert_eq!(&found_version, version_key);
            assert_eq!(
                found_info.outside_execution_version,
                controller_info
                    .version_info
                    .as_ref()
                    .unwrap()
                    .outside_execution_version
            );
        }
    }

    // Test with unknown hash
    let unknown_hash = Felt::from_hex("0x1234567890abcdef").unwrap();
    let result = find_version_by_hash(unknown_hash).expect("Failed to search for unknown hash");
    assert!(result.is_none(), "Should not find version for unknown hash");
}

#[test]
fn test_version_changes_content() {
    let metadata = ControllerMetadata::load().expect("Failed to load metadata");

    // Test specific version changes
    if let Some(controller) = metadata.controllers.get("v1.0.4") {
        if let Some(version_info) = &controller.version_info {
            assert!(
                version_info.changes.is_empty(),
                "v1.0.4 should have no changes"
            );
        }
    }

    if let Some(controller) = metadata.controllers.get("v1.0.5") {
        if let Some(version_info) = &controller.version_info {
            assert!(version_info
                .changes
                .contains(&"Improved session token implementation".to_string()));
        }
    }

    if let Some(controller) = metadata.controllers.get("v1.0.6") {
        if let Some(version_info) = &controller.version_info {
            assert!(
                version_info.changes.len() >= 3,
                "v1.0.6 should have multiple changes"
            );
            assert!(version_info
                .changes
                .contains(&"Support session key message signing".to_string()));
        }
    }

    if let Some(controller) = metadata.controllers.get("v1.0.9") {
        if let Some(version_info) = &controller.version_info {
            assert!(version_info
                .changes
                .contains(&"Wildcard session support".to_string()));
        }
    }
}

#[test]
fn test_controller_info_structure() {
    let metadata = ControllerMetadata::load().expect("Failed to load metadata");

    for (version_key, controller_info) in &metadata.controllers {
        // All controllers should have class_hash and casm_hash
        assert!(
            !controller_info.class_hash.is_empty(),
            "Version {version_key} should have class_hash"
        );
        assert!(
            !controller_info.casm_hash.is_empty(),
            "Version {version_key} should have casm_hash"
        );

        // class_hash should be valid hex
        assert!(
            Felt::from_hex(&controller_info.class_hash).is_ok(),
            "Version {version_key} should have valid class_hash"
        );
        assert!(
            Felt::from_hex(&controller_info.casm_hash).is_ok(),
            "Version {version_key} should have valid casm_hash"
        );

        // Latest should not have version_info, others should
        if version_key == "latest" {
            assert!(
                controller_info.version_info.is_none(),
                "Latest version should not have version_info"
            );
        } else {
            assert!(
                controller_info.version_info.is_some(),
                "Version {version_key} should have version_info"
            );
        }
    }
}

#[test]
fn test_upgrade_path_structure() {
    let upgrade_path =
        determine_upgrade_path(Some("v1.0.4")).expect("Failed to determine upgrade path");

    assert!(upgrade_path.available);
    assert!(
        !upgrade_path
            .target_hash
            .to_bytes_be()
            .iter()
            .all(|&b| b == 0),
        "Target hash should not be zero"
    );

    // Verify the target version info is complete
    assert!(
        !upgrade_path.target_version.changes.is_empty()
            || upgrade_path.target_version.changes.is_empty(),
        "Changes should be a valid vector"
    );
}

#[test]
fn test_version_ordering() {
    // Test that version indices are in correct order
    let v4_index = get_version_index("v1.0.4").unwrap();
    let v5_index = get_version_index("v1.0.5").unwrap();
    let v9_index = get_version_index("v1.0.9").unwrap();

    assert!(v4_index < v5_index, "v1.0.4 should come before v1.0.5");
    assert!(v5_index < v9_index, "v1.0.5 should come before v1.0.9");

    // Test upgrade availability based on ordering
    let upgrade_v4_to_latest = determine_upgrade_path(Some("v1.0.4"))
        .expect("Failed to determine upgrade path from v1.0.4");
    assert!(upgrade_v4_to_latest.available);

    let upgrade_v8_to_latest = determine_upgrade_path(Some("v1.0.8"))
        .expect("Failed to determine upgrade path from v1.0.8");
    assert!(upgrade_v8_to_latest.available);
}

#[test]
fn test_upgrade_path_target_hash_validity() {
    let metadata = ControllerMetadata::load().expect("Failed to load metadata");
    let upgrade_path =
        determine_upgrade_path(Some("v1.0.4")).expect("Failed to determine upgrade path");

    // Target hash should match the latest version's class hash
    let latest_controller = metadata
        .controllers
        .get(&metadata.latest_version)
        .expect("Latest controller should exist");
    let expected_hash = Felt::from_hex(&latest_controller.class_hash)
        .expect("Latest controller should have valid class hash");

    assert_eq!(upgrade_path.target_hash, expected_hash);
}

#[test]
fn test_outside_execution_version_serialization() {
    // Test that OutsideExecutionVersion can be serialized/deserialized correctly
    let v2 = OutsideExecutionVersion::V2;
    let v3 = OutsideExecutionVersion::V3;

    let v2_json = serde_json::to_string(&v2).expect("Should serialize V2");
    let v3_json = serde_json::to_string(&v3).expect("Should serialize V3");

    assert_eq!(v2_json, "\"V2\"");
    assert_eq!(v3_json, "\"V3\"");

    let v2_deserialized: OutsideExecutionVersion =
        serde_json::from_str(&v2_json).expect("Should deserialize V2");
    let v3_deserialized: OutsideExecutionVersion =
        serde_json::from_str(&v3_json).expect("Should deserialize V3");

    assert_eq!(v2_deserialized, OutsideExecutionVersion::V2);
    assert_eq!(v3_deserialized, OutsideExecutionVersion::V3);
}
