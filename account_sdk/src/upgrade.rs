use serde::{Deserialize, Serialize};
use starknet::accounts::ConnectedAccount;
use starknet::core::types::{Call, InvokeTransactionResult};
use starknet::providers::Provider;
use starknet_crypto::Felt;
use std::collections::HashMap;

use crate::controller::Controller;
use crate::errors::ControllerError;
use crate::execute_from_outside::FeeSource;

#[cfg(all(test, not(target_arch = "wasm32")))]
#[path = "upgrade_test.rs"]
mod upgrade_test;

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum OutsideExecutionVersion {
    V2,
    V3,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ControllerVersionInfo {
    pub outside_execution_version: OutsideExecutionVersion,
    pub changes: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ControllerInfo {
    pub class_hash: String,
    pub casm_hash: String,
    #[serde(flatten)]
    pub version_info: Option<ControllerVersionInfo>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ControllerMetadata {
    pub versions: Vec<String>,
    pub latest_version: String,
    pub controllers: HashMap<String, ControllerInfo>,
}

#[derive(Clone, Debug)]
pub struct UpgradePath {
    pub available: bool,
    pub target_version: ControllerVersionInfo,
    pub target_hash: Felt,
}

impl ControllerMetadata {
    pub fn load() -> Result<Self, ControllerError> {
        let metadata_json = include_str!("../artifacts/metadata.json");
        serde_json::from_str(metadata_json)
            .map_err(|e| ControllerError::InvalidResponseData(e.to_string()))
    }
}

pub fn determine_upgrade_path(
    current_version_key: Option<&str>,
) -> Result<UpgradePath, ControllerError> {
    let metadata = ControllerMetadata::load()?;
    let target_version_key = &metadata.latest_version;

    let target_controller = metadata
        .controllers
        .get(target_version_key)
        .ok_or_else(|| {
            ControllerError::InvalidResponseData(format!(
                "Target controller version {target_version_key} not found"
            ))
        })?;

    let target_version_info = target_controller.version_info.as_ref().ok_or_else(|| {
        ControllerError::InvalidResponseData(format!(
            "Target version {target_version_key} has no version info"
        ))
    })?;

    let available = match current_version_key {
        Some(current) => {
            let current_index = get_version_index(current);
            let target_index = get_version_index(target_version_key);

            match (current_index, target_index) {
                (Some(current_idx), Some(target_idx)) => target_idx > current_idx,
                _ => false,
            }
        }
        None => true, // If no current version, upgrade is available
    };

    let target_hash = Felt::from_hex(&target_controller.class_hash)
        .map_err(|e| ControllerError::InvalidResponseData(format!("Invalid target hash: {e}")))?;

    Ok(UpgradePath {
        available,
        target_version: target_version_info.clone(),
        target_hash,
    })
}

pub fn find_version_by_hash(
    hash: Felt,
) -> Result<Option<(String, ControllerVersionInfo)>, ControllerError> {
    let metadata = ControllerMetadata::load()?;
    let hash_str = format!("{hash:#x}");

    for (version_key, controller_info) in metadata.controllers.iter() {
        if controller_info.class_hash == hash_str && version_key != "latest" {
            if let Some(version_info) = &controller_info.version_info {
                return Ok(Some((version_key.clone(), version_info.clone())));
            }
        }
    }

    Ok(None)
}

fn get_version_index(version: &str) -> Option<usize> {
    let version_without_prefix = version.strip_prefix('v').unwrap_or(version);
    let ordered_versions = ["1.0.4", "1.0.5", "1.0.6", "1.0.7", "1.0.8", "1.0.9"];
    ordered_versions
        .iter()
        .position(|&v| v == version_without_prefix)
}

impl Controller {
    pub fn upgrade(&self, new_class_hash: Felt) -> Call {
        self.contract().upgrade_getcall(&new_class_hash.into())
    }

    pub async fn current_version(
        &self,
    ) -> Result<Option<(String, ControllerVersionInfo)>, ControllerError> {
        let class_hash = self
            .provider
            .get_class_hash_at(self.block_id(), self.address)
            .await
            .map_err(ControllerError::ProviderError)?;

        find_version_by_hash(class_hash)
    }

    pub async fn check_upgrade_path(&self) -> Result<UpgradePath, ControllerError> {
        let current_version = self.current_version().await?;
        let current_version_key = current_version.as_ref().map(|(key, _)| key.as_str());
        determine_upgrade_path(current_version_key)
    }

    pub fn upgrade_to_target(&self, upgrade_path: &UpgradePath) -> Call {
        self.upgrade(upgrade_path.target_hash)
    }

    pub async fn execute_upgrade(
        &mut self,
        upgrade_calls: Vec<Call>,
        fee_source: Option<FeeSource>,
    ) -> Result<InvokeTransactionResult, ControllerError> {
        let current_version = self.current_version().await?;

        match current_version {
            Some((_, version_info)) => match version_info.outside_execution_version {
                OutsideExecutionVersion::V2 => {
                    self.execute_from_outside_v2(upgrade_calls, fee_source)
                        .await
                }
                OutsideExecutionVersion::V3 => {
                    self.execute_from_outside_v3(upgrade_calls, fee_source)
                        .await
                }
            },
            None => {
                self.execute_from_outside_v3(upgrade_calls, fee_source)
                    .await
            }
        }
    }
}
