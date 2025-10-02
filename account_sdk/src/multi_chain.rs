use starknet::core::types::{Call, FeeEstimate, Felt, InvokeTransactionResult};
use starknet::core::utils::cairo_short_string_to_felt;
use std::collections::HashMap;
use url::Url;

use crate::{
    controller::Controller,
    errors::ControllerError,
    factory::compute_account_address,
    signers::Owner,
    storage::{ControllerMetadata, Storage, StorageBackend},
};

/// Configuration for a specific blockchain network
#[derive(Debug, Clone)]
pub struct ChainConfig {
    pub chain_id: Felt,
    pub class_hash: Felt,
    pub rpc_url: Url,
    pub owner: Owner,
    /// Optional address - will be computed if not provided
    pub address: Option<Felt>,
}

/// Manages multiple Controller instances across different chains
#[derive(Clone)]
pub struct MultiChainController {
    pub app_id: String,
    pub username: String,
    controllers: HashMap<Felt, Controller>,
    pub active_chain: Felt,
    pub storage: Storage,
}

impl MultiChainController {
    /// Creates a new MultiChainController with an initial chain configuration
    pub async fn new(
        app_id: String,
        username: String,
        initial_config: ChainConfig,
    ) -> Result<Self, ControllerError> {
        let mut controllers = HashMap::new();
        let chain_id = initial_config.chain_id;

        // Create the initial controller
        let controller = Self::create_controller(&app_id, &username, initial_config).await?;

        controllers.insert(chain_id, controller);

        Ok(Self {
            app_id,
            username,
            controllers,
            active_chain: chain_id,
            storage: Storage::default(),
        })
    }

    /// Creates a new Controller from a ChainConfig
    async fn create_controller(
        app_id: &str,
        username: &str,
        config: ChainConfig,
    ) -> Result<Controller, ControllerError> {
        // Compute address if not provided
        let address = match config.address {
            Some(addr) => addr,
            None => {
                let salt = cairo_short_string_to_felt(username)
                    .map_err(|e| ControllerError::InvalidResponseData(e.to_string()))?;
                compute_account_address(config.class_hash, config.owner.clone(), salt)
            }
        };

        Controller::new(
            app_id.to_string(),
            username.to_string(),
            config.class_hash,
            config.rpc_url,
            config.owner,
            address,
        )
        .await
    }

    /// Adds a new chain configuration
    pub async fn add_chain(&mut self, config: ChainConfig) -> Result<(), ControllerError> {
        if self.controllers.contains_key(&config.chain_id) {
            return Err(ControllerError::InvalidResponseData(format!(
                "Chain {} already exists",
                config.chain_id
            )));
        }

        let controller =
            Self::create_controller(&self.app_id, &self.username, config.clone()).await?;

        self.controllers.insert(config.chain_id, controller);

        // Update storage with new chain configuration
        self.update_storage()?;

        Ok(())
    }

    /// Removes a chain configuration
    pub fn remove_chain(&mut self, chain_id: Felt) -> Result<(), ControllerError> {
        if self.active_chain == chain_id {
            return Err(ControllerError::InvalidResponseData(
                "Cannot remove active chain".to_string(),
            ));
        }

        self.controllers.remove(&chain_id).ok_or_else(|| {
            ControllerError::InvalidResponseData(format!("Chain {} not found", chain_id))
        })?;

        // Update storage
        self.update_storage()?;

        Ok(())
    }

    /// Switches to a different chain
    pub fn switch_chain(&mut self, chain_id: Felt) -> Result<(), ControllerError> {
        if !self.controllers.contains_key(&chain_id) {
            return Err(ControllerError::InvalidResponseData(format!(
                "Chain {} not configured",
                chain_id
            )));
        }

        self.active_chain = chain_id;

        // Update storage with new active chain
        self.update_storage()?;

        Ok(())
    }

    /// Gets the currently active controller
    pub fn active_controller(&self) -> Result<&Controller, ControllerError> {
        self.controllers.get(&self.active_chain).ok_or_else(|| {
            ControllerError::InvalidResponseData("Active controller not found".to_string())
        })
    }

    /// Gets the currently active controller mutably
    pub fn active_controller_mut(&mut self) -> Result<&mut Controller, ControllerError> {
        self.controllers.get_mut(&self.active_chain).ok_or_else(|| {
            ControllerError::InvalidResponseData("Active controller not found".to_string())
        })
    }

    /// Gets a controller for a specific chain
    pub fn controller_for_chain(&self, chain_id: Felt) -> Result<&Controller, ControllerError> {
        self.controllers.get(&chain_id).ok_or_else(|| {
            ControllerError::InvalidResponseData(format!(
                "Controller for chain {} not found",
                chain_id
            ))
        })
    }

    /// Lists all configured chain IDs
    pub fn configured_chains(&self) -> Vec<Felt> {
        self.controllers.keys().copied().collect()
    }

    /// Updates the RPC URL for a specific chain
    pub async fn update_chain_rpc(
        &mut self,
        chain_id: Felt,
        new_rpc_url: Url,
    ) -> Result<(), ControllerError> {
        let controller = self.controllers.get_mut(&chain_id).ok_or_else(|| {
            ControllerError::InvalidResponseData(format!("Chain {} not configured", chain_id))
        })?;

        // Use the existing switch_rpc method
        controller.switch_rpc(new_rpc_url).await?;

        // Update storage
        self.update_storage()?;

        Ok(())
    }

    /// Updates storage with current configuration
    fn update_storage(&mut self) -> Result<(), ControllerError> {
        // Store metadata for each controller
        for (chain_id, controller) in &self.controllers {
            let metadata = ControllerMetadata::from(controller);
            self.storage
                .set_controller(&self.app_id, chain_id, controller.address, metadata)
                .map_err(ControllerError::StorageError)?;
        }

        // Store the active chain preference
        // This could be extended with a custom storage key for multi-chain state

        Ok(())
    }

    /// Loads a MultiChainController from storage
    pub async fn from_storage(app_id: String) -> Result<Option<Self>, ControllerError> {
        let storage = Storage::default();

        // For now, we'll need to implement a way to discover all stored chains
        // This is a simplified version that would need enhancement

        // Try to load the active controller first
        match storage.controller(&app_id) {
            Ok(Some(metadata)) => {
                // Create a controller from the metadata
                let rpc_url = Url::parse(&metadata.rpc_url)
                    .map_err(|e| ControllerError::InvalidResponseData(e.to_string()))?;

                let controller = Controller::new(
                    app_id.clone(),
                    metadata.username.clone(),
                    metadata.class_hash,
                    rpc_url,
                    metadata.owner.try_into()?,
                    metadata.address,
                )
                .await?;

                let mut controllers = HashMap::new();
                let chain_id = metadata.chain_id;
                controllers.insert(chain_id, controller);

                Ok(Some(Self {
                    app_id,
                    username: metadata.username,
                    controllers,
                    active_chain: chain_id,
                    storage,
                }))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(ControllerError::StorageError(e)),
        }
    }

    // Delegate common operations to the active controller

    pub async fn execute(
        &mut self,
        calls: Vec<Call>,
        max_fee: Option<FeeEstimate>,
        fee_source: Option<crate::execute_from_outside::FeeSource>,
    ) -> Result<InvokeTransactionResult, ControllerError> {
        let controller = self.active_controller_mut()?;
        Controller::execute(controller, calls, max_fee, fee_source).await
    }

    pub async fn estimate_invoke_fee(
        &self,
        calls: Vec<Call>,
    ) -> Result<FeeEstimate, ControllerError> {
        let controller = self.active_controller()?;
        controller.estimate_invoke_fee(calls).await
    }

    pub fn address(&self) -> Result<Felt, ControllerError> {
        let controller = self.active_controller()?;
        Ok(controller.address)
    }

    pub fn chain_id(&self) -> Result<Felt, ControllerError> {
        let controller = self.active_controller()?;
        Ok(controller.chain_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signers::Signer;
    use starknet::macros::{felt, short_string};

    #[tokio::test]
    async fn test_multi_chain_controller_creation() {
        let config = ChainConfig {
            chain_id: short_string!("SN_SEPOLIA"),
            class_hash: felt!("0x1234"),
            rpc_url: Url::parse("http://localhost:5050").unwrap(),
            owner: Owner::Signer(Signer::new_starknet_random()),
            address: Some(felt!("0xabcd")),
        };

        let multi_controller = MultiChainController::new(
            "test_app".to_string(),
            "test_user".to_string(),
            config.clone(),
        )
        .await;

        assert!(multi_controller.is_ok());
        let controller = multi_controller.unwrap();
        assert_eq!(controller.active_chain, config.chain_id);
        assert_eq!(controller.configured_chains().len(), 1);
    }

    #[tokio::test]
    async fn test_add_chain() {
        let initial_config = ChainConfig {
            chain_id: short_string!("SN_SEPOLIA"),
            class_hash: felt!("0x1234"),
            rpc_url: Url::parse("http://localhost:5050").unwrap(),
            owner: Owner::Signer(Signer::new_starknet_random()),
            address: Some(felt!("0xabcd")),
        };

        let mut multi_controller = MultiChainController::new(
            "test_app".to_string(),
            "test_user".to_string(),
            initial_config,
        )
        .await
        .unwrap();

        let new_config = ChainConfig {
            chain_id: short_string!("SN_MAIN"),
            class_hash: felt!("0x5678"),
            rpc_url: Url::parse("http://localhost:5051").unwrap(),
            owner: Owner::Signer(Signer::new_starknet_random()),
            address: Some(felt!("0xdef0")),
        };

        let result = multi_controller.add_chain(new_config).await;
        assert!(result.is_ok());
        assert_eq!(multi_controller.configured_chains().len(), 2);
    }

    #[tokio::test]
    async fn test_switch_chain() {
        let initial_config = ChainConfig {
            chain_id: short_string!("SN_SEPOLIA"),
            class_hash: felt!("0x1234"),
            rpc_url: Url::parse("http://localhost:5050").unwrap(),
            owner: Owner::Signer(Signer::new_starknet_random()),
            address: Some(felt!("0xabcd")),
        };

        let mut multi_controller = MultiChainController::new(
            "test_app".to_string(),
            "test_user".to_string(),
            initial_config,
        )
        .await
        .unwrap();

        let new_config = ChainConfig {
            chain_id: short_string!("SN_MAIN"),
            class_hash: felt!("0x5678"),
            rpc_url: Url::parse("http://localhost:5051").unwrap(),
            owner: Owner::Signer(Signer::new_starknet_random()),
            address: Some(felt!("0xdef0")),
        };

        multi_controller
            .add_chain(new_config.clone())
            .await
            .unwrap();

        let result = multi_controller.switch_chain(new_config.chain_id);
        assert!(result.is_ok());
        assert_eq!(multi_controller.active_chain, new_config.chain_id);
    }
}
