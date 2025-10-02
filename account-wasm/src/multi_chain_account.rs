use account_sdk::errors::ControllerError;
use account_sdk::multi_chain::{ChainConfig, MultiChainController};
use serde_wasm_bindgen::{from_value, to_value};
use starknet::core::types::Felt;
use std::rc::Rc;
use url::Url;
use wasm_bindgen::prelude::*;

use crate::errors::JsControllerError;
use crate::set_panic_hook;
use crate::storage::PolicyStorage;
use crate::sync::WasmMutex;
use crate::types::call::JsCall;
use crate::types::estimate::JsFeeEstimate;
use crate::types::owner::Owner;
use crate::types::{JsFeeSource, JsFelt};

pub type Result<T> = std::result::Result<T, JsError>;

/// JavaScript-friendly chain configuration
#[wasm_bindgen]
pub struct JsChainConfig {
    class_hash: JsFelt,
    rpc_url: String,
    owner: Owner,
    address: Option<JsFelt>,
}

#[wasm_bindgen]
impl JsChainConfig {
    #[wasm_bindgen(constructor)]
    pub fn new(class_hash: JsFelt, rpc_url: String, owner: Owner, address: Option<JsFelt>) -> Self {
        Self {
            class_hash,
            rpc_url,
            owner,
            address,
        }
    }

    #[wasm_bindgen(getter)]
    pub fn class_hash(&self) -> JsFelt {
        self.class_hash.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn rpc_url(&self) -> String {
        self.rpc_url.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn owner(&self) -> Owner {
        self.owner.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn address(&self) -> Option<JsFelt> {
        self.address.clone()
    }
}

impl TryFrom<JsChainConfig> for ChainConfig {
    type Error = JsError;

    fn try_from(config: JsChainConfig) -> Result<Self> {
        Ok(ChainConfig {
            class_hash: config.class_hash.try_into()?,
            rpc_url: Url::parse(&config.rpc_url)?,
            owner: config.owner.into(),
            address: config.address.map(|a| a.try_into()).transpose()?,
        })
    }
}

/// WASM bindings for MultiChainController
#[wasm_bindgen]
pub struct MultiChainAccount {
    multi_controller: Rc<WasmMutex<MultiChainController>>,
    policy_storage: Rc<WasmMutex<PolicyStorage>>,
    #[allow(dead_code)]
    cartridge_api_url: String,
}

#[wasm_bindgen]
impl MultiChainAccount {
    /// Creates a new MultiChainAccount with multiple chain configurations
    #[wasm_bindgen(js_name = createNew)]
    pub async fn new(
        app_id: String,
        username: String,
        chain_configs: Vec<JsChainConfig>,
        cartridge_api_url: String,
    ) -> Result<MultiChainAccount> {
        set_panic_hook();

        if chain_configs.is_empty() {
            return Err(JsError::new("At least one chain configuration is required"));
        }

        let username = username.to_lowercase();

        // Convert all JsChainConfigs to ChainConfigs
        let mut configs = Vec::new();
        for js_config in chain_configs {
            let config: ChainConfig = js_config.try_into()?;
            configs.push(config);
        }

        let multi_controller = MultiChainController::new(app_id.clone(), username.clone(), configs)
            .await
            .map_err(|e| JsError::new(&e.to_string()))?;

        // Initialize policy storage for the active chain
        let address = multi_controller
            .address()
            .map_err(|e| JsError::new(&e.to_string()))?;
        let chain_id = multi_controller
            .chain_id()
            .map_err(|e| JsError::new(&e.to_string()))?;

        let policy_storage = PolicyStorage::new(&address, &app_id, &chain_id);

        Ok(Self {
            multi_controller: Rc::new(WasmMutex::new(multi_controller)),
            policy_storage: Rc::new(WasmMutex::new(policy_storage)),
            cartridge_api_url,
        })
    }

    /// Loads a MultiChainAccount from storage
    #[wasm_bindgen(js_name = fromStorage)]
    pub async fn from_storage(
        app_id: String,
        cartridge_api_url: String,
    ) -> Result<Option<MultiChainAccount>> {
        set_panic_hook();

        let multi_controller = MultiChainController::from_storage(app_id.clone())
            .await
            .map_err(|e| JsError::new(&e.to_string()))?;

        if let Some(controller) = multi_controller {
            let address = controller
                .address()
                .map_err(|e| JsError::new(&e.to_string()))?;
            let chain_id = controller
                .chain_id()
                .map_err(|e| JsError::new(&e.to_string()))?;

            let policy_storage = PolicyStorage::new(&address, &app_id, &chain_id);

            Ok(Some(Self {
                multi_controller: Rc::new(WasmMutex::new(controller)),
                policy_storage: Rc::new(WasmMutex::new(policy_storage)),
                cartridge_api_url,
            }))
        } else {
            Ok(None)
        }
    }

    /// Adds a new chain configuration
    #[wasm_bindgen(js_name = addChain)]
    pub async fn add_chain(
        &self,
        config: JsChainConfig,
    ) -> std::result::Result<(), JsControllerError> {
        let chain_config: ChainConfig = config.try_into().map_err(|e: JsError| {
            JsControllerError::from(ControllerError::InvalidResponseData(format!(
                "Invalid chain config: {:?}",
                e
            )))
        })?;

        self.multi_controller
            .lock()
            .await
            .add_chain(chain_config)
            .await
            .map_err(JsControllerError::from)
    }

    /// Removes a chain configuration
    #[wasm_bindgen(js_name = removeChain)]
    pub async fn remove_chain(
        &self,
        chain_id: JsFelt,
    ) -> std::result::Result<(), JsControllerError> {
        let chain_id_felt: Felt = chain_id.try_into()?;

        self.multi_controller
            .lock()
            .await
            .remove_chain(chain_id_felt)
            .map_err(JsControllerError::from)
    }

    /// Switches to a different chain
    #[wasm_bindgen(js_name = switchChain)]
    pub async fn switch_chain(
        &self,
        chain_id: JsFelt,
    ) -> std::result::Result<(), JsControllerError> {
        let chain_id_felt: Felt = chain_id.try_into()?;

        let mut controller = self.multi_controller.lock().await;
        controller.switch_chain(chain_id_felt)?;

        // Update policy storage for the new active chain
        let address = controller.address()?;
        let app_id = controller.app_id.clone();
        let chain_id = controller.chain_id()?;

        *self.policy_storage.lock().await = PolicyStorage::new(&address, &app_id, &chain_id);

        Ok(())
    }

    /// Updates the RPC URL for a specific chain
    #[wasm_bindgen(js_name = updateChainRpc)]
    pub async fn update_chain_rpc(
        &self,
        chain_id: JsFelt,
        new_rpc_url: String,
    ) -> std::result::Result<(), JsControllerError> {
        let chain_id_felt: Felt = chain_id.try_into()?;
        let new_url = Url::parse(&new_rpc_url).map_err(|e| {
            JsControllerError::from(ControllerError::InvalidResponseData(format!(
                "Invalid RPC URL: {}",
                e
            )))
        })?;

        self.multi_controller
            .lock()
            .await
            .update_chain_rpc(chain_id_felt, new_url)
            .await
            .map_err(JsControllerError::from)
    }

    /// Gets the currently active chain ID
    #[wasm_bindgen(js_name = activeChain)]
    pub async fn active_chain(&self) -> JsFelt {
        let controller = self.multi_controller.lock().await;
        controller.active_chain.into()
    }

    /// Lists all configured chain IDs
    #[wasm_bindgen(js_name = configuredChains)]
    pub async fn configured_chains(&self) -> Vec<JsFelt> {
        let controller = self.multi_controller.lock().await;
        controller
            .configured_chains()
            .into_iter()
            .map(Into::into)
            .collect()
    }

    /// Gets a chain-specific account instance for direct operations
    #[wasm_bindgen(js_name = getChain)]
    pub fn get_chain(
        &self,
        chain_id: JsFelt,
    ) -> std::result::Result<ChainAccount, JsControllerError> {
        let chain_id_felt: Felt = chain_id.try_into()?;
        Ok(ChainAccount {
            chain_id: chain_id_felt,
            multi_controller: Rc::clone(&self.multi_controller),
            policy_storage: Rc::clone(&self.policy_storage),
        })
    }

    /// Gets the active chain account for direct operations
    #[wasm_bindgen(js_name = getActiveChain)]
    pub async fn get_active_chain(&self) -> ChainAccount {
        let controller = self.multi_controller.lock().await;
        let chain_id = controller.active_chain;
        drop(controller); // Release lock before creating ChainAccount

        ChainAccount {
            chain_id,
            multi_controller: Rc::clone(&self.multi_controller),
            policy_storage: Rc::clone(&self.policy_storage),
        }
    }

    /// Gets the address for the active chain
    #[wasm_bindgen(js_name = address)]
    pub async fn address(&self) -> std::result::Result<JsFelt, JsControllerError> {
        let controller = self.multi_controller.lock().await;
        let address = controller.address()?;
        Ok(address.into())
    }

    /// Gets the chain ID for the active chain
    #[wasm_bindgen(js_name = chainId)]
    pub async fn chain_id(&self) -> std::result::Result<JsFelt, JsControllerError> {
        let controller = self.multi_controller.lock().await;
        let chain_id = controller.chain_id()?;
        Ok(chain_id.into())
    }

    /// Executes calls on the active chain
    #[wasm_bindgen(js_name = execute)]
    pub async fn execute(
        &self,
        calls: Vec<JsCall>,
        max_fee: Option<JsFeeEstimate>,
        fee_source: Option<JsFeeSource>,
    ) -> std::result::Result<JsValue, JsControllerError> {
        set_panic_hook();

        let calls = calls
            .into_iter()
            .map(TryFrom::try_from)
            .collect::<std::result::Result<Vec<_>, _>>()?;

        let result = self
            .multi_controller
            .lock()
            .await
            .execute(
                calls,
                max_fee.map(Into::into),
                fee_source.map(|fs| fs.try_into()).transpose()?,
            )
            .await
            .map_err(JsControllerError::from)?;

        Ok(to_value(&result)?)
    }

    /// Estimates fee for calls on the active chain
    #[wasm_bindgen(js_name = estimateInvokeFee)]
    pub async fn estimate_invoke_fee(
        &self,
        calls: Vec<JsCall>,
    ) -> std::result::Result<JsFeeEstimate, JsControllerError> {
        set_panic_hook();

        let calls = calls
            .into_iter()
            .map(TryFrom::try_from)
            .collect::<std::result::Result<Vec<_>, _>>()?;

        let fee_estimate = self
            .multi_controller
            .lock()
            .await
            .estimate_invoke_fee(calls)
            .await?;

        Ok(fee_estimate.into())
    }

    // ============= Session Management Methods =============

    /// Get the active session for a specific chain
    #[wasm_bindgen(js_name = sessionForChain)]
    pub async fn session_for_chain(
        &self,
        chain_id: JsFelt,
    ) -> std::result::Result<JsValue, JsControllerError> {
        let chain_id_felt: Felt = chain_id.try_into()?;

        let controller = self.multi_controller.lock().await;
        let session = controller.session_for_chain(chain_id_felt)?;

        Ok(to_value(&session)?)
    }

    /// Create a session for a specific chain
    /// Returns the session account that can be used for execution
    #[wasm_bindgen(js_name = createSessionForChain)]
    pub async fn create_session_for_chain(
        &self,
        chain_id: JsFelt,
        policies: JsValue,
        expires_at: u64,
    ) -> std::result::Result<(), JsControllerError> {
        let chain_id_felt: Felt = chain_id.try_into()?;
        let policies = from_value(policies)?;

        let mut controller = self.multi_controller.lock().await;
        let _session = controller
            .create_session_for_chain(chain_id_felt, policies, expires_at)
            .await?;

        // SessionAccount is not serializable, just return success
        Ok(())
    }

    /// Register a session for a specific chain
    #[wasm_bindgen(js_name = registerSessionForChain)]
    pub async fn register_session_for_chain(
        &self,
        chain_id: JsFelt,
        policies: JsValue,
        expires_at: u64,
        public_key: JsFelt,
        guardian: JsFelt,
        max_fee: Option<JsFeeEstimate>,
    ) -> std::result::Result<JsValue, JsControllerError> {
        let chain_id_felt: Felt = chain_id.try_into()?;
        let public_key_felt: Felt = public_key.try_into()?;
        let guardian_felt: Felt = guardian.try_into()?;
        let policies = from_value(policies)?;

        let mut controller = self.multi_controller.lock().await;
        let result = controller
            .register_session_for_chain(
                chain_id_felt,
                policies,
                expires_at,
                public_key_felt,
                guardian_felt,
                max_fee.map(Into::into),
            )
            .await?;

        Ok(to_value(&result)?)
    }

    /// Revoke sessions for a specific chain
    #[wasm_bindgen(js_name = revokeSessionsForChain)]
    pub async fn revoke_sessions_for_chain(
        &self,
        chain_id: JsFelt,
        sessions: JsValue,
    ) -> std::result::Result<JsValue, JsControllerError> {
        let chain_id_felt: Felt = chain_id.try_into()?;
        let sessions = from_value(sessions)?;

        let mut controller = self.multi_controller.lock().await;
        let result = controller
            .revoke_sessions_for_chain(chain_id_felt, sessions)
            .await?;

        Ok(to_value(&result)?)
    }

    // ============= Deployment Status Methods =============

    /// Check if the account is deployed on a specific chain
    #[wasm_bindgen(js_name = isDeployedOnChain)]
    pub async fn is_deployed_on_chain(
        &self,
        chain_id: JsFelt,
    ) -> std::result::Result<bool, JsControllerError> {
        let chain_id_felt: Felt = chain_id.try_into()?;

        let controller = self.multi_controller.lock().await;
        let is_deployed = controller.is_deployed_on_chain(chain_id_felt).await?;

        Ok(is_deployed)
    }

    /// Deploy the account on a specific chain
    #[wasm_bindgen(js_name = deployOnChain)]
    pub async fn deploy_on_chain(
        &self,
        chain_id: JsFelt,
    ) -> std::result::Result<JsValue, JsControllerError> {
        let chain_id_felt: Felt = chain_id.try_into()?;

        let controller = self.multi_controller.lock().await;
        let deployment = controller.deploy_on_chain(chain_id_felt)?;

        // Send the deployment
        let result = deployment.send().await.map_err(|e| {
            JsControllerError::from(ControllerError::InvalidResponseData(format!(
                "Deployment failed: {:?}",
                e
            )))
        })?;

        Ok(to_value(&result)?)
    }

    /// Get deployment status for all chains
    #[wasm_bindgen(js_name = deploymentStatus)]
    pub async fn deployment_status(&self) -> std::result::Result<JsValue, JsControllerError> {
        let controller = self.multi_controller.lock().await;
        let status = controller.deployment_status().await;

        // Convert HashMap<Felt, bool> to a Vec of tuples for serialization
        let status_vec: Vec<(String, bool)> = status
            .into_iter()
            .map(|(chain_id, is_deployed)| (format!("{:#x}", chain_id), is_deployed))
            .collect();

        Ok(to_value(&status_vec)?)
    }

    // ============= Chain-Specific Execution Methods =============

    /// Execute a transaction on a specific chain
    #[wasm_bindgen(js_name = executeOnChain)]
    pub async fn execute_on_chain(
        &self,
        chain_id: JsFelt,
        calls: Vec<JsCall>,
        max_fee: Option<JsFeeEstimate>,
        fee_source: Option<JsFeeSource>,
    ) -> std::result::Result<JsValue, JsControllerError> {
        let chain_id_felt: Felt = chain_id.try_into()?;
        let calls = calls
            .into_iter()
            .map(TryFrom::try_from)
            .collect::<std::result::Result<Vec<_>, _>>()?;

        let mut controller = self.multi_controller.lock().await;
        let result = controller
            .execute_on_chain(
                chain_id_felt,
                calls,
                max_fee.map(Into::into),
                fee_source.map(|fs| fs.try_into()).transpose()?,
            )
            .await?;

        Ok(to_value(&result)?)
    }

    /// Estimate fees for a transaction on a specific chain
    #[wasm_bindgen(js_name = estimateFeesOnChain)]
    pub async fn estimate_fees_on_chain(
        &self,
        chain_id: JsFelt,
        calls: Vec<JsCall>,
    ) -> std::result::Result<JsFeeEstimate, JsControllerError> {
        let chain_id_felt: Felt = chain_id.try_into()?;
        let calls = calls
            .into_iter()
            .map(TryFrom::try_from)
            .collect::<std::result::Result<Vec<_>, _>>()?;

        let mut controller = self.multi_controller.lock().await;
        let fee = controller
            .estimate_fees_on_chain(chain_id_felt, calls)
            .await?;

        Ok(fee.into())
    }

    /// Execute a transaction from outside (v2) on a specific chain
    #[wasm_bindgen(js_name = executeFromOutsideV2OnChain)]
    pub async fn execute_from_outside_v2_on_chain(
        &self,
        chain_id: JsFelt,
        calls: Vec<JsCall>,
        fee_source: Option<JsFeeSource>,
    ) -> std::result::Result<JsValue, JsControllerError> {
        let chain_id_felt: Felt = chain_id.try_into()?;
        let calls = calls
            .into_iter()
            .map(TryFrom::try_from)
            .collect::<std::result::Result<Vec<_>, _>>()?;

        let mut controller = self.multi_controller.lock().await;
        let result = controller
            .execute_from_outside_v2_on_chain(
                chain_id_felt,
                calls,
                fee_source.map(|fs| fs.try_into()).transpose()?,
            )
            .await?;

        Ok(to_value(&result)?)
    }

    /// Execute a transaction from outside (v3) on a specific chain
    #[wasm_bindgen(js_name = executeFromOutsideV3OnChain)]
    pub async fn execute_from_outside_v3_on_chain(
        &self,
        chain_id: JsFelt,
        calls: Vec<JsCall>,
        fee_source: Option<JsFeeSource>,
    ) -> std::result::Result<JsValue, JsControllerError> {
        let chain_id_felt: Felt = chain_id.try_into()?;
        let calls = calls
            .into_iter()
            .map(TryFrom::try_from)
            .collect::<std::result::Result<Vec<_>, _>>()?;

        let mut controller = self.multi_controller.lock().await;
        let result = controller
            .execute_from_outside_v3_on_chain(
                chain_id_felt,
                calls,
                fee_source.map(|fs| fs.try_into()).transpose()?,
            )
            .await?;

        Ok(to_value(&result)?)
    }

    // ============= Chain Configuration Validation =============

    /// Validate a chain configuration before adding it
    #[wasm_bindgen(js_name = validateChainConfig)]
    pub async fn validate_chain_config(
        config: JsChainConfig,
    ) -> std::result::Result<(), JsControllerError> {
        let chain_config: ChainConfig = config.try_into().map_err(|e: JsError| {
            JsControllerError::from(ControllerError::InvalidResponseData(format!(
                "Invalid chain config: {:?}",
                e
            )))
        })?;

        MultiChainController::validate_chain_config(&chain_config).await?;

        Ok(())
    }

    // ============= Chain-Specific Signer Management =============

    /// Set the owner for a specific chain
    #[wasm_bindgen(js_name = setOwnerForChain)]
    pub async fn set_owner_for_chain(
        &self,
        chain_id: JsFelt,
        owner: Owner,
    ) -> std::result::Result<(), JsControllerError> {
        let chain_id_felt: Felt = chain_id.try_into()?;

        let mut controller = self.multi_controller.lock().await;
        controller.set_owner_for_chain(chain_id_felt, owner.into())?;

        Ok(())
    }

    /// Get the owner for a specific chain
    #[wasm_bindgen(js_name = getOwnerForChain)]
    pub async fn get_owner_for_chain(
        &self,
        chain_id: JsFelt,
    ) -> std::result::Result<Owner, JsControllerError> {
        let chain_id_felt: Felt = chain_id.try_into()?;

        let controller = self.multi_controller.lock().await;
        let owner = controller.get_owner_for_chain(chain_id_felt)?;

        // Convert the SDK Owner to WASM Owner
        Ok(owner.into())
    }

    /// Get the owner GUID for a specific chain
    #[wasm_bindgen(js_name = getOwnerGuidForChain)]
    pub async fn get_owner_guid_for_chain(
        &self,
        chain_id: JsFelt,
    ) -> std::result::Result<JsFelt, JsControllerError> {
        let chain_id_felt: Felt = chain_id.try_into()?;

        let controller = self.multi_controller.lock().await;
        let guid = controller.get_owner_guid_for_chain(chain_id_felt)?;

        Ok(guid.into())
    }
}

/// A chain-specific account that provides direct access to operations on that chain
#[wasm_bindgen]
pub struct ChainAccount {
    chain_id: Felt,
    multi_controller: Rc<WasmMutex<MultiChainController>>,
    #[allow(dead_code)]
    policy_storage: Rc<WasmMutex<PolicyStorage>>,
}

#[wasm_bindgen]
impl ChainAccount {
    /// Get the chain ID this account operates on
    #[wasm_bindgen(js_name = chainId)]
    pub fn chain_id(&self) -> JsFelt {
        self.chain_id.into()
    }

    /// Get the account address on this chain
    #[wasm_bindgen(js_name = address)]
    pub async fn address(&self) -> std::result::Result<JsFelt, JsControllerError> {
        let controller = self.multi_controller.lock().await;
        let chain_controller = controller.controller_for_chain(self.chain_id)?;
        Ok(chain_controller.address.into())
    }

    /// Check if the account is deployed on this chain
    #[wasm_bindgen(js_name = isDeployed)]
    pub async fn is_deployed(&self) -> std::result::Result<bool, JsControllerError> {
        let controller = self.multi_controller.lock().await;
        let is_deployed = controller.is_deployed_on_chain(self.chain_id).await?;
        Ok(is_deployed)
    }

    /// Deploy the account on this chain
    #[wasm_bindgen(js_name = deploy)]
    pub async fn deploy(&self) -> std::result::Result<JsValue, JsControllerError> {
        let controller = self.multi_controller.lock().await;
        let deployment = controller.deploy_on_chain(self.chain_id)?;

        // Send the deployment
        let result = deployment.send().await.map_err(|e| {
            JsControllerError::from(ControllerError::InvalidResponseData(format!(
                "Deployment failed: {:?}",
                e
            )))
        })?;

        Ok(to_value(&result)?)
    }

    /// Execute calls on this chain
    #[wasm_bindgen(js_name = execute)]
    pub async fn execute(
        &self,
        calls: Vec<JsCall>,
        max_fee: Option<JsFeeEstimate>,
        fee_source: Option<JsFeeSource>,
    ) -> std::result::Result<JsValue, JsControllerError> {
        let calls = calls
            .into_iter()
            .map(TryFrom::try_from)
            .collect::<std::result::Result<Vec<_>, _>>()?;

        let mut controller = self.multi_controller.lock().await;
        let result = controller
            .execute_on_chain(
                self.chain_id,
                calls,
                max_fee.map(Into::into),
                fee_source.map(|fs| fs.try_into()).transpose()?,
            )
            .await?;

        Ok(to_value(&result)?)
    }

    /// Estimate fees for calls on this chain
    #[wasm_bindgen(js_name = estimateFees)]
    pub async fn estimate_fees(
        &self,
        calls: Vec<JsCall>,
    ) -> std::result::Result<JsFeeEstimate, JsControllerError> {
        let calls = calls
            .into_iter()
            .map(TryFrom::try_from)
            .collect::<std::result::Result<Vec<_>, _>>()?;

        let mut controller = self.multi_controller.lock().await;
        let fee = controller
            .estimate_fees_on_chain(self.chain_id, calls)
            .await?;

        Ok(fee.into())
    }

    /// Get session for this chain
    #[wasm_bindgen(js_name = session)]
    pub async fn session(&self) -> std::result::Result<JsValue, JsControllerError> {
        let controller = self.multi_controller.lock().await;
        let session = controller.session_for_chain(self.chain_id)?;
        Ok(to_value(&session)?)
    }

    /// Create a session for this chain
    #[wasm_bindgen(js_name = createSession)]
    pub async fn create_session(
        &self,
        policies: JsValue,
        expires_at: u64,
    ) -> std::result::Result<(), JsControllerError> {
        let policies = from_value(policies)?;

        let mut controller = self.multi_controller.lock().await;
        let _session = controller
            .create_session_for_chain(self.chain_id, policies, expires_at)
            .await?;

        Ok(())
    }

    /// Register a session for this chain
    #[wasm_bindgen(js_name = registerSession)]
    pub async fn register_session(
        &self,
        policies: JsValue,
        expires_at: u64,
        public_key: JsFelt,
        guardian: JsFelt,
        max_fee: Option<JsFeeEstimate>,
    ) -> std::result::Result<JsValue, JsControllerError> {
        let public_key_felt: Felt = public_key.try_into()?;
        let guardian_felt: Felt = guardian.try_into()?;
        let policies = from_value(policies)?;

        let mut controller = self.multi_controller.lock().await;
        let result = controller
            .register_session_for_chain(
                self.chain_id,
                policies,
                expires_at,
                public_key_felt,
                guardian_felt,
                max_fee.map(Into::into),
            )
            .await?;

        Ok(to_value(&result)?)
    }

    /// Revoke sessions for this chain
    #[wasm_bindgen(js_name = revokeSessions)]
    pub async fn revoke_sessions(
        &self,
        sessions: JsValue,
    ) -> std::result::Result<JsValue, JsControllerError> {
        let sessions = from_value(sessions)?;

        let mut controller = self.multi_controller.lock().await;
        let result = controller
            .revoke_sessions_for_chain(self.chain_id, sessions)
            .await?;

        Ok(to_value(&result)?)
    }

    /// Execute from outside v2 on this chain
    #[wasm_bindgen(js_name = executeFromOutsideV2)]
    pub async fn execute_from_outside_v2(
        &self,
        calls: Vec<JsCall>,
        fee_source: Option<JsFeeSource>,
    ) -> std::result::Result<JsValue, JsControllerError> {
        let calls = calls
            .into_iter()
            .map(TryFrom::try_from)
            .collect::<std::result::Result<Vec<_>, _>>()?;

        let mut controller = self.multi_controller.lock().await;
        let result = controller
            .execute_from_outside_v2_on_chain(
                self.chain_id,
                calls,
                fee_source.map(|fs| fs.try_into()).transpose()?,
            )
            .await?;

        Ok(to_value(&result)?)
    }

    /// Execute from outside v3 on this chain
    #[wasm_bindgen(js_name = executeFromOutsideV3)]
    pub async fn execute_from_outside_v3(
        &self,
        calls: Vec<JsCall>,
        fee_source: Option<JsFeeSource>,
    ) -> std::result::Result<JsValue, JsControllerError> {
        let calls = calls
            .into_iter()
            .map(TryFrom::try_from)
            .collect::<std::result::Result<Vec<_>, _>>()?;

        let mut controller = self.multi_controller.lock().await;
        let result = controller
            .execute_from_outside_v3_on_chain(
                self.chain_id,
                calls,
                fee_source.map(|fs| fs.try_into()).transpose()?,
            )
            .await?;

        Ok(to_value(&result)?)
    }

    /// Get the owner for this chain
    #[wasm_bindgen(js_name = getOwner)]
    pub async fn get_owner(&self) -> std::result::Result<Owner, JsControllerError> {
        let controller = self.multi_controller.lock().await;
        let owner = controller.get_owner_for_chain(self.chain_id)?;
        Ok(owner.into())
    }

    /// Set the owner for this chain
    #[wasm_bindgen(js_name = setOwner)]
    pub async fn set_owner(&self, owner: Owner) -> std::result::Result<(), JsControllerError> {
        let mut controller = self.multi_controller.lock().await;
        controller.set_owner_for_chain(self.chain_id, owner.into())?;
        Ok(())
    }

    /// Get the owner GUID for this chain
    #[wasm_bindgen(js_name = getOwnerGuid)]
    pub async fn get_owner_guid(&self) -> std::result::Result<JsFelt, JsControllerError> {
        let controller = self.multi_controller.lock().await;
        let guid = controller.get_owner_guid_for_chain(self.chain_id)?;
        Ok(guid.into())
    }

    /// Update the RPC URL for this chain
    #[wasm_bindgen(js_name = updateRpc)]
    pub async fn update_rpc(
        &self,
        new_rpc_url: String,
    ) -> std::result::Result<(), JsControllerError> {
        let new_url = Url::parse(&new_rpc_url).map_err(|e| {
            JsControllerError::from(ControllerError::InvalidResponseData(format!(
                "Invalid RPC URL: {}",
                e
            )))
        })?;

        let mut controller = self.multi_controller.lock().await;
        controller.update_chain_rpc(self.chain_id, new_url).await?;
        Ok(())
    }
}

/// Metadata for displaying multi-chain information
#[wasm_bindgen]
pub struct MultiChainAccountMeta {
    app_id: String,
    username: String,
    active_chain: JsFelt,
    chains: Vec<JsFelt>,
}

#[wasm_bindgen]
impl MultiChainAccountMeta {
    #[wasm_bindgen(getter)]
    pub fn app_id(&self) -> String {
        self.app_id.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn username(&self) -> String {
        self.username.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn active_chain(&self) -> JsFelt {
        self.active_chain.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn chains(&self) -> Vec<JsFelt> {
        self.chains.clone()
    }
}

impl MultiChainAccount {
    /// Gets metadata about the multi-chain account
    pub async fn meta(&self) -> MultiChainAccountMeta {
        let controller = self.multi_controller.lock().await;
        MultiChainAccountMeta {
            app_id: controller.app_id.clone(),
            username: controller.username.clone(),
            active_chain: controller.active_chain.into(),
            chains: controller
                .configured_chains()
                .into_iter()
                .map(Into::into)
                .collect(),
        }
    }
}
