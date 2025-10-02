use account_sdk::controller::Controller;
use account_sdk::errors::ControllerError;
use account_sdk::multi_chain::{ChainConfig, MultiChainController};
use serde_wasm_bindgen::to_value;
use starknet::core::types::Felt;
use starknet::providers::Provider;
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
    #[wasm_bindgen(js_name = create)]
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

        // Initialize policy storage with the first chain (policy storage will be per-controller)
        let first_chain_id = multi_controller
            .configured_chains()
            .into_iter()
            .next()
            .ok_or_else(|| JsError::new("No chains configured"))?;
        let first_controller = multi_controller
            .controller_for_chain(first_chain_id)
            .map_err(|e| JsError::new(&e.to_string()))?;

        let policy_storage =
            PolicyStorage::new(&first_controller.address, &app_id, &first_chain_id);

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

        if let Some(multi_controller) = multi_controller {
            // Initialize policy storage with the first chain
            let first_chain_id = multi_controller
                .configured_chains()
                .into_iter()
                .next()
                .ok_or_else(|| JsError::new("No chains configured"))?;
            let first_controller = multi_controller
                .controller_for_chain(first_chain_id)
                .map_err(|e| JsError::new(&e.to_string()))?;

            let policy_storage =
                PolicyStorage::new(&first_controller.address, &app_id, &first_chain_id);

            Ok(Some(Self {
                multi_controller: Rc::new(WasmMutex::new(multi_controller)),
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

    /// Gets an account instance for a specific chain
    #[wasm_bindgen(js_name = controller)]
    pub async fn controller(
        &self,
        chain_id: JsFelt,
    ) -> std::result::Result<Account, JsControllerError> {
        let chain_id_felt: Felt = chain_id.try_into()?;

        // Get the controller for this chain
        let multi_controller = self.multi_controller.lock().await;
        let controller = multi_controller.controller_for_chain(chain_id_felt)?;

        // Clone the controller to create an owned instance
        let controller_instance = controller.clone();
        drop(multi_controller); // Release the lock

        Ok(Account {
            controller: WasmMutex::new(controller_instance),
            policy_storage: Rc::clone(&self.policy_storage),
            cartridge_api_url: self.cartridge_api_url.clone(),
        })
    }
}

/// An account instance for a specific chain that provides direct access to operations
#[wasm_bindgen]
pub struct Account {
    controller: WasmMutex<Controller>,
    #[allow(dead_code)]
    policy_storage: Rc<WasmMutex<PolicyStorage>>,
    #[allow(dead_code)]
    cartridge_api_url: String,
}

#[wasm_bindgen]
impl Account {
    /// Get the chain ID this account operates on
    #[wasm_bindgen(js_name = chainId)]
    pub async fn chain_id(&self) -> std::result::Result<JsFelt, JsControllerError> {
        let controller = self.controller.lock().await;
        Ok(controller.chain_id.into())
    }

    /// Get the account address on this chain
    #[wasm_bindgen(js_name = address)]
    pub async fn address(&self) -> std::result::Result<JsFelt, JsControllerError> {
        let controller = self.controller.lock().await;
        Ok(controller.address.into())
    }

    /// Check if the account is deployed on this chain
    #[wasm_bindgen(js_name = isDeployed)]
    pub async fn is_deployed(&self) -> std::result::Result<bool, JsControllerError> {
        let controller = self.controller.lock().await;
        // Check if account is deployed by checking class hash at address
        match controller
            .provider
            .get_class_hash_at(
                starknet::core::types::BlockId::Tag(starknet::core::types::BlockTag::PreConfirmed),
                controller.address,
            )
            .await
        {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    /// Deploy the account on this chain
    #[wasm_bindgen(js_name = deploy)]
    pub async fn deploy(&self) -> std::result::Result<JsValue, JsControllerError> {
        let controller = self.controller.lock().await;
        let deployment = controller.deploy();

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

        let mut controller = self.controller.lock().await;
        let result = controller
            .execute(
                calls,
                max_fee.map(Into::into),
                fee_source.map(|fs| fs.try_into()).transpose()?,
            )
            .await?;

        Ok(to_value(&result)?)
    }

    /// Estimate fees for calls on this chain
    #[wasm_bindgen(js_name = estimateInvokeFee)]
    pub async fn estimate_invoke_fee(
        &self,
        calls: Vec<JsCall>,
    ) -> std::result::Result<JsFeeEstimate, JsControllerError> {
        let calls = calls
            .into_iter()
            .map(TryFrom::try_from)
            .collect::<std::result::Result<Vec<_>, _>>()?;

        let controller = self.controller.lock().await;
        let fee = controller.estimate_invoke_fee(calls).await?;
        Ok(fee.into())
    }

    /// Execute from outside v2
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

        let mut controller = self.controller.lock().await;
        let result = controller
            .execute_from_outside_v2(calls, fee_source.map(|fs| fs.try_into()).transpose()?)
            .await?;

        Ok(to_value(&result)?)
    }

    /// Execute from outside v3
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

        let mut controller = self.controller.lock().await;
        let result = controller
            .execute_from_outside_v3(calls, fee_source.map(|fs| fs.try_into()).transpose()?)
            .await?;

        Ok(to_value(&result)?)
    }
}

/// Metadata for displaying multi-chain information
#[wasm_bindgen]
pub struct MultiChainAccountMeta {
    app_id: String,
    username: String,
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
            chains: controller
                .configured_chains()
                .into_iter()
                .map(Into::into)
                .collect(),
        }
    }
}
