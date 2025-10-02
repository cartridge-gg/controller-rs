use account_sdk::errors::ControllerError;
use account_sdk::multi_chain::{ChainConfig, MultiChainController};
use serde_wasm_bindgen::to_value;
use starknet::core::types::Felt;
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
    multi_controller: WasmMutex<MultiChainController>,
    policy_storage: WasmMutex<PolicyStorage>,
    #[allow(dead_code)]
    cartridge_api_url: String,
}

#[wasm_bindgen]
impl MultiChainAccount {
    /// Creates a new MultiChainAccount with an initial chain configuration
    #[wasm_bindgen(js_name = createNew)]
    pub async fn new(
        app_id: String,
        username: String,
        initial_config: JsChainConfig,
        cartridge_api_url: String,
    ) -> Result<MultiChainAccount> {
        set_panic_hook();

        let username = username.to_lowercase();
        let config: ChainConfig = initial_config.try_into()?;

        let multi_controller = MultiChainController::new(app_id.clone(), username.clone(), config)
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
            multi_controller: WasmMutex::new(multi_controller),
            policy_storage: WasmMutex::new(policy_storage),
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
                multi_controller: WasmMutex::new(controller),
                policy_storage: WasmMutex::new(policy_storage),
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
