use crate::abigen::controller::SignerSignature;
use crate::account::session::policy::Policy;
use crate::account::{AccountHashAndCallsSigner, CallEncoder};
use crate::constants::STRK_CONTRACT_ADDRESS;
use crate::errors::ControllerError;
use crate::execute_from_outside::FeeSource;
use crate::factory::ControllerFactory;
use crate::graphql::registration::register::register::{SessionInput, SignerInput};
use crate::graphql::registration::register::RegisterInput;
use crate::provider::CartridgeJsonRpcProvider;
use crate::signers::types::SignerType;
use crate::signers::Owner;
use crate::storage::{ControllerMetadata, Storage, StorageBackend, StorageError};
use crate::typed_data::hash_components;
use crate::{
    abigen::{self},
    signers::{HashSigner, SignError},
};
use crate::{find_error_message_in_execution_error, impl_account};
use async_trait::async_trait;
use cainome::cairo_serde::{CairoSerde, U256};
use chrono::Utc;
use starknet::accounts::{AccountDeploymentV3, AccountError, AccountFactory, ExecutionV3};
use starknet::core::types::{
    BlockTag, Call, FeeEstimate, FunctionCall, InvokeTransactionResult, StarknetError, TypedData,
};
use starknet::core::utils::{cairo_short_string_to_felt, parse_cairo_short_string};
use starknet::macros::{selector, short_string};
use starknet::providers::{Provider, ProviderError};
use starknet::signers::SignerInteractivityContext;
use starknet::{
    accounts::{Account, ConnectedAccount, ExecutionEncoder},
    core::types::{BlockId, Felt},
};
use starknet_crypto::poseidon_hash;
use url::Url;

#[cfg(all(test, not(target_arch = "wasm32")))]
#[path = "controller_test.rs"]
mod controller_test;

const SESSION_TYPED_DATA_MAGIC: Felt = short_string!("session-typed-data");

pub const DEFAULT_SESSION_EXPIRATION: u64 = 7 * 24 * 60 * 60;

#[derive(Clone)]
pub struct Controller {
    pub app_id: String,
    pub address: Felt,
    pub chain_id: Felt,
    pub class_hash: Felt,
    pub rpc_url: Url,
    pub username: String,
    pub(crate) salt: Felt,
    pub provider: CartridgeJsonRpcProvider,
    pub owner: Owner,
    contract: Option<Box<abigen::controller::Controller<Self>>>,
    factory: ControllerFactory,
    pub storage: Storage,
    nonce: Felt,
    pub(crate) execute_from_outside_nonce: (Felt, u128),
}

impl Controller {
    pub async fn new(
        app_id: String,
        username: String,
        class_hash: Felt,
        rpc_url: Url,
        owner: Owner,
        address: Felt,
    ) -> Result<Self, ControllerError> {
        Self::new_with_storage(app_id, username, class_hash, rpc_url, owner, address, None).await
    }

    pub async fn new_with_storage(
        app_id: String,
        username: String,
        class_hash: Felt,
        rpc_url: Url,
        owner: Owner,
        address: Felt,
        storage: Option<Storage>,
    ) -> Result<Self, ControllerError> {
        let provider = CartridgeJsonRpcProvider::new(rpc_url.clone());
        let chain_id = provider.chain_id().await?;
        let salt = cairo_short_string_to_felt(&username).unwrap();

        // Verify the address exists on-chain if it's already deployed
        // This helps catch misconfigurations early
        match provider
            .get_class_hash_at(
                starknet::core::types::BlockId::Tag(starknet::core::types::BlockTag::PreConfirmed),
                address,
            )
            .await
        {
            Ok(on_chain_class_hash) => {
                // Account exists on-chain, verify it has the expected class hash
                if on_chain_class_hash != class_hash {
                    return Err(ControllerError::InvalidResponseData(format!(
                        "Account at {} has class hash {} but expected {}",
                        address, on_chain_class_hash, class_hash
                    )));
                }
            }
            Err(_) => {
                // Account doesn't exist on-chain yet, which is fine for new accounts
                // They will be deployed later
            }
        }

        let factory = ControllerFactory::new(class_hash, chain_id, owner.clone(), provider.clone());

        let storage = storage.unwrap_or_default();

        let mut controller = Self {
            app_id: app_id.clone(),
            address,
            chain_id,
            class_hash,
            rpc_url,
            username: username.clone(),
            salt,
            provider,
            owner,
            contract: None,
            factory,
            storage: storage.clone(),
            nonce: Felt::ZERO,
            execute_from_outside_nonce: (
                starknet::signers::SigningKey::from_random().secret_scalar(),
                0,
            ),
        };

        let contract = Box::new(abigen::controller::Controller::new(
            address,
            controller.clone(),
        ));
        controller.contract = Some(contract);

        // Persist controller metadata immediately to prevent data loss
        controller
            .storage
            .set_controller(
                &app_id,
                &chain_id,
                address,
                ControllerMetadata::from(&controller),
            )
            .map_err(ControllerError::StorageError)?;

        // Clears the stored session if it's been revoked
        controller.clear_invalid_session();

        Ok(controller)
    }

    // This method exists for backward compatibility and persists immediately
    pub async fn new_with_existing_storage(
        app_id: String,
        username: String,
        class_hash: Felt,
        rpc_url: Url,
        owner: Owner,
        address: Felt,
    ) -> Result<Self, ControllerError> {
        // Just call the new method with no storage (will create default and persist)
        Self::new_with_storage(app_id, username, class_hash, rpc_url, owner, address, None).await
    }

    pub async fn new_headless(
        app_id: String,
        username: String,
        class_hash: Felt,
        rpc_url: Url,
        owner: Owner,
    ) -> Result<Self, ControllerError> {
        let provider = CartridgeJsonRpcProvider::new(rpc_url.clone());
        let chain_id = provider.chain_id().await?;

        let factory = ControllerFactory::new(class_hash, chain_id, owner.clone(), provider.clone());

        // Compute the controller address based on the generated signer and username
        let salt = starknet::core::utils::cairo_short_string_to_felt(&username).unwrap();
        let address = crate::factory::compute_account_address(class_hash, owner.clone(), salt);

        let mut controller = Self {
            app_id: app_id.clone(),
            address,
            chain_id,
            class_hash,
            rpc_url,
            username,
            salt,
            provider,
            owner,
            contract: None,
            factory,
            storage: Storage::default(),
            nonce: Felt::ZERO,
            execute_from_outside_nonce: (
                starknet::signers::SigningKey::from_random().secret_scalar(),
                0,
            ),
        };

        let contract = Box::new(abigen::controller::Controller::new(
            address,
            controller.clone(),
        ));
        controller.contract = Some(contract);

        controller
            .storage
            .set_controller(
                app_id.as_str(),
                &chain_id,
                address,
                ControllerMetadata::from(&controller),
            )
            .expect("Should store controller");

        // Clears the stored session if it's been revoked in a fire-and-forget style when the controller is created (with fromStorage for example).
        // Doing this eagerly prevents having to thread mutability/async through callers that only need an initialized controller.
        controller.clear_invalid_session();

        Ok(controller)
    }

    pub async fn signup(
        &mut self,
        signer_type: SignerType,
        session_expiration: Option<u64>,
        cartridge_api_url: Option<String>,
    ) -> Result<crate::graphql::registration::register::register::ResponseData, ControllerError>
    {
        let session_expiration = session_expiration
            .unwrap_or(Utc::now().timestamp() as u64 + DEFAULT_SESSION_EXPIRATION);

        let session = self.create_wildcard_session(session_expiration).await?;

        let register_input = RegisterInput {
            username: self.username.clone(),
            chain_id: parse_cairo_short_string(&self.chain_id)?,
            owner: SignerInput {
                type_: signer_type.into(),
                credential: self.owner.clone().try_into()?,
            },
            session: SessionInput {
                expires_at: session_expiration,
                allowed_policies_root: session.session.inner.allowed_policies_root,
                session_key_guid: session.session.inner.session_key_guid,
                guardian_key_guid: session.session.inner.guardian_key_guid,
                metadata_hash: session.session.inner.metadata_hash,
                authorization: session.session_authorization,
                app_id: Some(self.app_id.clone()),
            },
        };

        let register_result = crate::graphql::registration::register::register(
            register_input,
            cartridge_api_url.unwrap_or("https://x.cartridge.gg".to_string()),
        )
        .await?;

        Ok(register_result)
    }

    pub async fn from_storage(app_id: String) -> Result<Option<Self>, ControllerError> {
        let mut storage = Storage::default();
        let metadata = match storage.controller(&app_id) {
            Ok(metadata) => metadata,
            Err(StorageError::Serialization(_)) => {
                storage.clear().ok();
                return Ok(None);
            }
            Err(e) => {
                return Err(ControllerError::from(e));
            }
        };

        if let Some(m) = metadata {
            let rpc_url = Url::parse(&m.rpc_url).map_err(ControllerError::from)?;
            Ok(Some(
                Controller::new(
                    app_id,
                    m.username,
                    m.class_hash,
                    rpc_url,
                    m.owner.try_into()?,
                    m.address,
                )
                .await?,
            ))
        } else {
            Ok(None)
        }
    }

    pub fn deploy(&self) -> AccountDeploymentV3<'_, ControllerFactory> {
        self.factory.deploy_v3(self.salt)
    }

    pub fn disconnect(&mut self) -> Result<(), ControllerError> {
        self.storage.clear().map_err(ControllerError::from)
    }

    pub fn contract(&self) -> &abigen::controller::Controller<Self> {
        self.contract.as_ref().unwrap()
    }

    pub fn set_owner(&mut self, owner: Owner) {
        self.owner = owner;
    }

    pub fn owner_guid(&self) -> Felt {
        self.owner.clone().into()
    }

    async fn build_not_deployed_err(&self) -> ControllerError {
        let balance = match self.fee_balance().await {
            Ok(balance) => balance,
            Err(e) => return e,
        };

        let fee_estimate = match ControllerFactory::new(
            self.class_hash,
            self.chain_id,
            self.owner.clone(),
            self.provider.clone(),
        )
        .deploy_v3(self.salt)
        .estimate_fee()
        .await
        {
            Ok(estimate) => estimate,
            Err(e) => return ControllerError::from(e),
        };

        ControllerError::NotDeployed {
            fee_estimate: Box::new(fee_estimate),
            balance,
        }
    }

    pub async fn estimate_invoke_fee(
        &self,
        calls: Vec<Call>,
    ) -> Result<FeeEstimate, ControllerError> {
        let est = self
            .execute_v3(calls.clone())
            .nonce(Felt::from(u64::MAX))
            .gas_estimate_multiplier(1.5)
            .gas_price_estimate_multiplier(2.0)
            .estimate_fee()
            .await;

        let balance = self.fee_balance().await?;

        match est {
            Ok(fee_estimate) => {
                if fee_estimate.overall_fee > balance {
                    Err(ControllerError::InsufficientBalance {
                        fee_estimate: Box::new(fee_estimate),
                        balance,
                    })
                } else {
                    Ok(fee_estimate)
                }
            }
            Err(e) => {
                if let AccountError::Provider(ProviderError::StarknetError(
                    StarknetError::TransactionExecutionError(err_data),
                )) = &e
                {
                    // Check for specific error messages in the execution error (including nested errors)
                    if find_error_message_in_execution_error(
                        &err_data.execution_error,
                        "session/already-registered",
                    ) {
                        return Err(ControllerError::SessionAlreadyRegistered);
                    }

                    if find_error_message_in_execution_error(
                        &err_data.execution_error,
                        &format!("{:x} is not deployed.", self.address),
                    ) {
                        return Err(self.build_not_deployed_err().await);
                    }
                }
                Err(ControllerError::AccountError(e))
            }
        }
    }

    pub async fn execute(
        &mut self,
        calls: Vec<Call>,
        max_fee: Option<FeeEstimate>,
        fee_source: Option<FeeSource>,
    ) -> Result<InvokeTransactionResult, ControllerError> {
        if max_fee.is_none() {
            return self.execute_from_outside_v3(calls, fee_source).await;
        }

        let gas_estimate_multiplier = 1.5;
        let max_fee = max_fee.unwrap();
        let mut retry_count = 0;
        let max_retries = 1;

        // Compute resource bounds for all gas types
        let l1_gas = ((max_fee.l1_gas_consumed as f64) * gas_estimate_multiplier) as u64;
        let l2_gas = ((max_fee.l2_gas_consumed as f64) * gas_estimate_multiplier) as u64;
        let l1_data_gas = ((max_fee.l1_data_gas_consumed as f64) * gas_estimate_multiplier) as u64;

        loop {
            let nonce = self.get_nonce().await?;
            let result = self
                .execute_v3(calls.clone())
                .nonce(nonce)
                .l1_gas(l1_gas)
                .l1_gas_price(max_fee.l1_gas_price)
                .l2_gas(l2_gas)
                .l2_gas_price(max_fee.l2_gas_price)
                .l1_data_gas(l1_data_gas)
                .l1_data_gas_price(max_fee.l1_data_gas_price)
                .send()
                .await;

            match result {
                Ok(tx_result) => {
                    // Update nonce
                    self.nonce += Felt::ONE;

                    // Update is_registered to true after successful execution with a session
                    if let Some(metadata) =
                        self.authorized_session_for_policies(&Policy::from_calls(&calls), None)
                    {
                        if !metadata.is_registered {
                            let key = self.session_key();
                            let mut updated_metadata = metadata;
                            updated_metadata.is_registered = true;
                            self.storage.set_session(&key, updated_metadata)?;
                        }
                    }
                    return Ok(tx_result);
                }
                Err(e) => {
                    match &e {
                        AccountError::Provider(ProviderError::StarknetError(
                            StarknetError::TransactionExecutionError(err_data),
                        )) => {
                            // Check for specific error messages in the execution error (including nested errors)
                            if find_error_message_in_execution_error(
                                &err_data.execution_error,
                                &format!("{:x} is not deployed.", self.address),
                            ) {
                                return Err(self.build_not_deployed_err().await);
                            }
                        }
                        AccountError::Provider(ProviderError::StarknetError(
                            StarknetError::InvalidTransactionNonce(..),
                        )) => {
                            if retry_count < max_retries {
                                // Refetch nonce from the provider
                                let new_nonce = self
                                    .provider
                                    .get_nonce(self.block_id(), self.address())
                                    .await?;
                                self.nonce = new_nonce;
                                retry_count += 1;
                                continue;
                            }
                        }
                        AccountError::Provider(ProviderError::StarknetError(
                            StarknetError::ValidationFailure(data),
                        )) => {
                            if data.starts_with("Invalid transaction nonce of contract at address")
                                && retry_count < max_retries
                            {
                                // Refetch nonce from the provider
                                let new_nonce = self
                                    .provider
                                    .get_nonce(self.block_id(), self.address())
                                    .await?;
                                self.nonce = new_nonce;
                                retry_count += 1;
                                continue;
                            } else if data.contains(&format!("{:x} is not deployed.", self.address))
                            {
                                return Err(self.build_not_deployed_err().await);
                            }
                        }
                        _ => {}
                    }
                    return Err(ControllerError::AccountError(e));
                }
            }
        }
    }

    pub async fn delegate_account(&self) -> Result<Felt, ControllerError> {
        self.contract()
            .delegate_account()
            .call()
            .await
            .map(|address| address.into())
            .map_err(ControllerError::CairoSerde)
    }

    pub fn set_delegate_account(&self, delegate_address: Felt) -> ExecutionV3<Self> {
        self.contract()
            .set_delegate_account(&delegate_address.into())
    }

    pub async fn fee_balance(&self) -> Result<u128, ControllerError> {
        let address = self.address;
        let result = self
            .provider
            .call(
                FunctionCall {
                    contract_address: STRK_CONTRACT_ADDRESS,
                    entry_point_selector: selector!("balanceOf"),
                    calldata: vec![address],
                },
                BlockId::Tag(BlockTag::PreConfirmed),
            )
            .await
            .map_err(ControllerError::ProviderError)?;

        U256::cairo_deserialize(&result, 0)
            .map_err(ControllerError::CairoSerde)
            .map(|v| v.low)
    }

    pub fn is_session_expired(&self) -> bool {
        self.authorized_session()
            .map(|s| s.session.is_expired())
            .unwrap_or(true)
    }

    pub async fn ensure_valid_session(&mut self, expires_at: u64) -> Result<(), ControllerError> {
        if self.is_session_expired() {
            self.create_wildcard_session(expires_at).await?;
        }
        Ok(())
    }

    pub async fn sign_message(&self, data: &TypedData) -> Result<Vec<Felt>, SignError> {
        let hash_parts = hash_components(data)?;
        let scope_hash = poseidon_hash(hash_parts.domain_separator_hash, hash_parts.type_hash);

        match self.session_account(&[Policy::new_typed_data(scope_hash)]) {
            Some(session_account) => {
                let abi_detailed_typed_data = DetailedTypedData {
                    domain_hash: hash_parts.domain_separator_hash,
                    type_hash: hash_parts.type_hash,
                    params: hash_parts.encoded_fields,
                };
                let abi_typed_data = abigen::controller::TypedData {
                    scope_hash,
                    typed_data_hash: hash_parts.message_hash,
                };
                Ok([
                    vec![SESSION_TYPED_DATA_MAGIC],
                    Vec::<DetailedTypedData>::cairo_serialize(&vec![abi_detailed_typed_data]),
                    abigen::controller::SessionToken::cairo_serialize(
                        &session_account.sign_typed_data(&[abi_typed_data]).await?,
                    ),
                ]
                .concat())
            }
            _ => {
                let signature = self.owner.sign(&data.message_hash(self.address)?).await?;
                Ok(Vec::<SignerSignature>::cairo_serialize(&vec![signature]))
            }
        }
    }

    pub async fn switch_chain(&mut self, rpc_url: Url) -> Result<(), ControllerError> {
        let provider = CartridgeJsonRpcProvider::new(rpc_url.clone());
        self.provider = provider;
        self.rpc_url = rpc_url;
        self.chain_id = self
            .provider
            .chain_id()
            .await
            .map_err(ControllerError::from)?;

        self.storage
            .set_controller(
                self.app_id.as_str(),
                &self.chain_id,
                self.address,
                ControllerMetadata::from(&self.clone()),
            )
            .expect("Should store controller");

        Ok(())
    }

    async fn get_nonce(&self) -> Result<Felt, ProviderError> {
        let current_nonce = self.nonce;

        if current_nonce == Felt::ZERO {
            match self
                .provider
                .get_nonce(self.block_id(), self.address())
                .await
            {
                Ok(nonce) => Ok(nonce),
                Err(ProviderError::StarknetError(StarknetError::ContractNotFound)) => {
                    Ok(Felt::ZERO)
                }
                Err(e) => Err(e),
            }
        } else {
            Ok(current_nonce)
        }
    }
}

impl_account!(Controller, |account: &Controller, context| {
    if let SignerInteractivityContext::Execution { calls } = context {
        account
            .session_account(&Policy::from_calls(calls))
            .is_none()
    } else {
        true
    }
});

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl ConnectedAccount for Controller {
    type Provider = CartridgeJsonRpcProvider;

    fn provider(&self) -> &Self::Provider {
        &self.provider
    }

    fn block_id(&self) -> BlockId {
        BlockId::Tag(BlockTag::PreConfirmed)
    }

    async fn get_nonce(&self) -> Result<Felt, ProviderError> {
        self.get_nonce().await
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl AccountHashAndCallsSigner for Controller {
    async fn sign_hash_and_calls(
        &self,
        hash: Felt,
        calls: &[Call],
    ) -> Result<Vec<Felt>, SignError> {
        match self.session_account(&Policy::from_calls(calls)) {
            Some(session_account) => session_account.sign_hash_and_calls(hash, calls).await,
            _ => {
                let signature = self.owner.sign(&hash).await?;
                Ok(Vec::<SignerSignature>::cairo_serialize(&vec![signature]))
            }
        }
    }
}

impl ExecutionEncoder for Controller {
    fn encode_calls(&self, calls: &[Call]) -> Vec<Felt> {
        CallEncoder::encode_calls(calls)
    }
}

#[derive(Clone)]
struct DetailedTypedData {
    domain_hash: Felt,
    type_hash: Felt,
    params: Vec<Felt>,
}

impl CairoSerde for DetailedTypedData {
    type RustType = Self;

    fn cairo_serialize(rust: &Self::RustType) -> Vec<Felt> {
        let mut result = vec![rust.domain_hash, rust.type_hash, rust.params.len().into()];
        result.extend_from_slice(&rust.params);
        result
    }

    fn cairo_deserialize(
        _felts: &[Felt],
        _offset: usize,
    ) -> cainome_cairo_serde::Result<Self::RustType> {
        unimplemented!()
    }
}
