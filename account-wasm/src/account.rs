use std::borrow::BorrowMut;

use account_sdk::controller::Controller;
use account_sdk::errors::ControllerError;
use account_sdk::session::RevokableSession;
use account_sdk::storage::selectors::Selectors;
use account_sdk::storage::StorageBackend;

use account_sdk::transaction_waiter::TransactionWaiter;
use serde_wasm_bindgen::to_value;
use starknet::accounts::ConnectedAccount;
use starknet::core::types::{BlockId, BlockTag, Call, FeeEstimate, FunctionCall, TypedData};

use starknet::macros::selector;
use starknet::providers::Provider;
use starknet_types_core::felt::Felt;
use url::Url;
use wasm_bindgen::prelude::*;

use crate::errors::JsControllerError;
use crate::storage::PolicyStorage;
use crate::sync::WasmMutex;
use crate::types::call::JsCall;
use crate::types::estimate::JsFeeEstimate;
use crate::types::owner::Owner;
use crate::types::policy::{CallPolicy, Policy, TypedDataPolicy};
use crate::types::register::{JsRegister, JsRegisterResponse};
use crate::types::session::{AuthorizedSession, JsRevokableSession};
use crate::types::signer::{JsSignerInput, Signer};
use crate::types::{Felts, JsFeeSource, JsFelt};
use crate::utils::set_panic_hook;

type Result<T> = std::result::Result<T, JsError>;

#[wasm_bindgen]
pub struct CartridgeAccount {
    pub(super) controller: WasmMutex<Controller>,
    policy_storage: WasmMutex<PolicyStorage>,
    cartridge_api_url: String,
}

#[wasm_bindgen]
impl CartridgeAccount {
    /// Creates a new `CartridgeAccount` instance.
    ///
    /// # Parameters
    /// - `app_id`: Application identifier.
    /// - `rpc_url`: The URL of the JSON-RPC endpoint.
    /// - `chain_id`: Identifier of the blockchain network to interact with.
    /// - `address`: The blockchain address associated with the account.
    /// - `username`: Username associated with the account.
    /// - `owner`: A Owner struct containing the owner signer and associated data.
    ///
    #[allow(clippy::new_ret_no_self, clippy::too_many_arguments)]
    pub fn new(
        app_id: String,
        class_hash: JsFelt,
        rpc_url: String,
        chain_id: JsFelt,
        address: JsFelt,
        username: String,
        owner: Owner,
        cartridge_api_url: String,
    ) -> Result<CartridgeAccountWithMeta> {
        set_panic_hook();

        let rpc_url = Url::parse(&rpc_url)?;
        let username = username.to_lowercase();

        let controller = Controller::new(
            app_id,
            username.clone(),
            class_hash.try_into()?,
            rpc_url,
            owner.into(),
            address.try_into()?,
            chain_id.try_into()?,
        );

        Ok(CartridgeAccountWithMeta::new(controller, cartridge_api_url))
    }

    /// Creates a new `CartridgeAccount` instance with a randomly generated Starknet signer.
    /// The controller address is computed internally based on the generated signer.
    ///
    /// # Parameters
    /// - `app_id`: Application identifier.
    /// - `rpc_url`: The URL of the JSON-RPC endpoint.
    /// - `chain_id`: Identifier of the blockchain network to interact with.
    /// - `username`: Username associated with the account.
    ///
    #[allow(clippy::new_ret_no_self)]
    #[wasm_bindgen(js_name = newHeadless)]
    pub fn new_headless(
        app_id: String,
        class_hash: JsFelt,
        rpc_url: String,
        chain_id: JsFelt,
        username: String,
        cartridge_api_url: String,
    ) -> Result<CartridgeAccountWithMeta> {
        set_panic_hook();

        let rpc_url = Url::parse(&rpc_url)?;
        let username = username.to_lowercase();
        let class_hash_felt: Felt = class_hash.try_into()?;
        let chain_id_felt: Felt = chain_id.try_into()?;

        // Create a random Starknet signer
        let signing_key = starknet::signers::SigningKey::from_random();
        let owner = account_sdk::signers::Owner::Signer(account_sdk::signers::Signer::Starknet(
            signing_key,
        ));

        // Compute the controller address based on the generated signer and username
        let salt = starknet::core::utils::cairo_short_string_to_felt(&username).unwrap();
        let address =
            account_sdk::factory::compute_account_address(class_hash_felt, owner.clone(), salt);

        let controller = Controller::new(
            app_id,
            username.clone(),
            class_hash_felt,
            rpc_url,
            owner,
            address,
            chain_id_felt,
        );

        Ok(CartridgeAccountWithMeta::new(controller, cartridge_api_url))
    }

    #[wasm_bindgen(js_name = fromStorage)]
    pub fn from_storage(
        app_id: String,
        cartridge_api_url: String,
    ) -> Result<Option<CartridgeAccountWithMeta>> {
        set_panic_hook();

        let controller =
            Controller::from_storage(app_id).map_err(|e| JsError::new(&e.to_string()))?;

        Ok(controller.map(|c| CartridgeAccountWithMeta::new(c, cartridge_api_url)))
    }

    #[wasm_bindgen(js_name = disconnect)]
    pub async fn disconnect(&self) -> std::result::Result<(), JsControllerError> {
        self.controller
            .lock()
            .await
            .disconnect()
            .map_err(JsControllerError::from)
    }

    #[wasm_bindgen(js_name = registerSession)]
    pub async fn register_session(
        &self,
        policies: Vec<Policy>,
        expires_at: u64,
        public_key: JsFelt,
        max_fee: Option<JsFeeEstimate>,
    ) -> std::result::Result<JsValue, JsControllerError> {
        let methods = policies
            .into_iter()
            .map(TryFrom::try_from)
            .collect::<std::result::Result<Vec<_>, _>>()?;

        let max_fee = max_fee.map(Into::into);
        let res = self
            .controller
            .lock()
            .await
            .register_session(
                methods,
                expires_at,
                public_key.try_into()?,
                Felt::ZERO,
                max_fee,
            )
            .await
            .map_err(JsControllerError::from)?;

        Ok(to_value(&res)?)
    }

    #[wasm_bindgen(js_name = registerSessionCalldata)]
    pub async fn register_session_calldata(
        &self,
        policies: Vec<Policy>,
        expires_at: u64,
        public_key: JsFelt,
    ) -> std::result::Result<JsValue, JsControllerError> {
        let methods = policies
            .into_iter()
            .map(TryFrom::try_from)
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let call = self.controller.lock().await.register_session_call(
            methods,
            expires_at,
            public_key.try_into()?,
            Felt::ZERO,
        )?;

        Ok(to_value(&call.calldata)?)
    }

    #[wasm_bindgen(js_name = upgrade)]
    pub async fn upgrade(
        &self,
        new_class_hash: JsFelt,
    ) -> std::result::Result<JsCall, JsControllerError> {
        let felt: Felt = new_class_hash.try_into()?;
        let call = self.controller.lock().await.upgrade(felt);
        Ok(JsCall {
            contract_address: call.to.into(),
            entrypoint: "upgrade".to_string(),
            calldata: call.calldata.into_iter().map(Into::into).collect(),
        })
    }

    #[wasm_bindgen(js_name = login)]
    pub async fn login(
        &self,
        expires_at: u64,
        is_controller_registered: Option<bool>,
        signers: Option<Signer>,
    ) -> std::result::Result<AuthorizedSession, JsControllerError> {
        set_panic_hook();

        let mut controller = self.controller.lock().await;
        if let Some(signers) = signers {
            if let Some(webauthns) = signers.webauthns {
                let converted_webauthns: Vec<account_sdk::signers::webauthn::WebauthnSigner> =
                    webauthns
                        .into_iter()
                        .map(TryInto::try_into)
                        .collect::<std::result::Result<Vec<_>, _>>()?;

                controller.owner = account_sdk::signers::Owner::Signer(
                    account_sdk::signers::Signer::Webauthns(converted_webauthns),
                );
            }
        }

        let account = controller.create_wildcard_session(expires_at).await?;

        if is_controller_registered.unwrap_or(false) {
            let controller_response = controller
                .register_session_with_cartridge(
                    &account.session,
                    &account.session_authorization,
                    self.cartridge_api_url.clone(),
                )
                .await;

            if let Err(e) = controller_response {
                let address = controller.address;
                let app_id = controller.app_id.clone();
                let chain_id = controller.chain_id;

                controller
                    .storage
                    .remove(&Selectors::session(&address, &app_id, &chain_id))
                    .map_err(|e| JsControllerError::from(ControllerError::StorageError(e)))?;

                return Err(JsControllerError::from(e));
            }
        }

        let session_metadata = AuthorizedSession {
            session: account.session.clone().into(),
            authorization: Some(
                account
                    .session_authorization
                    .clone()
                    .into_iter()
                    .map(Into::into)
                    .collect(),
            ),
            is_registered: false,
            expires_at: account.session.inner.expires_at,
            allowed_policies_root: account.session.inner.allowed_policies_root.into(),
            metadata_hash: account.session.inner.metadata_hash.into(),
            session_key_guid: account.session.inner.session_key_guid.into(),
            guardian_key_guid: account.session.inner.guardian_key_guid.into(),
        };

        Ok(session_metadata)
    }

    #[wasm_bindgen(js_name = register)]
    pub async fn register(
        &self,
        register: JsRegister,
    ) -> std::result::Result<JsRegisterResponse, JsControllerError> {
        set_panic_hook();

        let register: account_sdk::graphql::registration::register::RegisterInput = register.into();

        let res = account_sdk::graphql::registration::register::register(
            register,
            self.cartridge_api_url.clone(),
        )
        .await?;

        Ok(res.into())
    }

    #[wasm_bindgen(js_name = createSession)]
    pub async fn create_session(
        &self,
        policies: Vec<Policy>,
        expires_at: u64,
    ) -> std::result::Result<Option<AuthorizedSession>, JsControllerError> {
        set_panic_hook();

        let mut controller = self.controller.lock().await;

        let wildcard_exists = controller
            .authorized_session()
            .filter(|session| session.is_wildcard())
            .is_some();

        let session = if !wildcard_exists {
            let account = controller.create_wildcard_session(expires_at).await?;

            let controller_response = controller
                .register_session_with_cartridge(
                    &account.session,
                    &account.session_authorization,
                    self.cartridge_api_url.clone(),
                )
                .await;

            if let Err(e) = controller_response {
                let address = controller.address;
                let app_id = controller.app_id.clone();
                let chain_id = controller.chain_id;

                controller
                    .storage
                    .remove(&Selectors::session(&address, &app_id, &chain_id))
                    .map_err(|e| JsControllerError::from(ControllerError::StorageError(e)))?;

                return Err(JsControllerError::from(e));
            }

            let session_metadata = AuthorizedSession {
                session: account.session.clone().into(),
                authorization: Some(
                    account
                        .session_authorization
                        .clone()
                        .into_iter()
                        .map(Into::into)
                        .collect(),
                ),
                is_registered: false,
                expires_at: account.session.inner.expires_at,
                allowed_policies_root: account.session.inner.allowed_policies_root.into(),
                metadata_hash: account.session.inner.metadata_hash.into(),
                session_key_guid: account.session.inner.session_key_guid.into(),
                guardian_key_guid: account.session.inner.guardian_key_guid.into(),
            };
            Some(session_metadata)
        } else {
            None
        };

        self.policy_storage.lock().await.store(policies.clone())?;

        Ok(session)
    }

    #[wasm_bindgen(js_name = skipSession)]
    pub async fn skip_session(
        &self,
        policies: Vec<Policy>,
    ) -> std::result::Result<(), JsControllerError> {
        set_panic_hook();

        // Convert policies to have authorization explicitly set to false
        let unauthorized_policies = policies
            .into_iter()
            .map(|policy| match policy {
                Policy::Call(call_policy) => Policy::Call(CallPolicy {
                    target: call_policy.target,
                    method: call_policy.method,
                    authorized: Some(false),
                }),
                Policy::TypedData(td_policy) => Policy::TypedData(TypedDataPolicy {
                    scope_hash: td_policy.scope_hash,
                    authorized: Some(false),
                }),
            })
            .collect();

        self.policy_storage
            .lock()
            .await
            .store(unauthorized_policies)?;

        Ok(())
    }

    #[wasm_bindgen(js_name = addOwner)]
    pub async fn add_owner(
        &mut self,
        owner: Option<Signer>,
        signer_input: Option<JsSignerInput>,
        rp_id: Option<String>,
    ) -> std::result::Result<(), JsControllerError> {
        set_panic_hook();

        let (signer, signer_input) = if let Some(rp_id) = rp_id {
            self.handle_passkey_creation(rp_id).await?
        } else {
            if owner.is_none() || signer_input.is_none() {
                return Err(JsControllerError::from(
                    ControllerError::InvalidResponseData(
                        "Owner and signer input are required".to_string(),
                    ),
                ));
            }
            (
                owner.clone().unwrap().try_into()?,
                signer_input.unwrap().into(),
            )
        };

        let mut controller = self.controller.lock().await;
        let tx_result = controller.add_owner(signer.clone()).await?;

        TransactionWaiter::new(tx_result.transaction_hash, controller.provider())
            .with_timeout(std::time::Duration::from_secs(20))
            .wait()
            .await
            .map_err(Into::<ControllerError>::into)?;

        let signer_guid: Felt = signer.into();
        controller
            .add_owner_with_cartridge(signer_input, signer_guid, self.cartridge_api_url.clone())
            .await?;

        Ok(())
    }

    #[wasm_bindgen(js_name = createPasskeySigner)]
    pub async fn create_passkey_signer(
        &self,
        rp_id: String,
    ) -> std::result::Result<JsSignerInput, JsControllerError> {
        set_panic_hook();

        let mut controller = self.controller.lock().await;

        let (_, signer_input) = controller.create_passkey(rp_id, false).await?;

        Ok(JsSignerInput(signer_input))
    }

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
            .controller
            .lock()
            .await
            .estimate_invoke_fee(calls)
            .await?;

        Ok(fee_estimate.into())
    }

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

        let result = Controller::execute(
            self.controller.lock().await.borrow_mut(),
            calls,
            max_fee.map(Into::into),
            fee_source.map(|fs| fs.try_into()).transpose()?,
        )
        .await?;

        Ok(to_value(&result)?)
    }

    #[wasm_bindgen(js_name = executeFromOutsideV2)]
    pub async fn execute_from_outside_v2(
        &self,
        calls: Vec<JsCall>,
        fee_source: Option<JsFeeSource>,
    ) -> std::result::Result<JsValue, JsControllerError> {
        set_panic_hook();

        let calls = calls
            .into_iter()
            .map(TryInto::try_into)
            .collect::<std::result::Result<_, _>>()?;

        let response = self
            .controller
            .lock()
            .await
            .execute_from_outside_v2(calls, fee_source.map(|fs| fs.try_into()).transpose()?)
            .await?;
        Ok(to_value(&response)?)
    }

    #[wasm_bindgen(js_name = executeFromOutsideV3)]
    pub async fn execute_from_outside_v3(
        &self,
        calls: Vec<JsCall>,
        fee_source: Option<JsFeeSource>,
    ) -> std::result::Result<JsValue, JsControllerError> {
        set_panic_hook();

        let calls = calls
            .into_iter()
            .map(TryInto::try_into)
            .collect::<std::result::Result<_, _>>()?;

        let response = self
            .controller
            .lock()
            .await
            .execute_from_outside_v3(calls, fee_source.map(|fs| fs.try_into()).transpose()?)
            .await?;
        Ok(to_value(&response)?)
    }

    #[wasm_bindgen(js_name = isRegisteredSessionAuthorized)]
    pub async fn is_registered_session_authorized(
        &self,
        policies: Vec<Policy>,
        public_key: Option<JsFelt>,
    ) -> std::result::Result<Option<AuthorizedSession>, JsControllerError> {
        let policies = policies
            .into_iter()
            .map(TryFrom::try_from)
            .collect::<std::result::Result<Vec<_>, _>>()?;

        Ok(self
            .controller
            .lock()
            .await
            .authorized_session_for_policies(
                &policies,
                public_key.map(|f| f.try_into()).transpose()?,
            )
            .map(AuthorizedSession::from))
    }

    #[wasm_bindgen(js_name = hasRequestedSession)]
    pub async fn has_requested_session(
        &self,
        policies: Vec<Policy>,
    ) -> std::result::Result<bool, JsControllerError> {
        if !self.policy_storage.lock().await.is_requested(&policies)? {
            // If not requested locally, we don't need to check the session
            return Ok(false);
        }

        let controller_guard = self.controller.lock().await;
        Ok(controller_guard.authorized_session().is_some())
    }

    #[wasm_bindgen(js_name = revokeSession)]
    pub async fn revoke_session(&self, session: JsRevokableSession) -> Result<()> {
        self.revoke_sessions(vec![session]).await
    }

    #[wasm_bindgen(js_name = revokeSessions)]
    pub async fn revoke_sessions(&self, sessions: Vec<JsRevokableSession>) -> Result<()> {
        set_panic_hook();

        let sessions: Vec<RevokableSession> = sessions.into_iter().map(Into::into).collect();
        let mut controller = self.controller.lock().await;

        let provider = controller.provider();
        let block_id = BlockId::Tag(BlockTag::Pending);

        let mut to_revoke = vec![];
        for session in sessions.clone() {
            let result = provider
                .call(
                    &FunctionCall {
                        contract_address: controller.address,
                        entry_point_selector: selector!("is_session_revoked"),
                        calldata: vec![session.session_hash],
                    },
                    block_id,
                )
                .await?;
            if result[0] == Felt::from(0) {
                to_revoke.push(session);
            }
        }

        let tx = controller.revoke_sessions(to_revoke).await?;

        TransactionWaiter::new(tx.transaction_hash, controller.provider())
            .with_timeout(std::time::Duration::from_secs(20))
            .wait()
            .await
            .map_err(Into::<ControllerError>::into)?;

        let _ = controller
            .revoke_sessions_with_cartridge(&sessions, self.cartridge_api_url.clone())
            .await;
        Ok(())
    }

    #[wasm_bindgen(js_name = signMessage)]
    pub async fn sign_message(&self, typed_data: String) -> Result<Felts> {
        set_panic_hook();

        let signature = self
            .controller
            .lock()
            .await
            .sign_message(&serde_json::from_str(&typed_data)?)
            .await
            .map_err(|e| JsControllerError::from(ControllerError::SignError(e)))?;

        Ok(Felts(signature.into_iter().map(Into::into).collect()))
    }

    #[wasm_bindgen(js_name = getNonce)]
    pub async fn get_nonce(&self) -> std::result::Result<JsValue, JsControllerError> {
        let nonce = self
            .controller
            .lock()
            .await
            .get_nonce()
            .await
            .map_err(|e| JsControllerError::from(ControllerError::ProviderError(e)))?;

        Ok(to_value(&nonce)?)
    }

    #[wasm_bindgen(js_name = deploySelf)]
    pub async fn deploy_self(&self, max_fee: Option<JsFeeEstimate>) -> Result<JsValue> {
        set_panic_hook();

        let controller = self.controller.lock().await;
        let mut deployment = controller.deploy();

        if let Some(max_fee) = max_fee {
            let gas_estimate_multiplier = 1.5;
            let fee_estimate: FeeEstimate = max_fee.into();

            // Compute resource bounds for all gas types
            let l1_gas = ((fee_estimate.l1_gas_consumed as f64) * gas_estimate_multiplier) as u64;
            let l2_gas = ((fee_estimate.l2_gas_consumed as f64) * gas_estimate_multiplier) as u64;
            let l1_data_gas =
                ((fee_estimate.l1_data_gas_consumed as f64) * gas_estimate_multiplier) as u64;

            deployment = deployment
                .l1_gas(l1_gas)
                .l1_gas_price(fee_estimate.l1_gas_price)
                .l2_gas(l2_gas)
                .l2_gas_price(fee_estimate.l2_gas_price)
                .l1_data_gas(l1_data_gas)
                .l1_data_gas_price(fee_estimate.l1_data_gas_price);
        }

        let res = deployment
            .send()
            .await
            .map_err(|e| JsControllerError::from(ControllerError::AccountFactoryError(e)))?;

        Ok(to_value(&res)?)
    }

    #[wasm_bindgen(js_name = delegateAccount)]
    pub async fn delegate_account(&self) -> Result<JsFelt> {
        set_panic_hook();

        let res = self
            .controller
            .lock()
            .await
            .delegate_account()
            .await
            .map_err(JsControllerError::from)?;

        Ok(res.into())
    }

    #[wasm_bindgen(js_name = hasAuthorizedPoliciesForCalls)]
    pub async fn has_authorized_policies_for_calls(&self, calls: Vec<JsCall>) -> Result<bool> {
        let calls: Vec<Call> = calls
            .into_iter()
            .map(TryFrom::try_from)
            .collect::<std::result::Result<_, _>>()?;

        let policies: Vec<_> = calls.iter().map(Policy::from_call).collect();

        // Check local policy authorization
        if !self.policy_storage.lock().await.is_authorized(&policies)? {
            return Ok(false);
        }

        let controller_guard = self.controller.lock().await;
        Ok(controller_guard.authorized_session().is_some())
    }

    #[wasm_bindgen(js_name = hasAuthorizedPoliciesForMessage)]
    pub async fn has_authorized_policies_for_message(&self, typed_data: String) -> Result<bool> {
        let typed_data_obj: TypedData = serde_json::from_str(&typed_data)?;
        let policy = Policy::from_typed_data(&typed_data_obj)?;

        // Check local policy authorization
        if !self.policy_storage.lock().await.is_authorized(&[policy])? {
            return Ok(false);
        }

        let controller_guard = self.controller.lock().await;
        Ok(controller_guard.authorized_session().is_some())
    }
}

/// A type for accessing fixed attributes of `CartridgeAccount`.
///
/// This type exists as concurrent mutable and immutable calls to `CartridgeAccount` are guarded
/// with `WasmMutex`, which only operates under an `async` context. If these getters were directly
/// implemented under `CartridgeAccount`:
///
/// - calls to them would unnecessarily have to be `async` as well;
/// - there would be excessive locking.
///
/// This type is supposed to only ever be borrowed immutably. So no concurrent access control would
/// be needed.
#[wasm_bindgen]
#[derive(Clone)]
pub struct CartridgeAccountMeta {
    app_id: String,
    username: String,
    address: String,
    class_hash: String,
    rpc_url: String,
    chain_id: String,
    owner_guid: JsFelt,
    owner: Owner,
}

impl CartridgeAccountMeta {
    fn new(controller: &Controller) -> Self {
        Self {
            app_id: controller.app_id.clone(),
            username: controller.username.clone(),
            address: controller.address.to_hex_string(),
            class_hash: controller.class_hash.to_hex_string(),
            rpc_url: controller.rpc_url.to_string(),
            chain_id: controller.chain_id.to_hex_string(),
            owner_guid: controller.owner_guid().into(),
            owner: controller.owner.clone().into(),
        }
    }
}

#[wasm_bindgen]
impl CartridgeAccountMeta {
    #[wasm_bindgen(js_name = appId)]
    pub fn app_id(&self) -> String {
        self.app_id.clone()
    }

    #[wasm_bindgen(js_name = username)]
    pub fn username(&self) -> String {
        self.username.clone()
    }

    #[wasm_bindgen(js_name = address)]
    pub fn address(&self) -> String {
        self.address.clone()
    }

    #[wasm_bindgen(js_name = classHash)]
    pub fn class_hash(&self) -> String {
        self.class_hash.clone()
    }

    #[wasm_bindgen(js_name = rpcUrl)]
    pub fn rpc_url(&self) -> String {
        self.rpc_url.clone()
    }

    #[wasm_bindgen(js_name = chainId)]
    pub fn chain_id(&self) -> String {
        self.chain_id.clone()
    }

    #[wasm_bindgen(js_name = ownerGuid)]
    pub fn owner_guid(&self) -> JsFelt {
        self.owner_guid.clone()
    }

    #[wasm_bindgen(js_name = owner)]
    pub fn owner(&self) -> Owner {
        self.owner.clone()
    }
}

#[wasm_bindgen(js_name = signerToGuid)]
pub fn signer_to_guid(signer: Signer) -> JsFelt {
    let signer: account_sdk::signers::Signer = signer.try_into().unwrap();
    let felt: Felt = signer.into();
    felt.into()
}

/// A type used as the return type for constructing `CartridgeAccount` to provide an extra,
/// separately borrowable `meta` field for synchronously accessing fixed fields.
///
/// This type exists instead of simply having `CartridgeAccount::new()` return a tuple as tuples
/// don't implement `IntoWasmAbi` which is needed for crossing JS-WASM boundary.
#[wasm_bindgen]
pub struct CartridgeAccountWithMeta {
    account: CartridgeAccount,
    meta: CartridgeAccountMeta,
}

impl CartridgeAccountWithMeta {
    fn new(controller: Controller, cartridge_api_url: String) -> Self {
        let meta = CartridgeAccountMeta::new(&controller);
        let policy_storage = PolicyStorage::new(
            &controller.address,
            &controller.app_id,
            &controller.chain_id,
        );

        Self {
            account: CartridgeAccount {
                controller: WasmMutex::new(controller),
                policy_storage: WasmMutex::new(policy_storage),
                cartridge_api_url,
            },
            meta,
        }
    }
}

#[wasm_bindgen]
impl CartridgeAccountWithMeta {
    #[wasm_bindgen(js_name = meta)]
    pub fn meta(&self) -> CartridgeAccountMeta {
        self.meta.clone()
    }

    #[wasm_bindgen(js_name = intoAccount)]
    pub fn into_account(self) -> CartridgeAccount {
        self.account
    }
}

/// Computes the Starknet contract address for a controller account without needing a full instance.
///
/// # Arguments
///
/// * `class_hash` - The class hash of the account contract (JsFelt).
/// * `owner` - The owner configuration for the account.
/// * `salt` - The salt used for address calculation (JsFelt).
///
/// # Returns
///
/// The computed Starknet contract address as a `JsFelt`.
#[wasm_bindgen(js_name = computeAccountAddress)]
pub fn compute_account_address(class_hash: JsFelt, owner: Owner, salt: JsFelt) -> Result<JsFelt> {
    let class_hash_felt: Felt = class_hash.try_into()?;
    let salt_felt: Felt = salt.try_into()?;

    // The owner type from WASM is directly usable here
    let address =
        account_sdk::factory::compute_account_address(class_hash_felt, owner.into(), salt_felt);

    Ok(address.into())
}
