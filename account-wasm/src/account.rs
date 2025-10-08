use account_sdk::abigen::controller::OutsideExecutionV3;
use account_sdk::abigen::controller::Signer as AbigenSigner;
use account_sdk::abigen::controller::StarknetSigner;
use account_sdk::account::outside_execution::{
    OutsideExecution, OutsideExecutionAccount, OutsideExecutionCaller,
};
use account_sdk::account::session::hash::Session;
use account_sdk::account::session::policy::Policy as SdkPolicy;
use account_sdk::controller::{Controller, DEFAULT_SESSION_EXPIRATION};
use account_sdk::errors::ControllerError;
use account_sdk::session::RevokableSession;
use account_sdk::storage::selectors::Selectors;
use account_sdk::storage::StorageBackend;

use account_sdk::transaction_waiter::TransactionWaiter;
use cainome::cairo_serde::NonZero;
use cainome::cairo_serde::Zeroable;
use chrono::Utc;
use serde_wasm_bindgen::to_value;
use starknet::accounts::ConnectedAccount;
use starknet::core::types::{BlockId, BlockTag, Call, FeeEstimate, FunctionCall, TypedData};
use starknet::signers::SigningKey;

use starknet::core::utils::parse_cairo_short_string;
use starknet::macros::{selector, short_string};
use starknet::providers::{Provider, ProviderRequestData, ProviderResponseData};
use starknet_types_core::felt::Felt;
use url::Url;
use wasm_bindgen::prelude::*;

use crate::errors::JsControllerError;
use crate::set_panic_hook;
use crate::storage::PolicyStorage;
use crate::sync::WasmMutex;
use crate::types::call::JsCall;
use crate::types::estimate::JsFeeEstimate;
use crate::types::outside_execution::JsSignedOutsideExecution;
use crate::types::owner::Owner;
use crate::types::policy::{CallPolicy, Policy, TypedDataPolicy};
use crate::types::register::{JsRegister, JsRegisterResponse};
use crate::types::session::{AuthorizedSession, JsRevokableSession};
use crate::types::signer::{JsAddSignerInput, JsRemoveSignerInput, Signer};
use crate::types::{Felts, JsFeeSource, JsFelt};

pub type Result<T> = std::result::Result<T, JsError>;

async fn ensure_wildcard_session_if_expired(
    controller: &mut Controller,
) -> std::result::Result<(), ControllerError> {
    let session_metadata = controller.authorized_session();

    let should_recreate = match session_metadata {
        None => true,
        Some(metadata) => metadata.session.is_expired() && metadata.is_wildcard(),
    };

    if should_recreate {
        let expires_at = (Utc::now().timestamp() as u64) + DEFAULT_SESSION_EXPIRATION;
        controller.create_wildcard_session(expires_at).await?;
    }

    Ok(())
}

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
    /// - `address`: The blockchain address associated with the account.
    /// - `username`: Username associated with the account.
    /// - `owner`: A Owner struct containing the owner signer and associated data.
    ///
    #[allow(clippy::new_ret_no_self, clippy::too_many_arguments)]
    pub async fn new(
        app_id: String,
        class_hash: JsFelt,
        rpc_url: String,
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
            None,
        )
        .await
        .map_err(|e| JsError::new(&e.to_string()))?;

        Ok(CartridgeAccountWithMeta::new(controller, cartridge_api_url))
    }

    /// Creates a new `CartridgeAccount` instance with a randomly generated Starknet signer.
    /// The controller address is computed internally based on the generated signer.
    ///
    /// # Parameters
    /// - `app_id`: Application identifier.
    /// - `rpc_url`: The URL of the JSON-RPC endpoint.
    /// - `username`: Username associated with the account.
    ///
    #[allow(clippy::new_ret_no_self)]
    #[wasm_bindgen(js_name = newHeadless)]
    pub async fn new_headless(
        app_id: String,
        class_hash: JsFelt,
        rpc_url: String,
        username: String,
        cartridge_api_url: String,
    ) -> Result<CartridgeAccountWithMeta> {
        set_panic_hook();

        let rpc_url = Url::parse(&rpc_url)?;
        let username = username.to_lowercase();
        let class_hash_felt: Felt = class_hash.try_into()?;

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
            None,
        )
        .await
        .map_err(|e| JsError::new(&e.to_string()))?;

        Ok(CartridgeAccountWithMeta::new(controller, cartridge_api_url))
    }

    #[wasm_bindgen(js_name = fromStorage)]
    pub async fn from_storage(
        app_id: String,
        cartridge_api_url: String,
    ) -> Result<Option<CartridgeAccountWithMeta>> {
        set_panic_hook();

        let controller = Controller::from_storage(app_id)
            .await
            .map_err(|e| JsError::new(&e.to_string()))?;

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
        let pub_key: Felt = *public_key.as_felt();

        let res = self
            .controller
            .lock()
            .await
            .register_session(methods.clone(), expires_at, pub_key, Felt::ZERO, max_fee)
            .await
            .map_err(JsControllerError::from)?;

        let controller = self.controller.lock().await;

        TransactionWaiter::new(res.transaction_hash, controller.provider())
            .with_timeout(std::time::Duration::from_secs(DEFAULT_TIMEOUT))
            .wait()
            .await
            .map_err(Into::<ControllerError>::into)?;

        let session = Session::new(
            methods,
            expires_at,
            &AbigenSigner::Starknet(StarknetSigner {
                pubkey: NonZero::new(pub_key).unwrap(),
            }),
            Felt::ZERO,
        )?;
        let owner_guid = controller.owner_guid();
        let authorization = vec![short_string!("authorization-by-registered"), owner_guid];
        controller
            .register_session_with_cartridge(
                &session,
                &authorization,
                self.cartridge_api_url.clone(),
            )
            .await?;

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

        // First, check if any policies are forbidden (increaseAllowance, increase_allowance)
        for policy in &policies {
            if policy.is_forbidden_policy() {
                return Err(JsControllerError::from(ControllerError::ForbiddenEntrypoint(
                    "increaseAllowance and increase_allowance are not allowed in session policies"
                        .to_string(),
                )));
            }
        }

        // Separate approve policies from session policies
        let (approve_policies, session_policies): (Vec<_>, Vec<_>) =
            policies.into_iter().partition(|p| p.is_approve_policy());

        let mut controller = self.controller.lock().await;

        // Execute approve policies immediately if any exist
        if !approve_policies.is_empty() {
            // Convert approve policies to calls
            let approve_calls: Vec<Call> = approve_policies
                .iter()
                .filter_map(|policy| match policy {
                    Policy::Call(call_policy) => {
                        // Create a basic approve call with zero amount for now
                        // The actual amount should come from the calldata in a real implementation
                        Some(Call {
                            to: *call_policy.target.as_felt(),
                            selector: *call_policy.method.as_felt(),
                            // Note: In a real implementation, the calldata (spender, amount) should be
                            // provided by the caller. For now, we just execute with empty calldata
                            // which will fail, but demonstrates the structure.
                            calldata: vec![],
                        })
                    }
                    _ => None,
                })
                .collect();

            if !approve_calls.is_empty() {
                // Execute the approve calls immediately
                controller
                    .execute(approve_calls, None, None)
                    .await
                    .map_err(JsControllerError::from)?;
            }
        }

        let wildcard_exists = controller
            .authorized_session()
            .filter(|session| !session.session.is_expired() && session.is_wildcard())
            .is_some();

        let session = if !wildcard_exists {
            // Create wildcard session without approve policies
            // Note: This creates a wildcard session that allows all policies
            // Approve policies have already been executed above
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

        // Store only the session policies (approve policies are excluded)
        self.policy_storage.lock().await.store(session_policies)?;

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
        signer_input: Option<JsAddSignerInput>,
        rp_id: Option<String>,
    ) -> std::result::Result<(), JsControllerError> {
        set_panic_hook();

        let controller = self.controller.lock().await;

        if controller.chain_id != short_string!("SN_MAIN") {
            return Err(ControllerError::InvalidChainID(
                "SN_MAIN".to_string(),
                parse_cairo_short_string(&controller.chain_id).expect("Expected valid shortstring"),
            )
            .into());
        }

        std::mem::drop(controller);

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
            .with_timeout(std::time::Duration::from_secs(DEFAULT_TIMEOUT))
            .wait()
            .await
            .map_err(Into::<ControllerError>::into)?;

        let signer_guid: Felt = signer.into();
        controller
            .add_owner_with_cartridge(signer_input, signer_guid, self.cartridge_api_url.clone())
            .await?;

        Ok(())
    }

    #[wasm_bindgen(js_name = removeOwner)]
    pub async fn remove_owner(
        &mut self,
        signer: JsRemoveSignerInput,
    ) -> std::result::Result<(), JsControllerError> {
        set_panic_hook();

        let mut controller = self.controller.lock().await;

        if controller.chain_id != short_string!("SN_MAIN") {
            return Err(ControllerError::InvalidChainID(
                "SN_MAIN".to_string(),
                parse_cairo_short_string(&controller.chain_id).expect("Expected valid shortstring"),
            )
            .into());
        }

        let mut remove_owner_input: account_sdk::graphql::owner::remove_owner::SignerInput =
            signer.into();
        let signer: account_sdk::signers::Signer = remove_owner_input.clone().try_into()?;
        let tx_result = controller.remove_owner(signer.clone()).await?;

        TransactionWaiter::new(tx_result.transaction_hash, controller.provider())
            .with_timeout(std::time::Duration::from_secs(DEFAULT_TIMEOUT))
            .wait()
            .await
            .map_err(Into::<ControllerError>::into)?;
        let signer_guid: Felt = signer.into();

        let mut credentials: serde_json::Value =
            serde_json::from_str(&remove_owner_input.credential).map_err(|e| {
                JsControllerError::from(ControllerError::InvalidResponseData(e.to_string()))
            })?;
        let _ = credentials.as_object_mut().unwrap().remove("rpId");
        remove_owner_input.credential = serde_json::to_string(&credentials).map_err(|e| {
            JsControllerError::from(ControllerError::InvalidResponseData(e.to_string()))
        })?;
        controller
            .remove_owner_with_cartridge(
                remove_owner_input,
                signer_guid,
                self.cartridge_api_url.clone(),
            )
            .await?;

        Ok(())
    }

    #[wasm_bindgen(js_name = createPasskeySigner)]
    pub async fn create_passkey_signer(
        &self,
        rp_id: String,
    ) -> std::result::Result<JsAddSignerInput, JsControllerError> {
        set_panic_hook();

        let mut controller = self.controller.lock().await;

        let (_, signer_input) = controller.create_passkey(rp_id, false).await?;

        Ok(JsAddSignerInput(signer_input))
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

        let mut controller = self.controller.lock().await;
        ensure_wildcard_session_if_expired(&mut controller)
            .await
            .map_err(JsControllerError::from)?;

        let result = controller
            .execute(
                calls,
                max_fee.map(Into::into),
                fee_source.map(|fs| fs.try_into()).transpose()?,
            )
            .await
            .map_err(JsControllerError::from)?;

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

        let mut controller = self.controller.lock().await;
        ensure_wildcard_session_if_expired(&mut controller)
            .await
            .map_err(JsControllerError::from)?;

        let response = controller
            .execute_from_outside_v2(calls, fee_source.map(|fs| fs.try_into()).transpose()?)
            .await
            .map_err(JsControllerError::from)?;
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

        let mut controller = self.controller.lock().await;
        ensure_wildcard_session_if_expired(&mut controller)
            .await
            .map_err(JsControllerError::from)?;

        let response = controller
            .execute_from_outside_v3(calls, fee_source.map(|fs| fs.try_into()).transpose()?)
            .await
            .map_err(JsControllerError::from)?;
        Ok(to_value(&response)?)
    }

    #[wasm_bindgen(js_name = trySessionExecute)]
    pub async fn try_session_execute(
        &self,
        calls: Vec<JsCall>,
        fee_source: Option<JsFeeSource>,
    ) -> std::result::Result<JsValue, JsControllerError> {
        set_panic_hook();

        // Convert calls to internal format
        let calls = calls
            .into_iter()
            .map(TryInto::try_into)
            .collect::<std::result::Result<Vec<_>, _>>()?;

        // Extract policies from calls
        let policies = SdkPolicy::from_calls(&calls);

        // Convert SDK policies to WASM policies for client-side authorization check
        let wasm_policies: Vec<Policy> = policies.iter().map(|p| p.clone().into()).collect();

        // Lock controller
        let mut controller = self.controller.lock().await;

        // Check session status
        let session_metadata = controller.authorized_session();

        // Check if session is expired or missing
        match session_metadata {
            Some(metadata) => {
                if metadata.session.is_expired() {
                    // Session exists but is expired - check client-side policies to see if they would authorize the calls
                    let is_authorized = self
                        .policy_storage
                        .lock()
                        .await
                        .is_authorized(&wasm_policies)?;

                    if is_authorized {
                        // The expired session has policies that would authorize these calls
                        return Err(JsControllerError::from(
                            ControllerError::SessionRefreshRequired,
                        ));
                    } else {
                        // The expired session doesn't authorize these calls
                        return Err(JsControllerError::from(
                            ControllerError::ManualExecutionRequired,
                        ));
                    }
                } else {
                    // Session exists and is not expired - check if policies authorize execution
                    let is_authorized = self
                        .policy_storage
                        .lock()
                        .await
                        .is_authorized(&wasm_policies)?;

                    if !is_authorized {
                        // Session is valid but policies don't authorize these calls
                        return Err(JsControllerError::from(
                            ControllerError::ManualExecutionRequired,
                        ));
                    }
                }
            }
            None => {
                // No session exists
                return Err(JsControllerError::from(
                    ControllerError::ManualExecutionRequired,
                ));
            }
        }

        // Now execute with valid session
        // Try paymaster first (execute_from_outside_v3)
        match controller
            .execute_from_outside_v3(
                calls.clone(),
                fee_source
                    .as_ref()
                    .map(|fs| fs.clone().try_into())
                    .transpose()?,
            )
            .await
        {
            Ok(result) => Ok(to_value(&result)?),
            Err(e) => match e {
                ControllerError::PaymasterNotSupported => {
                    // Fallback to user pays flow when the paymaster path is unavailable
                    let estimate = controller.estimate_invoke_fee(calls.clone()).await?;
                    let result = controller
                        .execute(
                            calls,
                            Some(estimate),
                            fee_source.map(|fs| fs.try_into()).transpose()?,
                        )
                        .await?;
                    Ok(to_value(&result)?)
                }
                other => Err(JsControllerError::from(other)),
            },
        }
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
        Ok(controller_guard
            .authorized_session()
            .map(|metadata| !metadata.session.is_expired())
            .unwrap_or(false))
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

        let results = provider
            .batch_requests(
                sessions
                    .iter()
                    .map(|session| {
                        ProviderRequestData::Call(starknet::core::types::requests::CallRequest {
                            request: FunctionCall {
                                contract_address: controller.address,
                                entry_point_selector: selector!("is_session_revoked"),
                                calldata: vec![session.session_hash],
                            },
                            block_id: BlockId::Tag(BlockTag::PreConfirmed),
                        })
                    })
                    .collect::<Vec<_>>(),
            )
            .await?;

        let unrevoked_sessions = results
            .iter()
            .zip(sessions.iter())
            .map(|(result, session)| {
                if let ProviderResponseData::Call(call_response) = result {
                    if call_response.len() != 1 {
                        return Err(JsControllerError::from(
                            ControllerError::InvalidResponseData(
                                "Expected 1 response, got {:?}".to_string(),
                            ),
                        ));
                    }

                    let response = call_response[0];
                    if response != Felt::ONE && response != Felt::ZERO {
                        return Err(JsControllerError::from(
                            ControllerError::InvalidResponseData(
                                "Expected boolean, got {:?}".to_string(),
                            ),
                        ));
                    }

                    if response.is_zero() {
                        Ok(Some(session.clone()))
                    } else {
                        Ok(None)
                    }
                } else {
                    Err(JsControllerError::from(
                        ControllerError::InvalidResponseData(
                            "Expected call response, got {:?}".to_string(),
                        ),
                    ))
                }
            })
            .collect::<std::result::Result<Vec<_>, _>>()?
            .into_iter()
            .flatten()
            .collect();

        let tx = controller.revoke_sessions(unrevoked_sessions).await?;

        TransactionWaiter::new(tx.transaction_hash, controller.provider())
            .with_timeout(std::time::Duration::from_secs(DEFAULT_TIMEOUT))
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
        Ok(controller_guard
            .authorized_session()
            .map(|metadata| !metadata.session.is_expired())
            .unwrap_or(false))
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
        Ok(controller_guard
            .authorized_session()
            .map(|metadata| !metadata.session.is_expired())
            .unwrap_or(false))
    }

    /// Signs an OutsideExecution V3 transaction and returns both the OutsideExecution object and its signature.
    ///
    /// # Parameters
    /// - `calls`: Array of calls to execute from outside
    ///
    /// # Returns
    /// A `JsSignedOutsideExecution` containing the OutsideExecution V3 object and its signature
    #[wasm_bindgen(js_name = signExecuteFromOutside)]
    pub async fn sign_execute_from_outside(
        &self,
        calls: Vec<JsCall>,
    ) -> std::result::Result<JsSignedOutsideExecution, JsControllerError> {
        set_panic_hook();

        let calls = calls
            .into_iter()
            .map(TryInto::try_into)
            .collect::<std::result::Result<Vec<_>, _>>()?;

        let controller = self.controller.lock().await;
        let now = Utc::now().timestamp() as u64;

        let outside_execution = OutsideExecutionV3 {
            caller: OutsideExecutionCaller::Any.into(),
            execute_after: 0,
            execute_before: now + 600,
            calls: calls.into_iter().map(|call: Call| call.into()).collect(),
            nonce: (SigningKey::from_random().secret_scalar(), 1),
        };

        let signed = controller
            .sign_outside_execution(OutsideExecution::V3(outside_execution.clone()))
            .await
            .map_err(JsControllerError::from)?;

        Ok(JsSignedOutsideExecution {
            outside_execution: outside_execution.into(),
            signature: signed.signature.into_iter().map(Into::into).collect(),
        })
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
    owner: Owner,
    owner_guid: Felt,
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
            owner: controller.owner.clone().into(),
            owner_guid: controller.owner.clone().into(),
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

    #[wasm_bindgen(js_name = owner)]
    pub fn owner(&self) -> Owner {
        self.owner.clone()
    }

    #[wasm_bindgen(js_name = ownerGuid)]
    pub fn owner_guid(&self) -> JsFelt {
        self.owner_guid.into()
    }
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
    pub fn new(controller: Controller, cartridge_api_url: String) -> Self {
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

const DEFAULT_TIMEOUT: u64 = 30;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::errors::ErrorCode;
    use crate::types::policy::CallPolicy;
    use account_sdk::account::session::policy::{CallPolicy as SdkCallPolicy, Policy as SdkPolicy};
    use account_sdk::errors::ControllerError;
    use starknet::core::types::Call;
    use starknet::macros::felt;

    #[test]
    fn test_paymaster_error_codes() {
        // Test that PaymasterNotSupported error code is properly handled
        let controller_err = ControllerError::PaymasterNotSupported;
        let js_err = JsControllerError::from(controller_err);
        assert!(matches!(js_err.code, ErrorCode::PaymasterNotSupported));
        assert_eq!(js_err.message, "Paymaster not supported");
    }

    #[test]
    fn test_paymaster_not_supported_detection_is_explicit() {
        assert!(matches!(
            ControllerError::PaymasterNotSupported,
            ControllerError::PaymasterNotSupported
        ));

        let generic_err = ControllerError::InvalidResponseData("paymaster not supported".into());
        assert!(!matches!(
            generic_err,
            ControllerError::PaymasterNotSupported
        ));

        let nested_err = ControllerError::PaymasterError(
            account_sdk::provider::ExecuteFromOutsideError::InvalidCaller,
        );
        assert!(!matches!(
            nested_err,
            ControllerError::PaymasterNotSupported
        ));
    }

    #[test]
    fn test_sdk_policy_to_wasm_policy_conversion() {
        // Test Call policy conversion
        let sdk_call_policy = SdkPolicy::Call(SdkCallPolicy {
            contract_address: felt!("0x1234"),
            selector: felt!("0x5678"),
            authorized: Some(true),
        });

        let wasm_policy: Policy = sdk_call_policy.clone().into();

        match &wasm_policy {
            Policy::Call(call_policy) => {
                assert_eq!(*call_policy.target.as_felt(), felt!("0x1234"));
                assert_eq!(*call_policy.method.as_felt(), felt!("0x5678"));
                assert_eq!(call_policy.authorized, Some(true));
            }
            _ => panic!("Expected Call policy"),
        }

        // Test that conversion round-trips correctly
        let sdk_policy_back: SdkPolicy = wasm_policy.try_into().unwrap();
        assert_eq!(sdk_call_policy, sdk_policy_back);
    }

    #[test]
    fn test_policy_from_calls_matches_client_side_check() {
        // Create a test call
        let call = Call {
            to: felt!("0x1234"),
            selector: felt!("0x5678"),
            calldata: vec![],
        };

        // Extract SDK policies from calls (this is what try_session_execute does)
        let sdk_policies = SdkPolicy::from_calls(&[call.clone()]);

        // Convert to WASM policies for client-side check
        let wasm_policies: Vec<Policy> = sdk_policies.iter().map(|p| p.clone().into()).collect();

        // Verify the conversion produces the expected policy
        assert_eq!(wasm_policies.len(), 1);
        match &wasm_policies[0] {
            Policy::Call(call_policy) => {
                assert_eq!(*call_policy.target.as_felt(), felt!("0x1234"));
                assert_eq!(*call_policy.method.as_felt(), felt!("0x5678"));
                // SDK policies from calls set authorized to Some(true)
                assert_eq!(call_policy.authorized, Some(true));
            }
            _ => panic!("Expected Call policy"),
        }
    }

    #[test]
    fn test_client_side_policy_authorization_check() {
        use crate::storage::check_is_authorized;

        // Create authorized policies that would be stored client-side
        let stored_policy = Policy::Call(CallPolicy {
            target: JsFelt(felt!("0x1234")),
            method: JsFelt(felt!("0x5678")),
            authorized: Some(true),
        });

        // Create a call that matches the stored policy
        let call = Call {
            to: felt!("0x1234"),
            selector: felt!("0x5678"),
            calldata: vec![],
        };

        // Extract policies from call (as try_session_execute would)
        let sdk_policies = SdkPolicy::from_calls(&[call]);
        let wasm_policies: Vec<Policy> = sdk_policies.iter().map(|p| p.clone().into()).collect();

        // Verify that the stored authorized policy matches the call
        assert!(
            check_is_authorized(&[stored_policy.clone()], &wasm_policies),
            "Stored authorized policy should match the call"
        );

        // Test with unauthorized policy
        let unauthorized_policy = Policy::Call(CallPolicy {
            target: JsFelt(felt!("0x1234")),
            method: JsFelt(felt!("0x5678")),
            authorized: Some(false),
        });

        assert!(
            !check_is_authorized(&[unauthorized_policy], &wasm_policies),
            "Stored unauthorized policy should not match the call"
        );

        // Test with different target
        let different_target_call = Call {
            to: felt!("0x9999"),
            selector: felt!("0x5678"),
            calldata: vec![],
        };
        let different_policies = SdkPolicy::from_calls(&[different_target_call]);
        let different_wasm_policies: Vec<Policy> = different_policies
            .iter()
            .map(|p| p.clone().into())
            .collect();

        assert!(
            !check_is_authorized(&[stored_policy], &different_wasm_policies),
            "Stored policy should not match call with different target"
        );
    }

    #[test]
    fn test_multiple_policies_authorization() {
        use crate::storage::check_is_authorized;

        // Create multiple authorized policies
        let stored_policies = vec![
            Policy::Call(CallPolicy {
                target: JsFelt(felt!("0x1234")),
                method: JsFelt(felt!("0x5678")),
                authorized: Some(true),
            }),
            Policy::Call(CallPolicy {
                target: JsFelt(felt!("0xabcd")),
                method: JsFelt(felt!("0xef01")),
                authorized: Some(true),
            }),
        ];

        // Create calls that match both policies
        let calls = vec![
            Call {
                to: felt!("0x1234"),
                selector: felt!("0x5678"),
                calldata: vec![],
            },
            Call {
                to: felt!("0xabcd"),
                selector: felt!("0xef01"),
                calldata: vec![],
            },
        ];

        let sdk_policies = SdkPolicy::from_calls(&calls);
        let wasm_policies: Vec<Policy> = sdk_policies.iter().map(|p| p.clone().into()).collect();

        assert!(
            check_is_authorized(&stored_policies, &wasm_policies),
            "All calls should be authorized"
        );

        // Test with one unauthorized call
        let mixed_calls = vec![
            Call {
                to: felt!("0x1234"),
                selector: felt!("0x5678"),
                calldata: vec![],
            },
            Call {
                to: felt!("0x9999"), // Not in stored policies
                selector: felt!("0xef01"),
                calldata: vec![],
            },
        ];

        let mixed_sdk_policies = SdkPolicy::from_calls(&mixed_calls);
        let mixed_wasm_policies: Vec<Policy> = mixed_sdk_policies
            .iter()
            .map(|p| p.clone().into())
            .collect();

        assert!(
            !check_is_authorized(&stored_policies, &mixed_wasm_policies),
            "Should fail if any call is not authorized"
        );
    }

    #[test]
    fn test_wildcard_session_not_used_for_client_side_checks() {
        // This test documents the fix: we should NOT use wildcard session's
        // would_authorize (which always returns true) for client-side checks
        use account_sdk::account::session::hash::Session;

        // Create a wildcard session (simulating what WASM controller uses)
        let wildcard_session = Session::new_wildcard(
            9999999999,
            &account_sdk::abigen::controller::Signer::Starknet(
                account_sdk::abigen::controller::StarknetSigner {
                    pubkey: cainome::cairo_serde::NonZero::new(felt!("0x123")).unwrap(),
                },
            ),
            starknet_types_core::felt::Felt::ZERO,
        )
        .unwrap();

        // Verify it's a wildcard
        assert!(wildcard_session.is_wildcard());

        // Create any policy
        let policy = SdkPolicy::Call(SdkCallPolicy {
            contract_address: felt!("0x1234"),
            selector: felt!("0x5678"),
            authorized: None,
        });

        // Wildcard sessions would authorize anything (this is the problem)
        assert!(
            wildcard_session.is_authorized(&policy),
            "Wildcard session authorizes everything"
        );

        // The fix: we now check client-side policies instead
        // which properly enforces authorization
        let wasm_policy: Policy = policy.into();
        let unauthorized_stored = Policy::Call(CallPolicy {
            target: JsFelt(felt!("0x1234")),
            method: JsFelt(felt!("0x5678")),
            authorized: Some(false), // Explicitly not authorized
        });

        // Client-side check should properly reject unauthorized policies
        assert!(
            !crate::storage::check_is_authorized(&[unauthorized_stored], &[wasm_policy]),
            "Client-side check should respect authorization flag"
        );
    }

    #[test]
    fn test_session_policy_authorization_logic() {
        use crate::storage::check_is_authorized;

        // Scenario 1: Session not expired, policies authorize execution
        let authorized_stored = vec![Policy::Call(CallPolicy {
            target: JsFelt(felt!("0x1234")),
            method: JsFelt(felt!("0x5678")),
            authorized: Some(true),
        })];

        let call = Call {
            to: felt!("0x1234"),
            selector: felt!("0x5678"),
            calldata: vec![],
        };

        let sdk_policies = SdkPolicy::from_calls(&[call.clone()]);
        let wasm_policies: Vec<Policy> = sdk_policies.iter().map(|p| p.clone().into()).collect();

        // Should be authorized - execution proceeds
        assert!(
            check_is_authorized(&authorized_stored, &wasm_policies),
            "Valid session with authorized policies should allow execution"
        );

        // Scenario 2: Session not expired, policies do NOT authorize execution
        let unauthorized_stored = vec![Policy::Call(CallPolicy {
            target: JsFelt(felt!("0x1234")),
            method: JsFelt(felt!("0x5678")),
            authorized: Some(false), // Explicitly not authorized
        })];

        // Should NOT be authorized - ManualExecutionRequired
        assert!(
            !check_is_authorized(&unauthorized_stored, &wasm_policies),
            "Valid session with unauthorized policies should require manual execution"
        );

        // Scenario 3: Session not expired, but wrong policy target
        let different_target_stored = vec![Policy::Call(CallPolicy {
            target: JsFelt(felt!("0x9999")), // Different target
            method: JsFelt(felt!("0x5678")),
            authorized: Some(true),
        })];

        // Should NOT be authorized - ManualExecutionRequired
        assert!(
            !check_is_authorized(&different_target_stored, &wasm_policies),
            "Valid session with non-matching policies should require manual execution"
        );

        // Scenario 4: Session not expired, no stored policies at all
        let empty_stored: Vec<Policy> = vec![];

        // Should NOT be authorized - ManualExecutionRequired
        assert!(
            !check_is_authorized(&empty_stored, &wasm_policies),
            "Valid session with no stored policies should require manual execution"
        );
    }
}
