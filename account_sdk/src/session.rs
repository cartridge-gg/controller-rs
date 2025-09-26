use cainome::cairo_serde::{CairoSerde, NonZero};
use serde::{Deserialize, Serialize};
use starknet::accounts::ConnectedAccount;
use starknet::core::types::{Call, FeeEstimate, Felt, InvokeTransactionResult};
use starknet::core::utils::parse_cairo_short_string;
use starknet::signers::{SigningKey, VerifyingKey};

use crate::abigen::controller::{Signer as AbigenSigner, SignerSignature, StarknetSigner};
use crate::account::session::account::SessionAccount;
use crate::account::session::hash::Session;
use crate::account::session::policy::Policy;
use crate::controller::Controller;
use crate::errors::ControllerError;
use crate::execute_from_outside::FeeSource;
use crate::graphql::run_query;
use crate::graphql::session::revoke_sessions::RevokeSessionInput;
use crate::graphql::session::{
    self, create_session, subscribe_create_session, CreateSession, SubscribeCreateSession,
};
use crate::hash::MessageHashRev1;
use crate::provider::ExecuteFromOutsideError;
use crate::signers::{HashSigner, Signer};
use crate::storage::{
    selectors::Selectors, Credentials, SessionMetadata, StorageBackend, StorageError,
};

#[cfg(all(test, not(target_arch = "wasm32")))]
#[path = "session_test.rs"]
mod session_test;

impl Controller {
    pub async fn create_session(
        &mut self,
        methods: Vec<Policy>,
        expires_at: u64,
    ) -> Result<SessionAccount, ControllerError> {
        self.create_session_with_guardian(methods, expires_at, Felt::ZERO)
            .await
    }

    pub async fn create_session_with_guardian(
        &mut self,
        methods: Vec<Policy>,
        expires_at: u64,
        guardian: Felt,
    ) -> Result<SessionAccount, ControllerError> {
        let signer = SigningKey::from_random();
        let session_signer = Signer::Starknet(signer.clone());

        let session = Session::new(
            methods,
            expires_at,
            &session_signer.clone().into(),
            guardian,
        )?;

        self.create_with_session(signer, session).await
    }

    pub async fn create_wildcard_session(
        &mut self,
        expires_at: u64,
    ) -> Result<SessionAccount, ControllerError> {
        let signer = SigningKey::from_random();
        let session_signer = Signer::Starknet(signer.clone());

        let session =
            Session::new_wildcard(expires_at, &session_signer.clone().into(), Felt::ZERO)?;

        self.create_with_session(signer, session).await
    }

    pub async fn create_with_session(
        &mut self,
        session_signer: SigningKey,
        session: Session,
    ) -> Result<SessionAccount, ControllerError> {
        let hash = session
            .inner
            .get_message_hash_rev_1(self.chain_id, self.address);
        let authorization = self.owner.sign(&hash).await?;
        let authorization = Vec::<SignerSignature>::cairo_serialize(&vec![authorization.clone()]);
        self.storage.set_session(
            &Selectors::session(&self.address, &self.app_id, &self.chain_id),
            SessionMetadata {
                session: session.clone(),
                max_fee: None,
                credentials: Some(Credentials {
                    authorization: authorization.clone(),
                    private_key: session_signer.secret_scalar(),
                }),
                is_registered: false,
            },
        )?;

        let session_account = SessionAccount::new(
            self.provider().clone(),
            Signer::Starknet(session_signer),
            self.address,
            self.chain_id,
            authorization.clone(),
            session.clone(),
        );

        Ok(session_account)
    }

    pub async fn register_session_with_cartridge(
        &self,
        session: &Session,
        authorization: &[Felt],
        cartridge_api_url: String,
    ) -> Result<(), ControllerError> {
        let _ = run_query::<CreateSession>(
            create_session::Variables {
                username: self.username.clone(),
                app_id: self.app_id.clone(),
                chain_id: parse_cairo_short_string(&self.chain_id).unwrap(),
                session: session::create_session::SessionInput {
                    expires_at: session.inner.expires_at,
                    allowed_policies_root: session.inner.allowed_policies_root,
                    metadata_hash: session.inner.metadata_hash,
                    session_key_guid: session.inner.session_key_guid,
                    guardian_key_guid: session.inner.guardian_key_guid,
                    authorization: authorization.to_vec(),
                    app_id: None,
                },
            },
            cartridge_api_url,
        )
        .await?;
        Ok(())
    }

    pub async fn revoke_sessions_with_cartridge(
        &self,
        sessions: &[RevokableSession],
        cartridge_api_url: String,
    ) -> Result<(), ControllerError> {
        let _ = session::revoke_sessions(
            sessions
                .iter()
                .map(|s| RevokeSessionInput {
                    session_hash: s.session_hash,
                    username: self.username.clone(),
                    chain_id: parse_cairo_short_string(&self.chain_id).unwrap(),
                })
                .collect(),
            cartridge_api_url,
        )
        .await?;
        Ok(())
    }

    pub fn register_session_call(
        &mut self,
        policies: Vec<Policy>,
        expires_at: u64,
        public_key: Felt,
        guardian: Felt,
    ) -> Result<Call, ControllerError> {
        let pubkey = VerifyingKey::from_scalar(public_key);
        let signer = AbigenSigner::Starknet(StarknetSigner {
            pubkey: NonZero::new(pubkey.scalar()).unwrap(),
        });
        let session = Session::new(policies, expires_at, &signer, guardian)?;
        let call = self
            .contract()
            .register_session_getcall(&session.into(), &self.owner_guid());

        Ok(call)
    }

    pub async fn register_session(
        &mut self,
        policies: Vec<Policy>,
        expires_at: u64,
        public_key: Felt,
        guardian: Felt,
        max_fee: Option<FeeEstimate>,
    ) -> Result<InvokeTransactionResult, ControllerError> {
        let session = Session::new(
            policies,
            expires_at,
            &AbigenSigner::Starknet(StarknetSigner {
                pubkey: NonZero::new(public_key).unwrap(),
            }),
            guardian,
        )?;

        let call = self
            .contract()
            .register_session_getcall(&session.clone().into(), &self.owner_guid());
        let txn = self.execute(vec![call], max_fee, None).await?;

        self.storage.set_session(
            &Selectors::session(&self.address, &self.app_id, &self.chain_id),
            SessionMetadata {
                session,
                max_fee: None,
                credentials: None,
                is_registered: true,
            },
        )?;

        Ok(txn)
    }

    pub async fn revoke_sessions(
        &mut self,
        sessions: Vec<RevokableSession>,
    ) -> Result<InvokeTransactionResult, ControllerError> {
        let calls = sessions
            .iter()
            .map(|session| {
                self.contract()
                    .revoke_session_getcall(&session.session_hash)
            })
            .collect();
        let txn = self
            .execute_from_outside_v3(calls, Some(FeeSource::Paymaster))
            .await?;

        for session in sessions {
            self.storage.remove(&Selectors::session(
                &self.address,
                &session.app_id,
                &session.chain_id,
            ))?;
        }

        Ok(txn)
    }

    pub fn authorized_session(&self) -> Option<SessionMetadata> {
        let key = self.session_key();
        self.storage.session(&key).ok().flatten()
    }

    pub fn authorized_session_for_policies(
        &self,
        policies: &[Policy],
        public_key: Option<Felt>,
    ) -> Option<SessionMetadata> {
        let key = self.session_key();
        self.storage
            .session(&key)
            .ok()
            .flatten()
            .filter(|metadata| metadata.is_authorized(policies, public_key))
    }

    pub fn is_requested_session(&self, policies: &[Policy], public_key: Option<Felt>) -> bool {
        let key = self.session_key();
        self.storage
            .session(&key)
            .ok()
            .flatten()
            .filter(|metadata| metadata.is_requested(policies, public_key))
            .is_some()
    }

    pub fn session_key(&self) -> String {
        Selectors::session(&self.address, &self.app_id, &self.chain_id)
    }

    pub fn session_account(&self, policies: &[Policy]) -> Option<SessionAccount> {
        // Return None if any policy contains a call to the controller's own address
        if policies.iter().any(|policy| match policy {
            Policy::Call(contract_policy) => contract_policy.contract_address == self.address,
            _ => false,
        }) {
            return None;
        }

        // Check if there's a valid session stored
        let metadata = self.authorized_session_for_policies(policies, None)?;
        let credentials = metadata.credentials.as_ref()?;
        let session_signer =
            Signer::Starknet(SigningKey::from_secret_scalar(credentials.private_key));
        let session_account = SessionAccount::new(
            self.provider().clone(),
            session_signer,
            self.address,
            self.chain_id,
            credentials.authorization.clone(),
            metadata.session,
        );

        Some(session_account)
    }

    pub async fn try_session_execute(
        &mut self,
        calls: Vec<Call>,
        fee_source: Option<FeeSource>,
    ) -> Result<InvokeTransactionResult, ControllerError> {
        let policies = Policy::from_calls(&calls);

        match self.authorized_session() {
            Some(metadata) => {
                if metadata.session.is_expired() {
                    if metadata.would_authorize(&policies, None) {
                        return Err(ControllerError::SessionRefreshRequired);
                    } else {
                        return Err(ControllerError::ManualExecutionRequired);
                    }
                }
            }
            None => return Err(ControllerError::ManualExecutionRequired),
        }

        match self
            .execute_from_outside_v3(calls.clone(), fee_source)
            .await
        {
            Ok(result) => Ok(result),
            Err(err) if is_paymaster_not_supported(&err) => {
                let estimate = self.estimate_invoke_fee(calls.clone()).await?;
                self.execute(calls, Some(estimate), fee_source).await
            }
            Err(err) => Err(err),
        }
    }

    pub fn clear_invalid_session(&mut self) {
        let mut controller_clone = self.clone();

        let _ = self.clear_session_if_expired();

        #[cfg(target_arch = "wasm32")]
        wasm_bindgen_futures::spawn_local(async move {
            let result = controller_clone.clear_session_if_revoked().await;
            if let Err(e) = result {
                web_sys::console::error_1(
                    &format!("Error clearing session if revoked: {}", e).into(),
                );
            }
        });

        #[cfg(not(target_arch = "wasm32"))]
        {
            let _ = std::thread::spawn(move || {
                if let Err(e) =
                    futures::executor::block_on(controller_clone.clear_session_if_revoked())
                {
                    println!("Error clearing session if revoked: {}", e);
                }
            });
        }
    }

    pub fn clear_session_if_expired(&mut self) -> Result<(), StorageError> {
        let key = self.session_key();
        let session = self.storage.session(&key).ok().flatten();

        if session.is_none() {
            return Ok(());
        }

        let session = session.expect("Checked for None above");

        if session.session.is_expired() {
            self.storage.remove(&key)?;
        }

        Ok(())
    }

    async fn clear_session_if_revoked(&mut self) -> Result<(), StorageError> {
        let key = self.session_key();
        let session = self.storage.session(&key).ok().flatten();

        if session.is_none() {
            return Ok(());
        }

        let session = session.expect("Checked for None above");

        let session_hash = session
            .session
            .inner
            .get_message_hash_rev_1(self.chain_id, self.address);

        let is_revoked = self
            .contract()
            .is_session_revoked(&session_hash)
            .call()
            .await
            .map_err(|e| StorageError::OperationFailed(e.to_string()))?;

        if is_revoked {
            self.storage.remove(&key)?;
        }

        Ok(())
    }
}

pub async fn subscribe_create_session(
    session_key_guid: Felt,
    cartridge_api_url: String,
) -> Result<subscribe_create_session::ResponseData, ControllerError> {
    run_query::<SubscribeCreateSession>(
        subscribe_create_session::Variables { session_key_guid },
        cartridge_api_url,
    )
    .await
}

fn is_paymaster_not_supported(err: &ControllerError) -> bool {
    matches!(err, ControllerError::PaymasterNotSupported)
        || matches!(
            err,
            ControllerError::PaymasterError(
                ExecuteFromOutsideError::ExecuteFromOutsideNotSupported(_)
            )
        )
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[allow(non_snake_case)]
pub struct RevokableSession {
    pub app_id: String,
    pub chain_id: Felt,
    pub session_hash: Felt,
}
