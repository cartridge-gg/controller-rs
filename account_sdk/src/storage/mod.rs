use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use starknet::{
    core::types::{EthAddress, Felt},
    signers::{SigningKey, VerifyingKey},
};

use crate::{
    account::session::{hash::Session, policy::Policy},
    errors::ControllerError,
};

#[cfg(feature = "webauthn")]
use {
    crate::signers::webauthn::CredentialID,
    base64::{engine::general_purpose, Engine},
    coset::{CborSerializable, CoseKey},
};

#[cfg(all(not(target_arch = "wasm32"), feature = "filestorage"))]
pub mod filestorage;
#[cfg(not(target_arch = "wasm32"))]
pub mod inmemory;
#[cfg(target_arch = "wasm32")]
pub mod localstorage;
pub mod selectors;

#[cfg(all(test, not(target_arch = "wasm32")))]
#[path = "storage_test.rs"]
mod storage_test;

#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("Storage operation failed: {0}")]
    OperationFailed(String),
    #[error("Type mismatch in storage")]
    TypeMismatch,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebauthnSigner {
    pub rp_id: String,
    pub credential_id: String,
    pub public_key: String,
}

#[cfg(feature = "webauthn")]
type WebauthnSigners = Vec<WebauthnSigner>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StarknetSigner {
    pub private_key: Felt,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Eip191Signer {
    pub address: EthAddress,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Signer {
    Starknet(StarknetSigner),
    #[cfg(feature = "webauthn")]
    Webauthn(WebauthnSigner),
    #[cfg(feature = "webauthn")]
    Webauthns(WebauthnSigners),
    Eip191(Eip191Signer),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Owner {
    Signer(Signer),
    Account(Felt),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControllerMetadata {
    pub username: String,
    pub class_hash: Felt,
    pub rpc_url: String,
    pub salt: Felt,
    pub owner: Owner,
    pub address: Felt,
    pub chain_id: Felt,
}

use crate::controller::Controller;

impl From<&Controller> for ControllerMetadata {
    fn from(controller: &Controller) -> Self {
        ControllerMetadata {
            address: controller.address,
            class_hash: controller.class_hash,
            chain_id: controller.chain_id,
            rpc_url: controller.rpc_url.to_string(),
            salt: controller.salt,
            owner: (&controller.owner).into(),
            username: controller.username.clone(),
        }
    }
}

impl From<&crate::signers::Owner> for Owner {
    fn from(owner: &crate::signers::Owner) -> Self {
        match owner {
            crate::signers::Owner::Signer(signer) => Owner::Signer(signer.into()),
            crate::signers::Owner::Account(address) => Owner::Account(*address),
        }
    }
}

impl From<&crate::signers::Signer> for Signer {
    fn from(signer: &crate::signers::Signer) -> Self {
        match signer {
            crate::signers::Signer::Starknet(s) => Signer::Starknet(s.into()),
            #[cfg(feature = "webauthn")]
            crate::signers::Signer::Webauthn(s) => Signer::Webauthn(s.into()),
            #[cfg(feature = "webauthn")]
            crate::signers::Signer::Webauthns(s) => {
                Signer::Webauthns(s.iter().map(|s| s.into()).collect())
            }
            crate::signers::Signer::Eip191(s) => Signer::Eip191(s.into()),
        }
    }
}

impl From<&SigningKey> for StarknetSigner {
    fn from(signer: &SigningKey) -> Self {
        StarknetSigner {
            private_key: signer.secret_scalar(),
        }
    }
}

#[cfg(feature = "webauthn")]
impl From<&crate::signers::webauthn::WebauthnSigner> for WebauthnSigner {
    fn from(signer: &crate::signers::webauthn::WebauthnSigner) -> Self {
        WebauthnSigner {
            rp_id: signer.rp_id.clone(),
            credential_id: base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(signer.credential_id.as_ref()),
            public_key: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(
                signer
                    .pub_key
                    .clone()
                    .to_vec()
                    .expect("Public Key serialize to bytes"),
            ),
        }
    }
}

impl From<&crate::signers::eip191::Eip191Signer> for Eip191Signer {
    fn from(signer: &crate::signers::eip191::Eip191Signer) -> Self {
        Eip191Signer {
            address: signer.address(),
        }
    }
}

#[cfg(feature = "webauthn")]
impl TryFrom<WebauthnSigner> for crate::signers::webauthn::WebauthnSigner {
    type Error = ControllerError;
    fn try_from(signer: WebauthnSigner) -> Result<Self, Self::Error> {
        let credential_id_bytes = general_purpose::URL_SAFE_NO_PAD.decode(signer.credential_id)?;
        let credential_id = CredentialID::from(credential_id_bytes);

        let cose_bytes = general_purpose::URL_SAFE_NO_PAD.decode(signer.public_key)?;
        let cose = CoseKey::from_slice(&cose_bytes)?;

        Ok(Self {
            rp_id: signer.rp_id,
            credential_id,
            pub_key: cose,
        })
    }
}

impl TryFrom<Signer> for crate::signers::Signer {
    type Error = ControllerError;

    fn try_from(signer: Signer) -> Result<Self, Self::Error> {
        match signer {
            Signer::Starknet(s) => Ok(Self::Starknet(SigningKey::from_secret_scalar(
                s.private_key,
            ))),
            #[cfg(feature = "webauthn")]
            Signer::Webauthn(w) => Ok(Self::Webauthn(w.try_into()?)),
            #[cfg(feature = "webauthn")]
            Signer::Webauthns(s) => Ok(Self::Webauthns(
                s.iter()
                    .map(|s| s.clone().try_into())
                    .collect::<Result<Vec<_>, _>>()?,
            )),
            Signer::Eip191(s) => Ok(Self::Eip191(crate::signers::eip191::Eip191Signer {
                // Storage wont work with native signer until this is fixed to properly store the private key
                #[cfg(not(target_arch = "wasm32"))]
                signing_key: crate::signers::eip191::Eip191Signer::random().signing_key,
                address: s.address,
            })),
        }
    }
}

impl TryFrom<Owner> for crate::signers::Owner {
    type Error = ControllerError;

    fn try_from(owner: Owner) -> Result<Self, Self::Error> {
        match owner {
            Owner::Signer(signer) => Ok(crate::signers::Owner::Signer(signer.try_into()?)),
            Owner::Account(address) => Ok(crate::signers::Owner::Account(address)),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SessionMetadata {
    pub session: Session,
    pub max_fee: Option<Felt>,
    pub credentials: Option<Credentials>,
    pub is_registered: bool,
}

impl SessionMetadata {
    pub fn is_authorized(&self, policies: &[Policy], public_key: Option<Felt>) -> bool {
        let public_key = if let Some(public_key) = public_key {
            let pubkey = VerifyingKey::from_scalar(public_key);
            pubkey.scalar()
        } else if let Some(credentials) = &self.credentials {
            let signer = SigningKey::from_secret_scalar(credentials.private_key);
            signer.verifying_key().scalar()
        } else {
            return false;
        };

        !self.session.is_expired()
            && self.session.is_session_key(public_key)
            && policies
                .iter()
                .all(|policy| self.session.is_authorized(policy))
    }

    pub fn is_requested(&self, policies: &[Policy], public_key: Option<Felt>) -> bool {
        let public_key = if let Some(public_key) = public_key {
            let pubkey = VerifyingKey::from_scalar(public_key);
            pubkey.scalar()
        } else if let Some(credentials) = &self.credentials {
            let signer = SigningKey::from_secret_scalar(credentials.private_key);
            signer.verifying_key().scalar()
        } else {
            return false;
        };

        !self.session.is_expired()
            && self.session.is_session_key(public_key)
            && policies
                .iter()
                .all(|policy| self.session.is_requested(policy))
    }

    pub fn is_wildcard(&self) -> bool {
        self.session.is_wildcard()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct Credentials {
    pub authorization: Vec<Felt>,
    pub private_key: Felt,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct ActiveMetadata {
    address: Felt,
    chain_id: Felt,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StorageValue {
    Active(ActiveMetadata),
    Controller(ControllerMetadata),
    Session(SessionMetadata),
}

#[async_trait]
pub trait StorageBackend: Send + Sync {
    fn set(&mut self, key: &str, value: &StorageValue) -> Result<(), StorageError>;
    fn set_serialized(&mut self, key: &str, value: &str) -> Result<(), StorageError>;
    fn get(&self, key: &str) -> Result<Option<StorageValue>, StorageError>;
    fn remove(&mut self, key: &str) -> Result<(), StorageError>;
    fn clear(&mut self) -> Result<(), StorageError>;
    fn keys(&self) -> Result<Vec<String>, StorageError>;

    fn session(&self, key: &str) -> Result<Option<SessionMetadata>, StorageError> {
        self.get(key).and_then(|value| match value {
            Some(StorageValue::Session(metadata)) => Ok(Some(metadata)),
            Some(_) => Err(StorageError::TypeMismatch),
            None => Ok(None),
        })
    }

    fn set_session(&mut self, key: &str, metadata: SessionMetadata) -> Result<(), StorageError> {
        self.set(key, &StorageValue::Session(metadata))
    }

    fn controller(&self, app_id: &str) -> Result<Option<ControllerMetadata>, StorageError> {
        let active_value = self.get(&selectors::Selectors::active(app_id))?;
        match active_value {
            Some(StorageValue::Active(metadata)) => {
                let account_value = self.get(&selectors::Selectors::account(
                    &metadata.address,
                    &metadata.chain_id,
                ))?;

                match account_value {
                    Some(StorageValue::Controller(metadata)) => Ok(Some(metadata)),
                    Some(_) => Err(StorageError::TypeMismatch),
                    None => Ok(None),
                }
            }
            Some(_) => Err(StorageError::TypeMismatch),
            None => Ok(None),
        }
    }

    fn set_controller(
        &mut self,
        app_id: &str,
        chain_id: &Felt,
        address: Felt,
        metadata: ControllerMetadata,
    ) -> Result<(), StorageError> {
        self.set(
            &selectors::Selectors::active(app_id),
            &StorageValue::Active(ActiveMetadata {
                address,
                chain_id: *chain_id,
            }),
        )?;
        self.set(
            &selectors::Selectors::account(&address, chain_id),
            &StorageValue::Controller(metadata),
        )
    }
}

#[cfg(all(not(target_arch = "wasm32"), not(feature = "filestorage")))]
pub type Storage = inmemory::InMemoryBackend;

#[cfg(target_arch = "wasm32")]
pub type Storage = localstorage::LocalStorage;

#[cfg(all(not(target_arch = "wasm32"), feature = "filestorage"))]
pub type Storage = filestorage::FileSystemBackend;
