use account_sdk::controller::Controller;
use serde::{Deserialize, Serialize};
use starknet::core::utils::cairo_short_string_to_felt;
use tsify_next::Tsify;
use wasm_bindgen::JsValue;

use super::owner::Owner;
use super::policy::Policy;
use super::session::Credentials;
use super::{EncodingError, JsFelt};

#[allow(non_snake_case)]
#[derive(Tsify, Serialize, Deserialize, Debug, Clone)]
#[tsify(into_wasm_abi, from_wasm_abi)]
#[serde(rename_all = "camelCase")]
pub struct ImportedControllerMetadata {
    pub username: String,
    pub class_hash: JsFelt,
    pub rpc_url: String,
    pub salt: JsFelt,
    pub owner: Owner,
    pub address: JsFelt,
    pub chain_id: JsFelt,
}

impl TryFrom<JsValue> for ImportedControllerMetadata {
    type Error = EncodingError;

    fn try_from(value: JsValue) -> Result<Self, Self::Error> {
        Ok(serde_wasm_bindgen::from_value(value)?)
    }
}

impl From<&Controller> for ImportedControllerMetadata {
    fn from(value: &Controller) -> Self {
        Self {
            username: value.username.clone(),
            class_hash: value.class_hash.into(),
            rpc_url: value.rpc_url.to_string(),
            salt: cairo_short_string_to_felt(&value.username)
                .expect("controller username should always be a valid short string")
                .into(),
            owner: value.owner.clone().into(),
            address: value.address.into(),
            chain_id: value.chain_id.into(),
        }
    }
}

#[allow(non_snake_case)]
#[derive(Tsify, Serialize, Deserialize, Debug, Clone, PartialEq)]
#[tsify(into_wasm_abi, from_wasm_abi)]
#[serde(rename_all = "camelCase")]
pub struct ImportedProvedPolicy {
    pub policy: Policy,
    pub proof: Vec<JsFelt>,
}

impl From<account_sdk::account::session::policy::ProvedPolicy> for ImportedProvedPolicy {
    fn from(value: account_sdk::account::session::policy::ProvedPolicy) -> Self {
        Self {
            policy: value.policy.into(),
            proof: value.proof.into_iter().map(Into::into).collect(),
        }
    }
}

impl TryFrom<ImportedProvedPolicy> for account_sdk::account::session::policy::ProvedPolicy {
    type Error = EncodingError;

    fn try_from(value: ImportedProvedPolicy) -> Result<Self, Self::Error> {
        Ok(Self {
            policy: value.policy.try_into()?,
            proof: value
                .proof
                .into_iter()
                .map(TryInto::try_into)
                .collect::<Result<Vec<_>, _>>()?,
        })
    }
}

#[allow(non_snake_case)]
#[derive(Tsify, Serialize, Deserialize, Debug, Clone, PartialEq)]
#[tsify(into_wasm_abi, from_wasm_abi)]
#[serde(rename_all = "camelCase")]
pub struct ImportedSession {
    pub requested_policies: Vec<Policy>,
    pub proved_policies: Vec<ImportedProvedPolicy>,
    pub expires_at: u64,
    pub allowed_policies_root: JsFelt,
    pub metadata_hash: JsFelt,
    pub session_key_guid: JsFelt,
    pub guardian_key_guid: JsFelt,
    pub metadata: String,
}

impl From<account_sdk::account::session::hash::Session> for ImportedSession {
    fn from(value: account_sdk::account::session::hash::Session) -> Self {
        Self {
            requested_policies: value
                .requested_policies
                .into_iter()
                .map(Into::into)
                .collect(),
            proved_policies: value.proved_policies.into_iter().map(Into::into).collect(),
            expires_at: value.inner.expires_at,
            allowed_policies_root: value.inner.allowed_policies_root.into(),
            metadata_hash: value.inner.metadata_hash.into(),
            session_key_guid: value.inner.session_key_guid.into(),
            guardian_key_guid: value.inner.guardian_key_guid.into(),
            metadata: value.metadata,
        }
    }
}

impl TryFrom<ImportedSession> for account_sdk::account::session::hash::Session {
    type Error = EncodingError;

    fn try_from(value: ImportedSession) -> Result<Self, Self::Error> {
        Ok(Self {
            inner: account_sdk::abigen::controller::Session {
                expires_at: value.expires_at,
                allowed_policies_root: value.allowed_policies_root.try_into()?,
                metadata_hash: value.metadata_hash.try_into()?,
                session_key_guid: value.session_key_guid.try_into()?,
                guardian_key_guid: value.guardian_key_guid.try_into()?,
            },
            requested_policies: value
                .requested_policies
                .into_iter()
                .map(TryInto::try_into)
                .collect::<Result<Vec<_>, _>>()?,
            proved_policies: value
                .proved_policies
                .into_iter()
                .map(TryInto::try_into)
                .collect::<Result<Vec<_>, _>>()?,
            metadata: value.metadata,
        })
    }
}

#[allow(non_snake_case)]
#[derive(Tsify, Serialize, Deserialize, Debug, Clone)]
#[tsify(into_wasm_abi, from_wasm_abi)]
#[serde(rename_all = "camelCase")]
pub struct ImportedSessionMetadata {
    pub session: ImportedSession,
    #[tsify(optional)]
    pub max_fee: Option<JsFelt>,
    #[tsify(optional)]
    pub credentials: Option<Credentials>,
    pub is_registered: bool,
    #[tsify(optional)]
    pub app_id: Option<String>,
    #[tsify(optional)]
    pub policies: Option<Vec<Policy>>,
}

impl TryFrom<JsValue> for ImportedSessionMetadata {
    type Error = EncodingError;

    fn try_from(value: JsValue) -> Result<Self, Self::Error> {
        Ok(serde_wasm_bindgen::from_value(value)?)
    }
}

impl From<account_sdk::storage::SessionMetadata> for ImportedSessionMetadata {
    fn from(value: account_sdk::storage::SessionMetadata) -> Self {
        Self {
            session: value.session.into(),
            max_fee: value.max_fee.map(Into::into),
            credentials: value.credentials.map(Into::into),
            is_registered: value.is_registered,
            app_id: None,
            policies: None,
        }
    }
}

impl TryFrom<ImportedSessionMetadata> for account_sdk::storage::SessionMetadata {
    type Error = EncodingError;

    fn try_from(value: ImportedSessionMetadata) -> Result<Self, Self::Error> {
        if !value.is_registered && value.credentials.is_none() {
            return Err(EncodingError::UnexpectedOption(
                "Imported session requires credentials unless it is already registered".to_string(),
            ));
        }

        Ok(Self {
            session: value.session.try_into()?,
            max_fee: value.max_fee.map(TryInto::try_into).transpose()?,
            credentials: value.credentials.map(TryInto::try_into).transpose()?,
            is_registered: value.is_registered,
        })
    }
}

#[cfg(test)]
mod tests {
    use account_sdk::account::session::hash::Session;
    use account_sdk::account::session::policy::{CallPolicy, Policy as SdkPolicy, TypedDataPolicy};
    use account_sdk::signers::Signer;
    use account_sdk::storage::{Credentials, SessionMetadata};
    use starknet::core::types::Felt;
    use starknet::signers::SigningKey;

    use super::ImportedSessionMetadata;

    #[test]
    fn wildcard_session_roundtrip_preserves_metadata() {
        let session_signer = Signer::Starknet(SigningKey::from_secret_scalar(Felt::from(321u64)));
        let session = Session::new_wildcard(1_700_000_000, &session_signer.into(), Felt::ZERO)
            .expect("wildcard session should build");
        let metadata = SessionMetadata {
            session,
            max_fee: Some(Felt::from(55u64)),
            credentials: Some(Credentials {
                authorization: vec![Felt::from(1u64), Felt::from(2u64)],
                private_key: Felt::from(321u64),
            }),
            is_registered: false,
        };

        let imported = ImportedSessionMetadata::from(metadata.clone());
        let restored = SessionMetadata::try_from(imported).expect("roundtrip should succeed");

        assert_eq!(restored, metadata);
        assert!(restored.session.is_wildcard());
    }

    #[test]
    fn policy_session_roundtrip_preserves_requested_and_proved_policies() {
        let session_signer = Signer::Starknet(SigningKey::from_secret_scalar(Felt::from(654u64)));
        let session = Session::new(
            vec![
                SdkPolicy::Call(CallPolicy {
                    contract_address: Felt::from(11u64),
                    selector: Felt::from(12u64),
                    authorized: Some(true),
                }),
                SdkPolicy::TypedData(TypedDataPolicy {
                    scope_hash: Felt::from(13u64),
                    authorized: Some(false),
                }),
            ],
            1_800_000_000,
            &session_signer.into(),
            Felt::from(99u64),
        )
        .expect("policy session should build");

        let metadata = SessionMetadata {
            session,
            max_fee: None,
            credentials: Some(Credentials {
                authorization: vec![Felt::from(21u64), Felt::from(22u64)],
                private_key: Felt::from(654u64),
            }),
            is_registered: true,
        };

        let imported = ImportedSessionMetadata::from(metadata.clone());
        let restored = SessionMetadata::try_from(imported).expect("roundtrip should succeed");

        assert_eq!(restored, metadata);
        assert_eq!(restored.session.requested_policies.len(), 2);
        assert_eq!(restored.session.proved_policies.len(), 1);
    }

    #[test]
    fn import_requires_credentials_for_unregistered_sessions() {
        let session_signer = Signer::Starknet(SigningKey::from_secret_scalar(Felt::from(777u64)));
        let session = Session::new_wildcard(1_900_000_000, &session_signer.into(), Felt::ZERO)
            .expect("wildcard session should build");
        let mut imported = ImportedSessionMetadata::from(SessionMetadata {
            session,
            max_fee: None,
            credentials: Some(Credentials {
                authorization: vec![Felt::from(31u64)],
                private_key: Felt::from(777u64),
            }),
            is_registered: false,
        });
        imported.credentials = None;

        assert!(SessionMetadata::try_from(imported).is_err());
    }
}
