use cainome::cairo_serde;
use starknet::{
    accounts::{AccountError, AccountFactoryError},
    core::types::FeeEstimate,
    providers::ProviderError,
};

use crate::{api, provider::ExecuteFromOutsideError, signers::SignError};

#[derive(Debug, thiserror::Error)]
pub enum ControllerError {
    #[error(transparent)]
    SignError(#[from] SignError),

    #[error(transparent)]
    StorageError(#[from] crate::storage::StorageError),

    #[error(transparent)]
    AccountError(#[from] AccountError<SignError>),

    #[error("Controller is not deployed. Required fee: {fee_estimate:?}")]
    NotDeployed {
        fee_estimate: Box<FeeEstimate>,
        balance: u128,
    },

    #[error(transparent)]
    AccountFactoryError(#[from] AccountFactoryError<SignError>),

    #[error(transparent)]
    PaymasterError(#[from] ExecuteFromOutsideError),

    #[error(transparent)]
    CairoSerde(#[from] cairo_serde::Error),

    #[error(transparent)]
    ProviderError(#[from] ProviderError),

    #[error("Insufficient balance for transaction. Required fee: {fee_estimate:?}")]
    InsufficientBalance {
        fee_estimate: Box<FeeEstimate>,
        balance: u128,
    },

    #[error("Session already registered. ")]
    SessionAlreadyRegistered,

    #[error(transparent)]
    UrlParseError(#[from] url::ParseError),

    #[cfg(feature = "webauthn")]
    #[error(transparent)]
    Base64DecodeError(#[from] base64::DecodeError),

    #[cfg(feature = "webauthn")]
    #[error(transparent)]
    CoseError(#[from] coset::CoseError),

    #[error(transparent)]
    Api(#[from] api::GraphQLErrors),

    #[error(transparent)]
    ReqwestError(#[from] reqwest::Error),

    #[error("Invalid owner data: {0}")]
    InvalidOwner(String),

    #[error("Transaction reverted: {0}")]
    TransactionReverted(String),

    #[error("Invalid response data: {0}")]
    InvalidResponseData(String),

    #[error("Transaction timeout")]
    TransactionTimeout,
}
