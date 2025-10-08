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
    PaymasterError(ExecuteFromOutsideError),

    #[error("Paymaster not supported")]
    PaymasterNotSupported,

    #[error("Session refresh required")]
    SessionRefreshRequired,

    #[error("Manual execution required")]
    ManualExecutionRequired,

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

    #[error("Failed to parse cairo short string: {0}")]
    ParseCairoShortString(#[from] starknet::core::utils::ParseCairoShortStringError),

    #[error("Conversion error: {0}")]
    ConversionError(String),

    #[error("Expected: {0}, Got {1}")]
    InvalidChainID(String, String),

    #[error("Forbidden entrypoint: {0}")]
    ForbiddenEntrypoint(String),
}

impl From<ExecuteFromOutsideError> for ControllerError {
    fn from(error: ExecuteFromOutsideError) -> Self {
        match error {
            ExecuteFromOutsideError::ExecuteFromOutsideNotSupported(_) => {
                ControllerError::PaymasterNotSupported
            }
            other => ControllerError::PaymasterError(other),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::ExecuteFromOutsideError;

    #[test]
    fn test_execute_from_outside_not_supported_maps_to_paymaster_not_supported() {
        let error = ExecuteFromOutsideError::ExecuteFromOutsideNotSupported(
            "insufficient credits and no applicable paymaster found".to_string(),
        );
        let controller_error: ControllerError = error.into();

        assert!(matches!(
            controller_error,
            ControllerError::PaymasterNotSupported
        ));
    }

    #[test]
    fn test_other_execute_from_outside_errors_map_to_paymaster_error() {
        let error = ExecuteFromOutsideError::RateLimitExceeded;
        let controller_error: ControllerError = error.into();

        assert!(matches!(
            controller_error,
            ControllerError::PaymasterError(_)
        ));
    }
}
