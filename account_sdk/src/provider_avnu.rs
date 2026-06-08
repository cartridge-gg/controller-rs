use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use starknet::core::serde::unsigned_field_element::UfeHex;
use starknet::core::types::{Call, Felt};
use starknet::providers::jsonrpc::JsonRpcResponse;
use url::Url;

use crate::provider::{
    is_execute_from_outside_rate_limited, ExecuteFromOutsideError, ExecuteFromOutsideResponse,
};
use crate::rate_limit::{retry_with_policy, RetryPolicy};

/// JSON-RPC request for AVNU paymaster API
#[derive(Debug, Serialize)]
struct AvnuJsonRpcRequest<T> {
    id: u64,
    jsonrpc: &'static str,
    method: &'static str,
    params: T,
}

#[cfg(test)]
#[path = "provider_avnu_test.rs"]
mod provider_avnu_test;

/// Provider for the AVNU Paymaster API
#[derive(Debug, Clone)]
pub struct AvnuPaymasterProvider {
    paymaster_url: Url,
    client: Client,
    api_key: Option<String>,
    retry_policy: RetryPolicy,
}

impl AvnuPaymasterProvider {
    pub fn new(paymaster_url: Url) -> Self {
        Self {
            paymaster_url,
            client: Client::new(),
            api_key: None,
            retry_policy: RetryPolicy::default(),
        }
    }

    /// Create a new provider with an API key for sponsored transactions
    pub fn with_api_key(paymaster_url: Url, api_key: String) -> Self {
        Self {
            paymaster_url,
            client: Client::new(),
            api_key: Some(api_key),
            retry_policy: RetryPolicy::default(),
        }
    }

    pub fn with_retry_policy(mut self, retry_policy: RetryPolicy) -> Self {
        self.retry_policy = retry_policy;
        self
    }

    /// Execute a direct transaction through the AVNU paymaster.
    /// This is the version-agnostic endpoint that accepts a pre-built execute_from_outside call.
    pub async fn execute_raw_transaction(
        &self,
        request: ExecuteRawRequest,
    ) -> Result<ExecuteRawResponse, ExecuteFromOutsideError> {
        self.execute_direct_transaction(request).await
    }

    /// Execute a direct transaction through the AVNU paymaster.
    /// This maps to the `paymaster_executeDirectTransaction` JSON-RPC method.
    pub async fn execute_direct_transaction(
        &self,
        request: ExecuteRawRequest,
    ) -> Result<ExecuteRawResponse, ExecuteFromOutsideError> {
        retry_with_policy(
            self.retry_policy,
            || async {
                let rpc_request = AvnuJsonRpcRequest {
                    id: 1,
                    jsonrpc: "2.0",
                    method: "paymaster_executeDirectTransaction",
                    params: request.clone(),
                };

                let mut req = self
                    .client
                    .post(self.paymaster_url.as_str())
                    .header("Content-Type", "application/json");

                // Add API key header if present (required for sponsored transactions)
                if let Some(api_key) = &self.api_key {
                    req = req.header("x-paymaster-api-key", api_key);
                }

                let response = req.json(&rpc_request).send().await?;

                if response.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
                    return Err(ExecuteFromOutsideError::RateLimitExceeded);
                }

                let json_rpc_response: JsonRpcResponse<ExecuteRawResponse> =
                    response.json().await?;

                match json_rpc_response {
                    JsonRpcResponse::Success { result, .. } => Ok(result),
                    JsonRpcResponse::Error { error, .. } => Err(error.into()),
                }
            },
            is_execute_from_outside_rate_limited,
        )
        .await
    }
}

/// Request for paymaster_executeDirectTransaction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecuteRawRequest {
    pub transaction: ExecuteRawTransactionParams,
    pub parameters: ExecutionParameters,
}

/// Transaction parameters for direct execute
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ExecuteRawTransactionParams {
    #[serde(rename = "invoke")]
    DirectInvoke { invoke: DirectInvokeParams },
}

/// Parameters for a direct invoke transaction
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirectInvokeParams {
    #[serde_as(as = "UfeHex")]
    pub user_address: Felt,
    pub execute_from_outside_call: Call,
}

/// Execution parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "version")]
pub enum ExecutionParameters {
    #[serde(rename = "0x1")]
    V1 {
        fee_mode: FeeMode,
        #[serde(default)]
        time_bounds: Option<TimeBounds>,
    },
}

/// Fee mode for the transaction
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum FeeMode {
    Default {
        #[serde_as(as = "UfeHex")]
        gas_token: Felt,
        #[serde(default)]
        tip: TipPriority,
    },
    Sponsored {
        #[serde(default)]
        tip: TipPriority,
    },
}

/// Priority to apply when estimating transaction tips.
#[derive(Debug, Serialize, Deserialize, Copy, Clone, Default)]
#[serde(rename_all = "snake_case")]
pub enum TipPriority {
    Slow,
    #[default]
    Normal,
    Fast,
    Custom(u64),
}

/// Time bounds for the transaction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeBounds {
    pub execute_after: u64,
    pub execute_before: u64,
}

/// Response from paymaster_executeDirectTransaction
#[serde_as]
#[derive(Debug, Deserialize, Serialize)]
pub struct ExecuteRawResponse {
    #[serde_as(as = "UfeHex")]
    pub transaction_hash: Felt,
    #[serde_as(as = "UfeHex")]
    pub tracking_id: Felt,
}

impl From<ExecuteRawResponse> for ExecuteFromOutsideResponse {
    fn from(response: ExecuteRawResponse) -> Self {
        ExecuteFromOutsideResponse {
            transaction_hash: response.transaction_hash,
        }
    }
}
