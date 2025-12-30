use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use serde_with::serde_as;
use starknet::core::serde::unsigned_field_element::UfeHex;
use starknet::core::types::{Call, Felt};
use starknet::providers::jsonrpc::JsonRpcResponse;
use url::Url;

use crate::provider::{ExecuteFromOutsideError, ExecuteFromOutsideResponse};

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
}

impl AvnuPaymasterProvider {
    pub fn new(paymaster_url: Url) -> Self {
        Self {
            paymaster_url,
            client: Client::new(),
            api_key: None,
        }
    }

    /// Create a new provider with an API key for sponsored transactions
    pub fn with_api_key(paymaster_url: Url, api_key: String) -> Self {
        Self {
            paymaster_url,
            client: Client::new(),
            api_key: Some(api_key),
        }
    }

    /// Execute a raw transaction through the AVNU paymaster.
    /// This is the version-agnostic endpoint that accepts a pre-built execute_from_outside call.
    pub async fn execute_raw_transaction(
        &self,
        request: ExecuteRawRequest,
    ) -> Result<ExecuteRawResponse, ExecuteFromOutsideError> {
        let rpc_request = AvnuJsonRpcRequest {
            id: 1,
            jsonrpc: "2.0",
            method: "paymaster_executeRawTransaction",
            params: request,
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

        let json_response: Value = response.json().await?;
        let json_rpc_response: JsonRpcResponse<ExecuteRawResponse> =
            serde_json::from_value(json_response)?;

        match json_rpc_response {
            JsonRpcResponse::Success { result, .. } => Ok(result),
            JsonRpcResponse::Error { error, .. } => Err(error.into()),
        }
    }
}

/// Request for paymaster_executeRawTransaction
#[derive(Debug, Serialize, Deserialize)]
pub struct ExecuteRawRequest {
    pub transaction: ExecuteRawTransactionParams,
    pub parameters: ExecutionParameters,
}

/// Transaction parameters for raw execute
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ExecuteRawTransactionParams {
    RawInvoke { invoke: RawInvokeParams },
}

/// Parameters for a raw invoke transaction
#[serde_as]
#[derive(Debug, Serialize, Deserialize)]
pub struct RawInvokeParams {
    #[serde_as(as = "UfeHex")]
    pub user_address: Felt,
    pub execute_from_outside_call: Call,
    #[serde_as(as = "Option<UfeHex>")]
    #[serde(default)]
    pub gas_token: Option<Felt>,
    #[serde_as(as = "Option<UfeHex>")]
    #[serde(default)]
    pub max_gas_token_amount: Option<Felt>,
}

/// Execution parameters
#[derive(Debug, Serialize, Deserialize)]
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
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum FeeMode {
    Default {
        #[serde_as(as = "UfeHex")]
        gas_token: Felt,
    },
    Sponsored,
}

/// Time bounds for the transaction
#[derive(Debug, Serialize, Deserialize)]
pub struct TimeBounds {
    pub execute_after: u64,
    pub execute_before: u64,
}

/// Response from paymaster_executeRawTransaction
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
