use async_trait::async_trait;
use auto_impl::auto_impl;
use nom::AsChar;
use starknet::core::types::{
    BlockHashAndNumber, BlockId, BroadcastedDeclareTransaction,
    BroadcastedDeployAccountTransaction, BroadcastedInvokeTransaction, BroadcastedTransaction,
    ConfirmedBlockId, ContractClass, ContractExecutionError, DeclareTransactionResult,
    DeployAccountTransactionResult, EventFilter, EventsPage, FeeEstimate, Felt, FunctionCall,
    Hash256, InvokeTransactionResult, MaybePreConfirmedBlockWithReceipts,
    MaybePreConfirmedBlockWithTxHashes, MaybePreConfirmedBlockWithTxs,
    MaybePreConfirmedStateUpdate, MessageFeeEstimate, MsgFromL1, SimulatedTransaction,
    SimulationFlag, SimulationFlagForEstimateFee, SyncStatusType, Transaction,
    TransactionExecutionErrorData, TransactionReceiptWithBlockInfo, TransactionStatus,
    TransactionTrace, TransactionTraceWithHash,
};
use starknet::providers::jsonrpc::HttpTransport;
use starknet::providers::{
    JsonRpcClient, Provider, ProviderError, ProviderRequestData, ProviderResponseData,
};
use url::Url;

use crate::account::outside_execution::OutsideExecution;
use crate::constants::VALIDATION_GAS;
use crate::execute_from_outside::FeeSource;

#[cfg(test)]
#[path = "provider_test.rs"]
mod provider_test;

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[auto_impl(&, Arc)]
pub trait CartridgeProvider: Provider + Clone {
    async fn add_execute_outside_transaction(
        &self,
        outside_execution: OutsideExecution,
        address: Felt,
        signature: Vec<Felt>,
        fee_source: Option<FeeSource>,
    ) -> Result<ExecuteFromOutsideResponse, ExecuteFromOutsideError>;
}

#[derive(Debug)]
pub struct CartridgeJsonRpcProvider {
    inner: JsonRpcClient<HttpTransport>,
    rpc_url: Url,
}

impl Clone for CartridgeJsonRpcProvider {
    fn clone(&self) -> Self {
        Self {
            inner: JsonRpcClient::new(HttpTransport::new(self.rpc_url.clone())),
            rpc_url: self.rpc_url.clone(),
        }
    }
}

impl CartridgeJsonRpcProvider {
    pub fn new(rpc_url: Url) -> Self {
        Self {
            inner: JsonRpcClient::new(HttpTransport::new(rpc_url.clone())),
            rpc_url,
        }
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl CartridgeProvider for CartridgeJsonRpcProvider {
    async fn add_execute_outside_transaction(
        &self,
        outside_execution: OutsideExecution,
        address: Felt,
        signature: Vec<Felt>,
        fee_source: Option<FeeSource>,
    ) -> Result<ExecuteFromOutsideResponse, ExecuteFromOutsideError> {
        let request = JsonRpcRequest {
            id: 1,
            jsonrpc: "2.0",
            method: "cartridge_addExecuteOutsideTransaction",
            params: OutsideExecutionParams {
                address,
                outside_execution,
                signature,
                fee_source,
            },
        };

        let client = Client::new();
        let response = client
            .post(self.rpc_url.as_str())
            .header("Content-Type", "application/json")
            .json(&request)
            .send()
            .await?;

        let json_response: Value = response.json().await?;
        let json_rpc_response: JsonRpcResponse<ExecuteFromOutsideResponse> =
            serde_json::from_value(json_response)?;

        match json_rpc_response {
            JsonRpcResponse::Success { result, .. } => Ok(result),
            JsonRpcResponse::Error { error, .. } => Err(error.into()),
        }
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl Provider for CartridgeJsonRpcProvider {
    async fn spec_version(&self) -> Result<String, ProviderError> {
        self.inner.spec_version().await
    }

    async fn get_block_with_tx_hashes<B>(
        &self,
        block_id: B,
    ) -> Result<MaybePreConfirmedBlockWithTxHashes, ProviderError>
    where
        B: AsRef<BlockId> + Send + Sync,
    {
        self.inner.get_block_with_tx_hashes(block_id).await
    }

    async fn get_block_with_txs<B>(
        &self,
        block_id: B,
    ) -> Result<MaybePreConfirmedBlockWithTxs, ProviderError>
    where
        B: AsRef<BlockId> + Send + Sync,
    {
        self.inner.get_block_with_txs(block_id).await
    }

    async fn get_block_with_receipts<B>(
        &self,
        block_id: B,
    ) -> Result<MaybePreConfirmedBlockWithReceipts, ProviderError>
    where
        B: AsRef<BlockId> + Send + Sync,
    {
        self.inner.get_block_with_receipts(block_id).await
    }

    async fn get_state_update<B>(
        &self,
        block_id: B,
    ) -> Result<MaybePreConfirmedStateUpdate, ProviderError>
    where
        B: AsRef<BlockId> + Send + Sync,
    {
        self.inner.get_state_update(block_id).await
    }

    async fn get_storage_at<A, K, B>(
        &self,
        contract_address: A,
        key: K,
        block_id: B,
    ) -> Result<Felt, ProviderError>
    where
        A: AsRef<Felt> + Send + Sync,
        K: AsRef<Felt> + Send + Sync,
        B: AsRef<BlockId> + Send + Sync,
    {
        self.inner
            .get_storage_at(contract_address, key, block_id)
            .await
    }

    async fn get_transaction_status<H>(
        &self,
        transaction_hash: H,
    ) -> Result<TransactionStatus, ProviderError>
    where
        H: AsRef<Felt> + Send + Sync,
    {
        self.inner.get_transaction_status(transaction_hash).await
    }

    async fn get_transaction_by_hash<H>(
        &self,
        transaction_hash: H,
    ) -> Result<Transaction, ProviderError>
    where
        H: AsRef<Felt> + Send + Sync,
    {
        self.inner.get_transaction_by_hash(transaction_hash).await
    }

    async fn get_transaction_by_block_id_and_index<B>(
        &self,
        block_id: B,
        index: u64,
    ) -> Result<Transaction, ProviderError>
    where
        B: AsRef<BlockId> + Send + Sync,
    {
        self.inner
            .get_transaction_by_block_id_and_index(block_id, index)
            .await
    }

    async fn get_transaction_receipt<H>(
        &self,
        transaction_hash: H,
    ) -> Result<TransactionReceiptWithBlockInfo, ProviderError>
    where
        H: AsRef<Felt> + Send + Sync,
    {
        self.inner.get_transaction_receipt(transaction_hash).await
    }

    async fn get_class<B, H>(
        &self,
        block_id: B,
        class_hash: H,
    ) -> Result<ContractClass, ProviderError>
    where
        B: AsRef<BlockId> + Send + Sync,
        H: AsRef<Felt> + Send + Sync,
    {
        self.inner.get_class(block_id, class_hash).await
    }

    async fn get_class_hash_at<B, A>(
        &self,
        block_id: B,
        contract_address: A,
    ) -> Result<Felt, ProviderError>
    where
        B: AsRef<BlockId> + Send + Sync,
        A: AsRef<Felt> + Send + Sync,
    {
        self.inner
            .get_class_hash_at(block_id, contract_address)
            .await
    }

    async fn get_class_at<B, A>(
        &self,
        block_id: B,
        contract_address: A,
    ) -> Result<ContractClass, ProviderError>
    where
        B: AsRef<BlockId> + Send + Sync,
        A: AsRef<Felt> + Send + Sync,
    {
        self.inner.get_class_at(block_id, contract_address).await
    }

    async fn get_block_transaction_count<B>(&self, block_id: B) -> Result<u64, ProviderError>
    where
        B: AsRef<BlockId> + Send + Sync,
    {
        self.inner.get_block_transaction_count(block_id).await
    }

    async fn call<R, B>(&self, request: R, block_id: B) -> Result<Vec<Felt>, ProviderError>
    where
        R: AsRef<FunctionCall> + Send + Sync,
        B: AsRef<BlockId> + Send + Sync,
    {
        self.inner.call(request, block_id).await
    }

    async fn estimate_fee<R, S, B>(
        &self,
        request: R,
        simulation_flags: S,
        block_id: B,
    ) -> Result<Vec<FeeEstimate>, ProviderError>
    where
        R: AsRef<[BroadcastedTransaction]> + Send + Sync,
        S: AsRef<[SimulationFlagForEstimateFee]> + Send + Sync,
        B: AsRef<BlockId> + Send + Sync,
    {
        let mut estimates = self
            .inner
            .estimate_fee(request, &simulation_flags, block_id)
            .await?;

        // Add VALIDATION_GAS if skip validate is enabled
        if simulation_flags
            .as_ref()
            .contains(&SimulationFlagForEstimateFee::SkipValidate)
        {
            // Add the L2 gas offset to each fee estimate
            for estimate in &mut estimates {
                estimate.l2_gas_consumed = estimate.l2_gas_consumed.saturating_add(VALIDATION_GAS);
            }
        }

        Ok(estimates)
    }

    async fn estimate_message_fee<M, B>(
        &self,
        message: M,
        block_id: B,
    ) -> Result<MessageFeeEstimate, ProviderError>
    where
        M: AsRef<MsgFromL1> + Send + Sync,
        B: AsRef<BlockId> + Send + Sync,
    {
        self.inner.estimate_message_fee(message, block_id).await
    }

    async fn block_number(&self) -> Result<u64, ProviderError> {
        self.inner.block_number().await
    }

    async fn block_hash_and_number(&self) -> Result<BlockHashAndNumber, ProviderError> {
        self.inner.block_hash_and_number().await
    }

    async fn chain_id(&self) -> Result<Felt, ProviderError> {
        self.inner.chain_id().await
    }

    async fn syncing(&self) -> Result<SyncStatusType, ProviderError> {
        self.inner.syncing().await
    }

    async fn get_events(
        &self,
        filter: EventFilter,
        continuation_token: Option<String>,
        chunk_size: u64,
    ) -> Result<EventsPage, ProviderError> {
        self.inner
            .get_events(filter, continuation_token, chunk_size)
            .await
    }

    async fn get_nonce<B, A>(&self, block_id: B, contract_address: A) -> Result<Felt, ProviderError>
    where
        B: AsRef<BlockId> + Send + Sync,
        A: AsRef<Felt> + Send + Sync,
    {
        self.inner.get_nonce(block_id, contract_address).await
    }

    async fn add_invoke_transaction<I>(
        &self,
        invoke_transaction: I,
    ) -> Result<InvokeTransactionResult, ProviderError>
    where
        I: AsRef<BroadcastedInvokeTransaction> + Send + Sync,
    {
        self.inner.add_invoke_transaction(invoke_transaction).await
    }

    async fn add_declare_transaction<D>(
        &self,
        declare_transaction: D,
    ) -> Result<DeclareTransactionResult, ProviderError>
    where
        D: AsRef<BroadcastedDeclareTransaction> + Send + Sync,
    {
        self.inner
            .add_declare_transaction(declare_transaction)
            .await
    }

    async fn add_deploy_account_transaction<D>(
        &self,
        deploy_account_transaction: D,
    ) -> Result<DeployAccountTransactionResult, ProviderError>
    where
        D: AsRef<BroadcastedDeployAccountTransaction> + Send + Sync,
    {
        self.inner
            .add_deploy_account_transaction(deploy_account_transaction)
            .await
    }

    async fn trace_transaction<H>(
        &self,
        transaction_hash: H,
    ) -> Result<TransactionTrace, ProviderError>
    where
        H: AsRef<Felt> + Send + Sync,
    {
        self.inner.trace_transaction(transaction_hash).await
    }

    async fn simulate_transactions<B, T, S>(
        &self,
        block_id: B,
        transactions: T,
        simulation_flags: S,
    ) -> Result<Vec<SimulatedTransaction>, ProviderError>
    where
        B: AsRef<BlockId> + Send + Sync,
        T: AsRef<[BroadcastedTransaction]> + Send + Sync,
        S: AsRef<[SimulationFlag]> + Send + Sync,
    {
        let mut simuations = self
            .inner
            .simulate_transactions(block_id, transactions, &simulation_flags)
            .await?;

        // Add VALIDATION_GAS if skip validate is enabled
        if simulation_flags
            .as_ref()
            .contains(&SimulationFlag::SkipValidate)
        {
            for simulation in &mut simuations {
                // Add the L2 gas offset to each fee estimate
                simulation.fee_estimation.l2_gas_consumed = simulation
                    .fee_estimation
                    .l2_gas_consumed
                    .saturating_add(VALIDATION_GAS);
            }
        }

        Ok(simuations)
    }

    async fn trace_block_transactions<B>(
        &self,
        block_id: B,
    ) -> Result<Vec<TransactionTraceWithHash>, ProviderError>
    where
        B: AsRef<ConfirmedBlockId> + Send + Sync,
    {
        self.inner.trace_block_transactions(block_id).await
    }

    async fn batch_requests<R>(
        &self,
        requests: R,
    ) -> Result<Vec<ProviderResponseData>, ProviderError>
    where
        R: AsRef<[ProviderRequestData]> + Send + Sync,
    {
        self.inner.batch_requests(requests).await
    }

    async fn get_messages_status(
        &self,
        transaction_hash: Hash256,
    ) -> Result<Vec<starknet::core::types::MessageStatus>, ProviderError> {
        self.inner.get_messages_status(transaction_hash).await
    }

    async fn get_storage_proof<B, H, A, K>(
        &self,
        block_id: B,
        class_hashes: H,
        contract_addresses: A,
        contracts_storage_keys: K,
    ) -> Result<starknet::core::types::StorageProof, ProviderError>
    where
        B: AsRef<starknet::core::types::ConfirmedBlockId> + Send + Sync,
        H: AsRef<[Felt]> + Send + Sync,
        A: AsRef<[Felt]> + Send + Sync,
        K: AsRef<[starknet::core::types::ContractStorageKeys]> + Send + Sync,
    {
        self.inner
            .get_storage_proof(
                block_id,
                class_hashes,
                contract_addresses,
                contracts_storage_keys,
            )
            .await
    }
}

use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use serde_with::serde_as;
use starknet::{
    core::{serde::unsigned_field_element::UfeHex, types::StarknetError},
    providers::jsonrpc::{JsonRpcClientError, JsonRpcError, JsonRpcResponse},
};

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct JsonRpcRequest<T> {
    id: u64,
    jsonrpc: &'static str,
    method: &'static str,
    params: T,
}

#[serde_as]
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct OutsideExecutionParams {
    #[serde_as(as = "UfeHex")]
    pub address: Felt,
    pub outside_execution: OutsideExecution,
    #[serde_as(as = "Vec<UfeHex>")]
    pub signature: Vec<Felt>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fee_source: Option<FeeSource>,
}

#[serde_as]
#[derive(Debug, Deserialize, Serialize)]
pub struct ExecuteFromOutsideResponse {
    #[serde_as(as = "UfeHex")]
    pub transaction_hash: Felt,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PaymasterRPCError {
    pub code: u32,
    pub message: String,
}

impl std::fmt::Display for PaymasterRPCError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Code: {}, Message: {}", self.code, self.message)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ExecuteFromOutsideError {
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error(transparent)]
    ProviderError(#[from] ProviderError),
    #[error("Execution time not yet reached")]
    ExecutionTimeNotReached,
    #[error("Execution time has passed")]
    ExecutionTimePassed,
    #[error("Invalid caller for this transaction")]
    InvalidCaller,
    #[error("Rate limit exceeded")]
    RateLimitExceeded,
    #[error("Paymaster not supported")]
    ExecuteFromOutsideNotSupported(String),
}

impl From<JsonRpcError> for ExecuteFromOutsideError {
    fn from(error: JsonRpcError) -> Self {
        match error.clone() {
            err if err.message.contains("execution time not yet reached") => {
                ExecuteFromOutsideError::ExecutionTimeNotReached
            }
            err if err.message.contains("execution time has passed") => {
                ExecuteFromOutsideError::ExecutionTimePassed
            }
            err if err.message.contains("invalid caller") => ExecuteFromOutsideError::InvalidCaller,
            err if err.message.contains("Transaction execution error") => {
                parse_transaction_execution_error(&err)
            }
            err if err.code == -32005 => ExecuteFromOutsideError::RateLimitExceeded,
            err if err.code == -32003 || err.code == -32004 => {
                ExecuteFromOutsideError::ExecuteFromOutsideNotSupported(err.message)
            }
            _ => match TryInto::<StarknetError>::try_into(&error) {
                Ok(starknet_error) => ExecuteFromOutsideError::ProviderError(
                    ProviderError::StarknetError(starknet_error),
                ),
                Err(_) => ExecuteFromOutsideError::ProviderError(ProviderError::StarknetError(
                    StarknetError::UnexpectedError(error.message),
                )),
            },
        }
    }
}

impl From<reqwest::Error> for ExecuteFromOutsideError {
    fn from(error: reqwest::Error) -> Self {
        ExecuteFromOutsideError::ProviderError(
            JsonRpcClientError::<reqwest::Error>::TransportError(error).into(),
        )
    }
}

fn parse_transaction_execution_error(err: &JsonRpcError) -> ExecuteFromOutsideError {
    let pattern = "('argent/multicall-failed'),";
    let mut failure_index: u64 = 0;
    let mut failure_reason = String::new();
    if err.data.is_some() && err.data.as_ref().unwrap().is_object() {
        let data = err.data.as_ref().unwrap().as_object().unwrap()["execution_error"].as_str();
        let error_message = if let Some(data) = data {
            data
        } else {
            err.data.as_ref().unwrap().as_object().unwrap()["execution_error"]
                .as_object()
                .unwrap()["error"]
                .as_str()
                .unwrap()
        };
        if let Some(pos) = error_message.find(pattern) {
            let start = pos + pattern.len();
            let substr = &error_message[start..].trim_start();
            if let Some(hex_chars) = substr.strip_prefix("0x") {
                let hex_chars: String =
                    hex_chars.chars().take_while(|c| c.is_hex_digit()).collect();
                if let Ok(index) = u64::from_str_radix(&hex_chars, 16) {
                    failure_index = index;
                }
            }
        }
        let pattern = "Failure reason:\n";
        failure_reason = if let Some(failure_index) = error_message.find(pattern) {
            error_message[failure_index + pattern.len()..]
                .trim()
                .to_string()
        } else {
            error_message.to_string()
        };
    }
    ExecuteFromOutsideError::ProviderError(ProviderError::StarknetError(
        StarknetError::TransactionExecutionError(TransactionExecutionErrorData {
            execution_error: ContractExecutionError::Message(failure_reason.to_string()),
            transaction_index: failure_index,
        }),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_failure_reason_multicall_mainnet() {
        let error = JsonRpcError {
            code: 41,
            message: "Transaction execution error".to_string(),
            data: Some(
                serde_json::json!({"execution_error": {"class_hash":"0xe2eb8f5672af4e6a4e8a8f1b44989685e668489b0a25437733756c5a34a1d6", "contract_address":"0x3947b852fb5b1b16611de6ac4ae9ed517752781467672b313d2685b4bdca929", "error":"(0x617267656e742f6d756c746963616c6c2d6661696c6564 ('argent/multicall-failed'), 0x1, 0x73657373696f6e2f616c72656164792d7265766f6b6564 ('session/already-revoked'), 0x454e545259504f494e545f4641494c4544 ('ENTRYPOINT_FAILED'), 0x454e545259504f494e545f4641494c4544 ('ENTRYPOINT_FAILED'))", "selector":"0x15d40a3d6ca2ac30f4031e42be28da9b056fef9bb7357ac5e85627ee876e5ad"}}),
            ),
        };
        let error_from_json = ExecuteFromOutsideError::from(error);
        match error_from_json {
            ExecuteFromOutsideError::ProviderError(ProviderError::StarknetError(
                StarknetError::TransactionExecutionError(TransactionExecutionErrorData {
                    execution_error: ContractExecutionError::Message(failure_reason),
                    transaction_index: failure_index,
                }),
            )) => {
                assert_eq!(failure_index, 1);
                assert!(failure_reason.contains("('argent/multicall-failed')"));
                assert!(failure_reason.contains("('session/already-revoked')"));
            }
            _ => {
                panic!("Unexpected error: {error_from_json:?}");
            }
        }
    }
    #[test]
    fn test_extract_failure_reason_multicall_katana() {
        let error = JsonRpcError {
            code: 41,
            message: "Transaction execution error".to_string(),
            data: Some(
                serde_json::json!({"execution_error": "Transaction reverted: Transaction execution has failed:\n0: Error in the called contract (contract address: 0x0585fa0cb392244c880c6a96e8c7d7a731e04022eccf61e9fd089d9972f1528a, class hash: 0x00e2eb8f5672af4e6a4e8a8f1b44989685e668489b0a25437733756c5a34a1d6, selector: 0x015d40a3d6ca2ac30f4031e42be28da9b056fef9bb7357ac5e85627ee876e5ad):\nExecution failed. Failure reason:\n(0x617267656e742f6d756c746963616c6c2d6661696c6564 ('argent/multicall-failed'), 0x1, 0x73657373696f6e2f616c72656164792d7265766f6b6564 ('session/already-revoked'), 0x454e545259504f494e545f4641494c4544 ('ENTRYPOINT_FAILED'), 0x454e545259504f494e545f4641494c4544 ('ENTRYPOINT_FAILED')).\n"}),
            ),
        };
        let error_from_json = ExecuteFromOutsideError::from(error);
        match error_from_json {
            ExecuteFromOutsideError::ProviderError(ProviderError::StarknetError(
                StarknetError::TransactionExecutionError(TransactionExecutionErrorData {
                    execution_error: ContractExecutionError::Message(failure_reason),
                    transaction_index: failure_index,
                }),
            )) => {
                assert_eq!(failure_index, 1);
                assert!(failure_reason.contains("('argent/multicall-failed')"));
                assert!(failure_reason.contains("('session/already-revoked')"));
            }
            _ => {
                panic!("Unexpected error: {error_from_json:?}");
            }
        }
    }

    #[test]
    fn test_insufficient_credits_error_mapping() {
        let error = JsonRpcError {
            code: -32003,
            message: "insufficient credits and no applicable paymaster found".to_string(),
            data: None,
        };
        let error_from_json = ExecuteFromOutsideError::from(error);
        match error_from_json {
            ExecuteFromOutsideError::ExecuteFromOutsideNotSupported(msg) => {
                assert_eq!(
                    msg,
                    "insufficient credits and no applicable paymaster found"
                );
            }
            _ => {
                panic!("Expected ExecuteFromOutsideNotSupported, got: {error_from_json:?}");
            }
        }
    }
}
