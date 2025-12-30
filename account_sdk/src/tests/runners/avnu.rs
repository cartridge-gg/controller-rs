use anyhow::Error;
use cainome::cairo_serde::CairoSerde;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Client, Request, Response, Server, StatusCode};
use serde_json::{json, Value};
use starknet::accounts::single_owner::SignError;
use starknet::accounts::{Account, AccountError, ExecutionEncoding};
use starknet::core::types::{Call, InvokeTransactionResult};
use starknet::macros::selector;
use starknet::providers::jsonrpc::HttpTransport;
use starknet::providers::JsonRpcClient;
use starknet_crypto::Felt;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use url::Url;

use crate::abigen::controller::{SessionToken, SignerSignature};
use crate::account::outside_execution::{OutsideExecution, SignedOutsideExecution};
use crate::account::session::hash::SessionHash;
use crate::constants::GUARDIAN_SIGNER;
use crate::hash::MessageHashRev1;
use crate::provider_avnu::{
    ExecuteRawRequest, ExecuteRawTransactionParams, ExecutionParameters, FeeMode, RawInvokeParams,
};
use crate::signers::HashSigner;

use super::find_free_port;
use super::katana::{single_owner_account_with_encoding, KatanaRunner, PREFUNDED};

/// AVNU Paymaster proxy that simulates the AVNU paymaster API for testing.
/// This implements the `paymaster_executeRawTransaction` endpoint.
pub struct AvnuPaymasterProxy {
    chain_id: Felt,
    rpc_url: Url,
    proxy_url: Url,
    rpc_client: JsonRpcClient<HttpTransport>,
    client: Client<hyper::client::HttpConnector>,
}

impl AvnuPaymasterProxy {
    pub fn new(rpc_url: Url, proxy_url: Url, chain_id: Felt) -> Self {
        let rpc_client = JsonRpcClient::new(HttpTransport::new(rpc_url.clone()));

        AvnuPaymasterProxy {
            chain_id,
            rpc_url,
            rpc_client,
            proxy_url,
            client: Client::new(),
        }
    }

    pub async fn run(self) {
        let proxy_addr: SocketAddr = self
            .proxy_url
            .socket_addrs(|| None)
            .expect("Failed to resolve proxy URL")
            .into_iter()
            .next()
            .expect("No socket addresses found for proxy URL");

        let shared_self = Arc::new(Mutex::new(self));

        let make_svc = make_service_fn(move |_conn| {
            let shared_self = shared_self.clone();
            async move {
                Ok::<_, hyper::Error>(service_fn(move |req| {
                    let shared_self = shared_self.clone();
                    async move {
                        let self_guard = shared_self.lock().await;
                        self_guard.handle_request(req).await
                    }
                }))
            }
        });

        let server = Server::bind(&proxy_addr).serve(make_svc);
        if let Err(e) = server.await {
            eprintln!("server error: {e}");
        }
    }

    async fn handle_request(&self, req: Request<Body>) -> Result<Response<Body>, hyper::Error> {
        let (parts, body) = req.into_parts();
        let body_bytes = hyper::body::to_bytes(body).await?;
        let body: Value = serde_json::from_slice(&body_bytes).unwrap_or(json!({}));

        if let Some(method) = body.get("method") {
            if method == "paymaster_executeRawTransaction" {
                return self.handle_execute_raw_transaction(&body).await;
            }
        }

        // Forward all other requests to the actual RPC
        let body = Body::from(serde_json::to_vec(&body).unwrap());

        let mut proxy_req = Request::builder()
            .method(parts.method)
            .uri(&self.rpc_url.to_string())
            .body(body)
            .unwrap();

        *proxy_req.headers_mut() = parts.headers;

        self.client.request(proxy_req).await
    }

    async fn handle_execute_raw_transaction(
        &self,
        body: &Value,
    ) -> Result<Response<Body>, hyper::Error> {
        let params = &body["params"];
        let result = match parse_execute_raw_params(params) {
            Ok(request) => match self.execute_raw_transaction(request).await {
                Ok(result) => Response::builder()
                    .status(StatusCode::OK)
                    .header("Content-Type", "application/json")
                    .body(Body::from(
                        json!({
                            "id": body.get("id").cloned().unwrap_or_else(|| json!(1_u64)),
                            "jsonrpc": "2.0",
                            "result": {
                                "transaction_hash": format!("0x{:x}", result.transaction_hash),
                                "tracking_id": "0x0"
                            }
                        })
                        .to_string(),
                    ))
                    .unwrap(),
                Err(e) => {
                    let error_response = json!({
                        "jsonrpc": "2.0",
                        "id": body.get("id").cloned().unwrap_or_else(|| json!(1_u64)),
                        "error": {
                            "code": -32000,
                            "message": "Execution error",
                            "data": e.to_string()
                        }
                    });

                    Response::builder()
                        .status(StatusCode::OK)
                        .header("Content-Type", "application/json")
                        .body(Body::from(error_response.to_string()))
                        .unwrap()
                }
            },
            Err(e) => {
                let error_response = json!({
                    "jsonrpc": "2.0",
                    "id": body.get("id").cloned().unwrap_or_else(|| json!(1_u64)),
                    "error": {
                        "code": -32602,
                        "message": e.to_string()
                    }
                });
                Response::builder()
                    .status(StatusCode::OK)
                    .header("Content-Type", "application/json")
                    .body(Body::from(error_response.to_string()))
                    .unwrap()
            }
        };
        Ok(result)
    }

    async fn execute_raw_transaction(
        &self,
        request: ExecuteRawRequest,
    ) -> Result<
        InvokeTransactionResult,
        AccountError<SignError<starknet::signers::local_wallet::SignError>>,
    > {
        let ExecuteRawTransactionParams::RawInvoke { invoke } = request.transaction;

        // The execute_from_outside_call contains the full call to the user's account
        // We need to add guardian signature to the signature in the calldata
        let execute_from_outside_call = invoke.execute_from_outside_call;

        // Parse the outside execution from the calldata to get the hash for signing
        let outside_execution =
            parse_outside_execution_from_call(&execute_from_outside_call, invoke.user_address);

        let outside_execution_hash =
            outside_execution.get_message_hash_rev_1(self.chain_id, invoke.user_address);

        // Extract signature from the call and add guardian signature
        let original_signature = extract_signature_from_call(&execute_from_outside_call);
        let signature = self
            .add_guardian_signature(
                invoke.user_address,
                outside_execution_hash,
                &original_signature,
            )
            .await;

        // Rebuild the call with the guardian-signed signature
        let mut calldata = <OutsideExecution as CairoSerde>::cairo_serialize(&outside_execution);
        calldata.extend(<Vec<Felt> as CairoSerde>::cairo_serialize(&signature));

        let call = Call {
            to: invoke.user_address,
            selector: selector!("execute_from_outside_v3"),
            calldata,
        };

        let executor = single_owner_account_with_encoding(
            &self.rpc_client,
            PREFUNDED.0.clone(),
            PREFUNDED.1,
            self.chain_id,
            ExecutionEncoding::New,
        );

        executor.execute_v3(vec![call]).send().await
    }

    async fn add_guardian_signature(
        &self,
        address: Felt,
        tx_hash: Felt,
        old_signature: &[Felt],
    ) -> Vec<Felt> {
        // First try to deserialize as Vec<SignerSignature> (owner signature)
        match <Vec<SignerSignature> as CairoSerde>::cairo_deserialize(old_signature, 0) {
            Ok(mut signature) => {
                let guardian_signature = GUARDIAN_SIGNER.sign(&tx_hash).await.unwrap();
                signature.push(guardian_signature);
                <Vec<SignerSignature> as CairoSerde>::cairo_serialize(&signature)
            }
            Err(_) => {
                // Try to deserialize as SessionToken (session signature)
                // The first element is the session magic marker
                match <SessionToken as CairoSerde>::cairo_deserialize(old_signature, 1) {
                    Ok(mut session_token) => {
                        let session_token_hash = session_token
                            .session
                            .hash(self.chain_id, address, tx_hash)
                            .unwrap();

                        // Add guardian authorization if needed
                        self.add_guardian_authorization(&mut session_token, address)
                            .await;

                        // Sign the session token hash with the guardian
                        let guardian_signature =
                            GUARDIAN_SIGNER.sign(&session_token_hash).await.unwrap();
                        session_token.guardian_signature = guardian_signature;

                        let mut serialized =
                            <SessionToken as CairoSerde>::cairo_serialize(&session_token);
                        serialized.insert(0, old_signature[0]); // Prepend the session magic marker
                        serialized
                    }
                    Err(_) => {
                        // If we can't deserialize, return the original
                        old_signature.to_vec()
                    }
                }
            }
        }
    }

    async fn add_guardian_authorization(&self, session_token: &mut SessionToken, address: Felt) {
        if session_token.session_authorization.len() == 2 {
            // Authorization by registered session - no guardian needed
            return;
        }
        let authorization = <Vec<SignerSignature> as CairoSerde>::cairo_deserialize(
            &session_token.session_authorization,
            0,
        )
        .unwrap();
        if authorization.len() == 1 {
            // Need to add guardian authorization
            let session_hash = session_token
                .session
                .get_message_hash_rev_1(self.chain_id, address);
            let guardian_authorization = GUARDIAN_SIGNER.sign(&session_hash).await.unwrap();
            session_token.session_authorization =
                <Vec<SignerSignature> as CairoSerde>::cairo_serialize(&vec![
                    authorization[0].clone(),
                    guardian_authorization,
                ]);
        }
    }
}

fn parse_execute_raw_params(params: &Value) -> Result<ExecuteRawRequest, Error> {
    serde_json::from_value(params.clone())
        .map_err(|e| anyhow::anyhow!("Failed to parse params: {e}"))
}

/// Parse the OutsideExecution from an execute_from_outside call
fn parse_outside_execution_from_call(call: &Call, _user_address: Felt) -> OutsideExecution {
    // The calldata for execute_from_outside_v3 contains:
    // - OutsideExecution struct (caller, execute_after, execute_before, calls, nonce)
    // - Signature
    <OutsideExecution as CairoSerde>::cairo_deserialize(&call.calldata, 0)
        .expect("Failed to deserialize OutsideExecution from call")
}

/// Extract signature from an execute_from_outside call
fn extract_signature_from_call(call: &Call) -> Vec<Felt> {
    // The signature comes after the OutsideExecution in the calldata
    // First, figure out where OutsideExecution ends
    let outside_execution =
        <OutsideExecution as CairoSerde>::cairo_deserialize(&call.calldata, 0).unwrap();
    let serialized_outside_execution =
        <OutsideExecution as CairoSerde>::cairo_serialize(&outside_execution);
    let signature_start = serialized_outside_execution.len();

    // Deserialize the signature
    <Vec<Felt> as CairoSerde>::cairo_deserialize(&call.calldata, signature_start)
        .unwrap_or_default()
}

/// Build an ExecuteRawRequest from a SignedOutsideExecution using sponsored fee mode
/// Returns the provider type that can be used with AvnuPaymasterProvider
///
/// Note: For sponsored mode, the paymaster pays for gas fees and no API key is required
/// for local testing. For default (non-sponsored) mode, the user must include a fee
/// transfer in their execute_from_outside calls.
pub fn build_execute_raw_request(signed: SignedOutsideExecution) -> ExecuteRawRequest {
    // Convert the SignedOutsideExecution to a Call
    let execute_from_outside_call: Call = signed.clone().into();

    ExecuteRawRequest {
        transaction: ExecuteRawTransactionParams::RawInvoke {
            invoke: RawInvokeParams {
                user_address: signed.contract_address,
                execute_from_outside_call,
                gas_token: None,
                max_gas_token_amount: None,
            },
        },
        parameters: ExecutionParameters::V1 {
            // Use sponsored mode - paymaster pays for gas, no API key needed for local testing
            fee_mode: FeeMode::Sponsored,
            time_bounds: None,
        },
    }
}

/// Create an AVNU proxy and return the proxy URL and a task handle
pub fn create_avnu_proxy(runner: &KatanaRunner) -> (Url, JoinHandle<()>) {
    let proxy_port = find_free_port();
    let proxy_url = Url::parse(&format!("http://127.0.0.1:{proxy_port}")).unwrap();

    // Use the direct katana URL (bypassing the Cartridge proxy) since we handle
    // guardian signatures ourselves in the AVNU proxy
    let proxy = AvnuPaymasterProxy::new(
        runner.katana_url().clone(),
        proxy_url.clone(),
        runner.chain_id(),
    );

    let handle = tokio::spawn(async move {
        proxy.run().await;
    });

    (proxy_url, handle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_execute_raw_params() {
        let params = json!({
            "transaction": {
                "type": "raw_invoke",
                "invoke": {
                    "user_address": "0x123",
                    "execute_from_outside_call": {
                        "to": "0x456",
                        "selector": "0x789",
                        "calldata": ["0x1", "0x2"]
                    },
                    "gas_token": "0xabc",
                    "max_gas_token_amount": "0xdef"
                }
            },
            "parameters": {
                "version": "0x1",
                "fee_mode": {
                    "mode": "default",
                    "gas_token": "0xabc"
                }
            }
        });

        let result = parse_execute_raw_params(&params);
        assert!(result.is_ok());
    }
}
