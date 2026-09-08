use std::sync::{Arc, Mutex};

use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Response, Server};
use serde_json::{json, Value};
use starknet::core::types::{Call, FeeEstimate};
use starknet::macros::felt;
use tokio::task::JoinHandle;
use url::Url;

use crate::account::session::policy::Policy;
use crate::controller::Controller;
use crate::errors::ControllerError;
use crate::gas::GasMultiplier;
use crate::provider::ExecuteFromOutsideError;
use crate::signers::{Owner, Signer};

#[test]
fn only_unsupported_paymaster_errors_allow_self_funding() {
    for error in [
        ControllerError::PaymasterNotSupported,
        ControllerError::PaymasterError(ExecuteFromOutsideError::ExecuteFromOutsideNotSupported(
            "outside execution unavailable".into(),
        )),
    ] {
        assert!(super::is_paymaster_not_supported(&error));
    }
    for error in [
        ControllerError::PaymasterError(ExecuteFromOutsideError::RateLimitExceeded),
        ControllerError::PaymasterError(ExecuteFromOutsideError::InvalidCaller),
        ControllerError::InvalidResponseData("paymaster not supported".into()),
    ] {
        assert!(!super::is_paymaster_not_supported(&error));
    }
}

// Exercise the real session fallback and transaction serialization without a
// live chain. The RPC rejects prices below the values observed at submission,
// reproducing a price increase between estimation and broadcast.
struct PricingRpc {
    url: Url,
    requests: Arc<Mutex<Vec<Value>>>,
    task: JoinHandle<()>,
    #[cfg(feature = "filestorage")]
    storage_dir: tempfile::TempDir,
}

impl PricingRpc {
    fn start(paymaster_supported: bool) -> Self {
        let requests = Arc::new(Mutex::new(Vec::new()));
        let recorded_requests = requests.clone();
        let server = Server::bind(&([127, 0, 0, 1], 0).into());
        let url = Url::parse(&format!("http://{}", server.local_addr())).unwrap();
        let service = make_service_fn(move |_| {
            let requests = recorded_requests.clone();
            async move {
                Ok::<_, hyper::Error>(service_fn(move |request| {
                    let requests = requests.clone();
                    async move {
                        let body = hyper::body::to_bytes(request.into_body()).await?;
                        let request: Value = serde_json::from_slice(&body).unwrap();
                        requests.lock().unwrap().push(request.clone());
                        let mut response = json!({"jsonrpc": "2.0", "id": request["id"]});
                        match request["method"].as_str().unwrap() {
                            "starknet_chainId" => {
                                response["result"] = json!("0x534e5f5345504f4c4941")
                            }
                            "starknet_getNonce" => response["result"] = json!("0x1"),
                            "starknet_getBlockWithTxs" => {
                                response["result"] = json!({
                                    "block_number": 1,
                                    "timestamp": 1,
                                    "sequencer_address": "0x1",
                                    "l1_gas_price": {"price_in_fri": "0x1", "price_in_wei": "0x1"},
                                    "l2_gas_price": {"price_in_fri": "0x1", "price_in_wei": "0x1"},
                                    "l1_data_gas_price": {"price_in_fri": "0x1", "price_in_wei": "0x1"},
                                    "l1_da_mode": "BLOB",
                                    "starknet_version": "0.14.0",
                                    "transactions": []
                                });
                            }
                            "starknet_call" => {
                                response["result"] =
                                    json!(["0xffffffffffffffffffffffffffffffff", "0x0"]);
                            }
                            "cartridge_addExecuteOutsideTransaction" => {
                                if paymaster_supported {
                                    response["result"] = json!({"transaction_hash": "0x123"});
                                } else {
                                    response["error"] = json!({
                                        "code": -32003,
                                        "message": "insufficient credits and no applicable paymaster found"
                                    });
                                }
                            }
                            "starknet_estimateFee" => {
                                response["result"] = json!([raw_estimate()]);
                            }
                            "starknet_addInvokeTransaction" => {
                                let bounds =
                                    &request["params"]["invoke_transaction"]["resource_bounds"];
                                let prices_sufficient = [
                                    ("l1_gas", 97_728_921_905_943u128),
                                    ("l1_data_gas", 135_546_644_105u128),
                                    ("l2_gas", 101u128),
                                ]
                                .into_iter()
                                .all(|(resource, price)| {
                                    hex_value(&bounds[resource]["max_price_per_unit"]) >= price
                                });
                                if prices_sufficient {
                                    response["result"] = json!({"transaction_hash": "0x456"});
                                } else {
                                    response["error"] = json!({
                                        "code": 55,
                                        "message": "Account validation failed",
                                        "data": "Resource bounds were not satisfied"
                                    });
                                }
                            }
                            method => panic!("unexpected RPC method: {method}"),
                        }
                        Ok::<_, hyper::Error>(Response::new(Body::from(response.to_string())))
                    }
                }))
            }
        });
        let task = tokio::spawn(async move { server.serve(service).await.unwrap() });
        Self {
            url,
            requests,
            task,
            #[cfg(feature = "filestorage")]
            storage_dir: tempfile::tempdir().unwrap(),
        }
    }

    async fn controller(&self) -> (Controller, Vec<Call>) {
        #[cfg(feature = "filestorage")]
        let storage = Some(crate::storage::Storage::new(
            self.storage_dir.path().to_path_buf(),
        ));
        #[cfg(not(feature = "filestorage"))]
        let storage = None;
        let mut controller = Controller::new(
            "pricingtest".to_owned(),
            felt!("0x1"),
            self.url.clone(),
            Owner::Signer(Signer::new_starknet_random()),
            felt!("0x9876"),
            storage,
        )
        .await
        .unwrap();
        let calls = vec![Call {
            to: felt!("0x1234"),
            selector: felt!("0x5678"),
            calldata: vec![],
        }];
        controller
            .create_session(Policy::from_calls(&calls), u64::MAX)
            .await
            .unwrap();
        (controller, calls)
    }

    fn submitted_bounds(&self) -> Value {
        self.requests
            .lock()
            .unwrap()
            .iter()
            .find(|request| request["method"] == "starknet_addInvokeTransaction")
            .expect("a self-funded transaction should have been submitted")["params"]
            ["invoke_transaction"]["resource_bounds"]
            .clone()
    }
}

impl Drop for PricingRpc {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn raw_estimate() -> FeeEstimate {
    FeeEstimate {
        l1_gas_consumed: 10,
        l1_gas_price: 96_966_059_925_918,
        l2_gas_consumed: 20,
        l2_gas_price: 100,
        l1_data_gas_consumed: 30,
        l1_data_gas_price: 134_488_580_849,
        overall_fee: 973_695_256_686_650,
    }
}

fn hex_value(value: &Value) -> u128 {
    u128::from_str_radix(value.as_str().unwrap().trim_start_matches("0x"), 16).unwrap()
}

#[tokio::test]
async fn self_funded_session_tolerates_price_drift_with_default_and_max_gas_multiplier() {
    for multiplier in [None, Some(GasMultiplier::new(10.0).unwrap())] {
        let rpc = PricingRpc::start(false);
        let (mut controller, calls) = rpc.controller().await;
        let result = controller
            .try_session_execute_with_gas_multiplier(calls, None, multiplier)
            .await
            .expect("price drift within headroom must not reject the fallback");
        assert_eq!(result.transaction_hash, felt!("0x456"));

        let bounds = rpc.submitted_bounds();
        for (resource, price, amount) in [
            ("l1_gas", 145_449_089_888_877, 10),
            ("l2_gas", 150, 20),
            ("l1_data_gas", 201_732_871_273, 30),
        ] {
            assert_eq!(hex_value(&bounds[resource]["max_price_per_unit"]), price);
            assert_eq!(
                hex_value(&bounds[resource]["max_amount"]),
                multiplier.unwrap_or_default().apply(amount) as u128
            );
        }
    }
}

#[tokio::test]
async fn explicit_max_fee_prices_are_not_buffered_again() {
    let rpc = PricingRpc::start(false);
    let (mut controller, calls) = rpc.controller().await;
    let mut max_fee = raw_estimate();
    max_fee.l1_gas_price *= 2;
    max_fee.l2_gas_price *= 2;
    max_fee.l1_data_gas_price *= 2;
    controller
        .execute(calls, Some(max_fee.clone()), None)
        .await
        .unwrap();

    let bounds = rpc.submitted_bounds();
    assert_eq!(
        hex_value(&bounds["l1_gas"]["max_price_per_unit"]),
        max_fee.l1_gas_price
    );
    assert_eq!(
        hex_value(&bounds["l2_gas"]["max_price_per_unit"]),
        max_fee.l2_gas_price
    );
    assert_eq!(
        hex_value(&bounds["l1_data_gas"]["max_price_per_unit"]),
        max_fee.l1_data_gas_price
    );
}

#[tokio::test]
async fn successful_paymaster_execution_does_not_estimate_or_submit_self_funded_transaction() {
    let rpc = PricingRpc::start(true);
    let (mut controller, calls) = rpc.controller().await;
    let result = controller.try_session_execute(calls, None).await.unwrap();
    assert_eq!(result.transaction_hash, felt!("0x123"));
    let requests = rpc.requests.lock().unwrap();
    assert!(requests
        .iter()
        .any(|request| request["method"] == "cartridge_addExecuteOutsideTransaction"));
    assert!(!requests.iter().any(|request| matches!(
        request["method"].as_str(),
        Some("starknet_estimateFee" | "starknet_addInvokeTransaction")
    )));
}
