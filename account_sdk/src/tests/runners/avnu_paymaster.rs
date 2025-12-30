//! AVNU Paymaster test runner that uses the real paymaster-rpc in-memory
//!
//! This runner starts:
//! 1. The AVNU Starknet devnet Docker container (with forwarder contract pre-deployed)
//! 2. The paymaster RPC server in-memory
//! 3. Deploys controller contracts to the devnet

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use paymaster_prices::mock::MockPriceOracle;
use paymaster_prices::TokenPrice;
use paymaster_relayer::lock::mock::MockLockLayer;
use paymaster_relayer::lock::{LockLayerConfiguration, RelayerLock};
use paymaster_relayer::RelayersConfiguration;
use paymaster_rpc::server::PaymasterServer;
use paymaster_rpc::{Configuration, RPCConfiguration};
use paymaster_starknet::constants::Token;
use paymaster_starknet::testing::TestEnvironment as StarknetTestEnvironment;
use paymaster_starknet::StarknetAccountConfiguration;
use starknet::accounts::{AccountFactory, ExecutionEncoding, SingleOwnerAccount};
use starknet::contract::{ContractFactory, UdcSelector};
use starknet::core::types::{BlockId, BlockTag, Felt};
use starknet::core::utils::cairo_short_string_to_felt;

use starknet::providers::jsonrpc::HttpTransport;
use starknet::providers::{JsonRpcClient, Provider};
use starknet::signers::{LocalWallet, SigningKey};
use tokio::task::JoinHandle;
use url::Url;

use crate::artifacts::{Version, CONTROLLERS};
use crate::controller::Controller;
use crate::factory::ControllerFactory;
use crate::provider::CartridgeJsonRpcProvider;
use crate::signers::Owner;
use crate::tests::account::AccountDeclaration;
use crate::transaction_waiter::TransactionWaiter;

use super::find_free_port;

/// Mock price oracle for testing
#[derive(Debug, Clone)]
struct MockPriceOracleImpl;

#[async_trait]
impl MockPriceOracle for MockPriceOracleImpl {
    fn new() -> Self {
        Self
    }

    async fn fetch_token(&self, address: Felt) -> Result<TokenPrice, paymaster_prices::Error> {
        Ok(TokenPrice {
            address,
            price_in_strk: Felt::from(1e18 as u128),
            decimals: 18,
        })
    }
}

/// Mock locking layer for testing
#[derive(Debug)]
struct MockLockingLayer;

#[async_trait]
impl MockLockLayer for MockLockingLayer {
    fn new() -> Self {
        Self
    }

    async fn count_enabled_relayers(&self) -> usize {
        1
    }

    async fn set_enabled_relayers(&self, _relayers: &HashSet<Felt>) {}

    async fn lock_relayer(&self) -> Result<RelayerLock, paymaster_relayer::lock::Error> {
        Ok(RelayerLock::new(
            StarknetTestEnvironment::ACCOUNT_3.address,
            None,
            Duration::from_secs(30),
        ))
    }

    async fn release_relayer(&self, _lock: RelayerLock) -> Result<(), paymaster_relayer::lock::Error> {
        Ok(())
    }
}

/// Test runner that uses the real AVNU paymaster in-memory
pub struct AvnuPaymasterRunner {
    /// The Starknet test environment (Docker container)
    starknet: StarknetTestEnvironment,
    /// Chain ID
    chain_id: Felt,
    /// URL to the paymaster RPC server
    pub paymaster_url: Url,
    /// URL to the Starknet RPC
    pub starknet_url: Url,
    /// Handle to the paymaster server task
    _server_handle: JoinHandle<()>,
    /// JSON-RPC client for Starknet
    rpc_client: Arc<JsonRpcClient<HttpTransport>>,
}

impl AvnuPaymasterRunner {
    /// Create a new AVNU paymaster test runner
    pub async fn new() -> Self {
        // Start the Starknet devnet container
        let starknet = StarknetTestEnvironment::new().await;
        let starknet_config = starknet.configuration();
        let starknet_url = Url::parse(&starknet_config.endpoint).unwrap();

        let chain_id = cairo_short_string_to_felt(StarknetTestEnvironment::NETWORK).unwrap();

        // Find a free port for the paymaster RPC
        let paymaster_port = find_free_port();
        let paymaster_url = Url::parse(&format!("http://127.0.0.1:{}", paymaster_port)).unwrap();

        // Create paymaster configuration
        let configuration = Configuration {
            rpc: RPCConfiguration {
                port: paymaster_port as u64,
            },
            supported_tokens: HashSet::from([
                Token::ETH_ADDRESS,
                Token::STRK_ADDRESS,
            ]),
            forwarder: StarknetTestEnvironment::FORWARDER,
            gas_tank: StarknetAccountConfiguration {
                address: StarknetTestEnvironment::GAS_TANK.address,
                private_key: StarknetTestEnvironment::GAS_TANK.private_key,
            },
            max_fee_multiplier: 3.0,
            provider_fee_overhead: 0.1,
            estimate_account: StarknetAccountConfiguration {
                address: StarknetTestEnvironment::ACCOUNT_1.address,
                private_key: StarknetTestEnvironment::ACCOUNT_1.private_key,
            },
            relayers: RelayersConfiguration {
                private_key: StarknetTestEnvironment::RELAYER_PRIVATE_KEY,
                addresses: vec![StarknetTestEnvironment::ACCOUNT_3.address],
                min_relayer_balance: Felt::ZERO,
                lock: LockLayerConfiguration::Mock {
                    retry_timeout: Duration::from_secs(5),
                    lock_layer: Arc::new(MockLockingLayer),
                },
                rebalancing: paymaster_relayer::rebalancing::OptionalRebalancingConfiguration::initialize(None),
            },
            starknet: starknet_config,
            price: paymaster_prices::Configuration::Mock(Arc::new(MockPriceOracleImpl)),
            sponsoring: paymaster_sponsoring::Configuration::none(),
        };

        // Start the paymaster server
        let server = PaymasterServer::new(&configuration);
        let server_handle = tokio::spawn(async move {
            if let Err(e) = server.start().await {
                eprintln!("Paymaster server error: {:?}", e);
            }
        });

        // Wait for server to start
        tokio::time::sleep(Duration::from_millis(100)).await;

        let rpc_client = Arc::new(JsonRpcClient::new(HttpTransport::new(starknet_url.clone())));

        Self {
            starknet,
            chain_id,
            paymaster_url,
            starknet_url,
            _server_handle: server_handle,
            rpc_client,
        }
    }

    /// Get the chain ID
    pub fn chain_id(&self) -> Felt {
        self.chain_id
    }

    /// Get a JSON-RPC provider for Starknet
    pub fn client(&self) -> CartridgeJsonRpcProvider {
        CartridgeJsonRpcProvider::new(self.starknet_url.clone())
    }

    /// Get an executor account (pre-funded account from the devnet)
    pub async fn executor(&self) -> SingleOwnerAccount<&JsonRpcClient<HttpTransport>, LocalWallet> {
        let signing_key = SigningKey::from_secret_scalar(StarknetTestEnvironment::ACCOUNT_1.private_key);
        let mut account = SingleOwnerAccount::new(
            &*self.rpc_client,
            LocalWallet::from(signing_key),
            StarknetTestEnvironment::ACCOUNT_1.address,
            self.chain_id,
            ExecutionEncoding::New,
        );
        account.set_block_id(BlockId::Tag(BlockTag::PreConfirmed));
        account
    }

    /// Declare the controller contract
    pub async fn declare_controller(&self, version: Version) {
        let executor = self.executor().await;
        AccountDeclaration::cartridge_account(&self.client(), version)
            .declare(&executor)
            .await
            .unwrap()
            .wait_for_completion()
            .await;
    }

    /// Deploy a controller and return it
    pub async fn deploy_controller(
        &self,
        username: String,
        owner: Owner,
        version: Version,
    ) -> Controller {
        let executor = self.executor().await;
        let class_hash = CONTROLLERS[&version].hash;

        // Declare if not already declared
        if self
            .client()
            .get_class(BlockId::Tag(BlockTag::PreConfirmed), class_hash)
            .await
            .is_err()
        {
            self.declare_controller(version).await;
        }

        let salt = cairo_short_string_to_felt(&username).unwrap();

        let contract_factory =
            ContractFactory::new_with_udc(class_hash, executor, UdcSelector::Legacy);
        let factory = ControllerFactory::new(
            class_hash,
            self.chain_id,
            owner.clone(),
            self.client(),
        );

        let tx = contract_factory
            .deploy_v3(factory.calldata(), salt, false)
            .send()
            .await
            .expect("Unable to deploy contract");

        let address = factory.address(salt);

        TransactionWaiter::new(tx.transaction_hash, &self.client())
            .wait()
            .await
            .unwrap();

        Controller::new(
            username,
            CONTROLLERS[&version].hash,
            self.starknet_url.clone(),
            owner,
            address,
            None,
        )
        .await
        .expect("controller creation should succeed")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore] // Requires Docker
    async fn test_avnu_paymaster_runner_starts() {
        let _runner = AvnuPaymasterRunner::new().await;
        // If we get here, the runner started successfully
    }
}
