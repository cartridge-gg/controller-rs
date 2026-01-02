//! AVNU Paymaster test runner that uses the real paymaster-rpc in-memory with Katana
//!
//! This runner starts:
//! 1. Katana local Starknet node
//! 2. Declares and deploys the forwarder contract to Katana
//! 3. The paymaster RPC server in-memory pointing to Katana
//! 4. Deploys controller contracts to Katana

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use jsonrpsee::server::ServerHandle;
use paymaster_prices::mock::MockPriceOracle;
use paymaster_prices::TokenPrice;
use paymaster_relayer::lock::mock::MockLockLayer;
use paymaster_relayer::lock::{LockLayerConfiguration, RelayerLock};
use paymaster_relayer::RelayersConfiguration;
use paymaster_rpc::server::PaymasterServer;
use paymaster_rpc::{Configuration, RPCConfiguration};
use paymaster_sponsoring::SelfConfiguration;
use paymaster_starknet::constants::Token;
use paymaster_starknet::{
    ChainID, Configuration as StarknetConfiguration, StarknetAccountConfiguration,
};
use starknet::accounts::{Account, ConnectedAccount, ExecutionEncoding, SingleOwnerAccount};
use starknet::contract::{ContractFactory, UdcSelector};
use starknet::core::types::contract::SierraClass;
use starknet::core::types::{BlockId, BlockTag, Call, Felt};
use starknet::macros::selector;
use starknet::providers::jsonrpc::HttpTransport;
use starknet::providers::{JsonRpcClient, Provider};
use starknet::signers::{LocalWallet, SigningKey};
use url::Url;

use crate::artifacts::{Version, FORWARDER};
use crate::controller::Controller;
use crate::provider::CartridgeJsonRpcProvider;
use crate::signers::Owner;

use super::find_free_port;
use super::katana::{KatanaRunner, PREFUNDED};

/// Mock price oracle for testing - returns 1:1 price ratio
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

/// Mock locking layer for testing - always returns the relayer
#[derive(Debug)]
struct MockLockingLayer {
    relayer_address: Felt,
}

impl MockLockingLayer {
    fn new(relayer_address: Felt) -> Self {
        Self { relayer_address }
    }
}

#[async_trait]
impl MockLockLayer for MockLockingLayer {
    fn new() -> Self {
        // This won't be called since we provide a pre-constructed instance
        Self {
            relayer_address: Felt::ZERO,
        }
    }

    async fn count_enabled_relayers(&self) -> usize {
        1
    }

    async fn set_enabled_relayers(&self, _relayers: &HashSet<Felt>) {}

    async fn lock_relayer(&self) -> Result<RelayerLock, paymaster_relayer::lock::Error> {
        Ok(RelayerLock::new(
            self.relayer_address,
            None,
            Duration::from_secs(30),
        ))
    }

    async fn release_relayer(
        &self,
        _lock: RelayerLock,
    ) -> Result<(), paymaster_relayer::lock::Error> {
        Ok(())
    }
}

/// Test runner that uses the real AVNU paymaster in-memory with Katana
pub struct AvnuPaymasterRunner {
    /// The underlying Katana runner
    katana: KatanaRunner,
    /// Deployed forwarder contract address
    pub forwarder_address: Felt,
    /// URL to the paymaster RPC server
    pub paymaster_url: Url,
    /// Handle to the paymaster server (keeps it alive)
    _server_handle: ServerHandle,
    /// JSON-RPC client for Starknet (direct to katana, bypassing cartridge proxy)
    rpc_client: Arc<JsonRpcClient<HttpTransport>>,
}

impl AvnuPaymasterRunner {
    /// Create a new AVNU paymaster test runner
    ///
    /// This will:
    /// 1. Start Katana
    /// 2. Declare and deploy the forwarder contract
    /// 3. Start the paymaster RPC server
    pub async fn new() -> Self {
        // Start Katana
        let katana = KatanaRunner::load();

        // Get direct katana URL (bypassing Cartridge proxy)
        let katana_url = katana.katana_url().clone();
        let chain_id = katana.chain_id();

        // Create RPC client pointing directly to Katana
        let rpc_client = Arc::new(JsonRpcClient::new(HttpTransport::new(katana_url.clone())));

        // Create executor account (prefunded)
        let executor =
            single_owner_account(&rpc_client, PREFUNDED.0.clone(), PREFUNDED.1, chain_id);

        // Declare and deploy forwarder contract
        let forwarder_address = declare_and_deploy_forwarder(&rpc_client, &executor).await;

        // Find a free port for the paymaster RPC
        let paymaster_port = find_free_port();
        let paymaster_url = Url::parse(&format!("http://127.0.0.1:{}", paymaster_port)).unwrap();

        // Create paymaster configuration
        // Use the prefunded account as gas tank, estimate account, and relayer
        let prefunded_config = StarknetAccountConfiguration {
            address: PREFUNDED.1,
            private_key: PREFUNDED.0.secret_scalar(),
        };

        let configuration = Configuration {
            rpc: RPCConfiguration {
                port: paymaster_port as u64,
            },
            supported_tokens: HashSet::from([Token::ETH_ADDRESS, Token::STRK_ADDRESS]),
            forwarder: forwarder_address,
            gas_tank: prefunded_config,
            max_fee_multiplier: 3.0,
            provider_fee_overhead: 0.1,
            estimate_account: prefunded_config,
            relayers: RelayersConfiguration {
                private_key: PREFUNDED.0.secret_scalar(),
                addresses: vec![PREFUNDED.1],
                min_relayer_balance: Felt::ZERO,
                lock: LockLayerConfiguration::Mock {
                    retry_timeout: Duration::from_secs(5),
                    lock_layer: Arc::new(MockLockingLayer::new(PREFUNDED.1)),
                },
                rebalancing:
                    paymaster_relayer::rebalancing::OptionalRebalancingConfiguration::initialize(
                        None,
                    ),
            },
            starknet: StarknetConfiguration {
                chain_id: ChainID::Sepolia,
                endpoint: katana_url.to_string(),
                timeout: 30,
                fallbacks: vec![],
            },
            price: paymaster_prices::Configuration::Mock(Arc::new(MockPriceOracleImpl)),
            // Use self-sponsoring with a test API key for local testing
            // API key must start with 'paymaster_' per paymaster-sponsoring validation
            sponsoring: paymaster_sponsoring::Configuration::SelfSponsoring(SelfConfiguration {
                api_key: "paymaster_test".to_string(),
                sponsor_metadata: vec![],
            }),
        };

        // Start the paymaster server
        let server = PaymasterServer::new(&configuration);
        let server_handle = server
            .start()
            .await
            .expect("Failed to start paymaster server");

        // Wait for server to be ready and relayer balance monitoring to run
        // The RelayerBalanceMonitoring service runs every 60s and sets enabled relayers
        // We wait a bit longer to ensure the service has time to enable the relayer
        tokio::time::sleep(Duration::from_secs(2)).await;

        Self {
            katana,
            forwarder_address,
            paymaster_url,
            _server_handle: server_handle,
            rpc_client,
        }
    }

    /// Get the chain ID
    pub fn chain_id(&self) -> Felt {
        self.katana.chain_id()
    }

    /// Get a Cartridge JSON-RPC provider (goes through Cartridge proxy)
    pub fn client(&self) -> &CartridgeJsonRpcProvider {
        self.katana.client()
    }

    /// Get an executor account (pre-funded account from Katana)
    pub async fn executor(&self) -> SingleOwnerAccount<&JsonRpcClient<HttpTransport>, LocalWallet> {
        single_owner_account(
            &self.rpc_client,
            PREFUNDED.0.clone(),
            PREFUNDED.1,
            self.chain_id(),
        )
    }

    /// Get the direct RPC URL to Katana (bypassing the Cartridge proxy)
    #[cfg(feature = "vrf")]
    pub fn katana_url(&self) -> Url {
        self.katana.katana_url().clone()
    }

    /// Deploy a controller and return it
    pub async fn deploy_controller(
        &self,
        username: String,
        owner: Owner,
        version: Version,
    ) -> Controller {
        self.katana
            .deploy_controller(username, owner, version)
            .await
    }
}

/// Create a SingleOwnerAccount
fn single_owner_account<'a>(
    client: &'a JsonRpcClient<HttpTransport>,
    signing_key: SigningKey,
    account_address: Felt,
    chain_id: Felt,
) -> SingleOwnerAccount<&'a JsonRpcClient<HttpTransport>, LocalWallet> {
    let mut account = SingleOwnerAccount::new(
        client,
        LocalWallet::from(signing_key),
        account_address,
        chain_id,
        ExecutionEncoding::New,
    );
    account.set_block_id(BlockId::Tag(BlockTag::PreConfirmed));
    account
}

/// Declare and deploy the forwarder contract to Katana
async fn declare_and_deploy_forwarder<A>(
    rpc_client: &Arc<JsonRpcClient<HttpTransport>>,
    executor: &A,
) -> Felt
where
    A: Account + ConnectedAccount + Sync,
{
    // Parse the Sierra class and flatten it
    let sierra_class: SierraClass =
        serde_json::from_str(FORWARDER.content).expect("Failed to parse forwarder Sierra class");
    let flattened_class = sierra_class
        .flatten()
        .expect("Failed to flatten forwarder Sierra class");

    // Parse the CASM class
    let casm_class: starknet::core::types::contract::CompiledClass =
        serde_json::from_str(FORWARDER.casm_content).expect("Failed to parse forwarder CASM class");

    // Compute CASM class hash
    let casm_class_hash = casm_class
        .class_hash()
        .expect("Failed to compute CASM hash");

    // Check if already declared
    let class_hash = FORWARDER.class_hash;
    let is_declared = rpc_client
        .get_class(BlockId::Tag(BlockTag::PreConfirmed), class_hash)
        .await
        .is_ok();

    if !is_declared {
        // Declare the contract
        let declare_result = executor
            .declare_v3(Arc::new(flattened_class), casm_class_hash)
            .send()
            .await
            .expect("Failed to declare forwarder");

        // Wait for declaration
        wait_for_tx(rpc_client, declare_result.transaction_hash).await;
    }

    // Deploy the forwarder contract
    // Forwarder constructor requires: owner, gas_fees_recipient
    // We use the executor (prefunded) account as both owner and gas fees recipient
    let owner = executor.address();
    let gas_fees_recipient = executor.address();

    let salt = Felt::from(0x12345u64); // Deterministic salt for testing
    let unique = false; // Not using unique address (uses deployer address in salt)
    let constructor_calldata: Vec<Felt> = vec![owner, gas_fees_recipient];

    let contract_factory = ContractFactory::new_with_udc(class_hash, executor, UdcSelector::Legacy);
    let deployment = contract_factory.deploy_v3(constructor_calldata.clone(), salt, unique);

    // Calculate the deployed address BEFORE sending the transaction
    let deployed_address = deployment.deployed_address();

    let deploy_result = deployment.send().await.expect("Failed to deploy forwarder");

    // Wait for deployment
    wait_for_tx(rpc_client, deploy_result.transaction_hash).await;

    // Whitelist the relayer (executor) on the forwarder so it can call execute
    let whitelist_call = Call {
        to: deployed_address,
        selector: selector!("set_whitelisted_address"),
        calldata: vec![owner, Felt::ONE], // address, is_whitelisted=true
    };

    let whitelist_result = executor
        .execute_v3(vec![whitelist_call])
        .send()
        .await
        .expect("Failed to whitelist relayer");

    wait_for_tx(rpc_client, whitelist_result.transaction_hash).await;

    deployed_address
}

/// Wait for a transaction to be confirmed
async fn wait_for_tx(client: &JsonRpcClient<HttpTransport>, tx_hash: Felt) {
    loop {
        match client.get_transaction_receipt(tx_hash).await {
            Ok(_) => break,
            Err(_) => tokio::time::sleep(Duration::from_millis(100)).await,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_avnu_paymaster_runner_starts() {
        let runner = AvnuPaymasterRunner::new().await;

        // Verify forwarder was deployed
        assert_ne!(runner.forwarder_address, Felt::ZERO);

        // Verify paymaster URL is set
        assert!(runner.paymaster_url.to_string().contains("127.0.0.1"));
    }
}
