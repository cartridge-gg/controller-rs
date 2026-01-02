//! VRF test runner that wraps the AVNU Paymaster runner with VRF capabilities.
//!
//! This runner:
//! 1. Starts Katana and AVNU paymaster (via AvnuPaymasterRunner)
//! 2. Declares and deploys VRF Account and VRF Consumer contracts
//! 3. Provides VRF proof generation via stark-vrf crate

use std::sync::Arc;
use std::time::Duration;

use stark_vrf::{
    base_field_from_field_element, field_element_from_base_field, field_element_from_scalar_field,
    generate_public_key, scalar_field_from_field_element, BaseField, ScalarField, StarkVRF,
};
use starknet::accounts::{Account, ConnectedAccount, ExecutionEncoding, SingleOwnerAccount};
use starknet::contract::{ContractFactory, UdcSelector};
use starknet::core::types::contract::SierraClass;
use starknet::core::types::{BlockId, BlockTag, Felt};
use starknet::providers::jsonrpc::HttpTransport;
use starknet::providers::{JsonRpcClient, Provider};
use starknet::signers::{LocalWallet, SigningKey};
use url::Url;

use crate::provider::CartridgeJsonRpcProvider;
use crate::tests::vrf_types::{Point, Proof};

use super::avnu_paymaster::AvnuPaymasterRunner;
use super::katana::PREFUNDED;

/// VRF Account contract class (Sierra JSON)
const VRF_ACCOUNT_CLASS: &str =
    include_str!("../../../artifacts/classes/vrf/cartridge_vrf_VrfAccount.contract_class.json");

/// VRF Account compiled contract class (CASM JSON)
const VRF_ACCOUNT_CASM: &str = include_str!(
    "../../../artifacts/classes/vrf/cartridge_vrf_VrfAccount.compiled_contract_class.json"
);

/// VRF Consumer contract class (Sierra JSON)
const VRF_CONSUMER_CLASS: &str =
    include_str!("../../../artifacts/classes/vrf/cartridge_vrf_VrfConsumer.contract_class.json");

/// VRF Consumer compiled contract class (CASM JSON)
const VRF_CONSUMER_CASM: &str = include_str!(
    "../../../artifacts/classes/vrf/cartridge_vrf_VrfConsumer.compiled_contract_class.json"
);

/// VRF test runner with proof generation capabilities
pub struct VrfRunner {
    /// The underlying AVNU paymaster runner
    pub avnu: AvnuPaymasterRunner,
    /// VRF secret key for proof generation
    vrf_secret_key: u64,
    /// VRF public key (x, y coordinates)
    pub vrf_public_key: (Felt, Felt),
    /// Deployed VRF Account contract address (provides randomness)
    pub vrf_account_address: Felt,
    /// Account public key for VRF Account
    pub account_public_key: Felt,
    /// Account private key for VRF Account
    account_private_key: SigningKey,
    /// Deployed Game Player Account address (requests randomness and plays)
    pub player_account_address: Felt,
    /// Account public key for Game Player Account
    pub player_public_key: Felt,
    /// Account private key for Game Player Account
    player_private_key: SigningKey,
    /// Deployed VRF Consumer contract address
    pub vrf_consumer_address: Felt,
    /// VRF Account class hash
    pub vrf_account_class_hash: Felt,
    /// VRF Consumer class hash
    pub vrf_consumer_class_hash: Felt,
    /// JSON-RPC client for Starknet (direct to katana)
    rpc_client: Arc<JsonRpcClient<HttpTransport>>,
}

impl VrfRunner {
    /// Create a new VRF test runner
    ///
    /// This will:
    /// 1. Start the AVNU paymaster runner (Katana + paymaster)
    /// 2. Declare and deploy VRF Account contract (provides randomness)
    /// 3. Declare and deploy Game Player Account (requests randomness)
    /// 4. Declare and deploy VRF Consumer contract (game logic)
    pub async fn new() -> Self {
        // VRF secret key for testing (must match the key used in VRF account setup)
        let vrf_secret_key: u64 = 420;

        // Compute VRF public key from secret key
        let vrf_public_key = compute_vrf_public_key(vrf_secret_key);

        // Account keys for VRF Account (provides randomness)
        let account_private_key = SigningKey::from_secret_scalar(Felt::from(0x111u64));
        let account_public_key = account_private_key.verifying_key().scalar();

        // Account keys for Game Player Account (requests randomness and plays)
        let player_private_key = SigningKey::from_secret_scalar(Felt::from(0x222u64));
        let player_public_key = player_private_key.verifying_key().scalar();

        // Start AVNU paymaster runner
        let avnu = AvnuPaymasterRunner::new().await;

        // Create RPC client pointing to katana
        let katana_url = get_katana_url(&avnu);
        let rpc_client = Arc::new(JsonRpcClient::new(HttpTransport::new(katana_url)));

        // Create executor account (prefunded)
        let chain_id = avnu.chain_id();
        let executor =
            single_owner_account(&rpc_client, PREFUNDED.0.clone(), PREFUNDED.1, chain_id);

        // Declare VRF Account class (used for both VRF provider and game player)
        let vrf_account_class_hash =
            declare_vrf_account_class(&rpc_client, &executor).await;

        // Deploy VRF Account (provides randomness)
        let vrf_account_address =
            deploy_vrf_account(&rpc_client, &executor, vrf_account_class_hash, account_public_key, Felt::from(0x54321u64)).await;

        // Fund the VRF Account so it can execute transactions
        fund_account(&rpc_client, &executor, vrf_account_address).await;

        // Set the VRF public key on the VRF Account
        set_vrf_public_key(
            &rpc_client,
            &account_private_key,
            vrf_account_address,
            vrf_public_key,
            chain_id,
        )
        .await;

        // Deploy Game Player Account (requests randomness and plays the game)
        // This is also a VRF Account but without VRF public key set - it only uses
        // the execute_from_outside_v2 functionality
        let player_account_address =
            deploy_vrf_account(&rpc_client, &executor, vrf_account_class_hash, player_public_key, Felt::from(0x67890u64)).await;

        // Fund the Game Player Account
        fund_account(&rpc_client, &executor, player_account_address).await;

        // Declare and deploy VRF Consumer (game contract)
        let (vrf_consumer_address, vrf_consumer_class_hash) =
            declare_and_deploy_vrf_consumer(&rpc_client, &executor, vrf_account_address).await;

        Self {
            avnu,
            vrf_secret_key,
            vrf_public_key,
            vrf_account_address,
            account_public_key,
            account_private_key,
            player_account_address,
            player_public_key,
            player_private_key,
            vrf_consumer_address,
            vrf_account_class_hash,
            vrf_consumer_class_hash,
            rpc_client,
        }
    }

    /// Generate a VRF proof for the given seed
    pub fn generate_proof(&self, seed: Felt) -> Proof {
        // Create the VRF instance with public key
        let secret_key = scalar_field_from_u64(self.vrf_secret_key);
        let public_key = generate_public_key(secret_key);
        let ecvrf = StarkVRF::new(public_key).unwrap();

        // Generate proof
        let seed_field = felt_to_base_field(seed);
        let proof = ecvrf.prove(&secret_key, &[seed_field]).unwrap();

        // Get sqrt_ratio hint
        let sqrt_ratio_hint = ecvrf.hash_to_sqrt_ratio_hint(&[seed_field]);

        Proof {
            gamma: Point {
                x: base_field_to_felt(proof.0.x),
                y: base_field_to_felt(proof.0.y),
            },
            c: scalar_field_to_felt(proof.1),
            s: scalar_field_to_felt(proof.2),
            sqrt_ratio_hint: base_field_to_felt(sqrt_ratio_hint),
        }
    }

    /// Get the chain ID
    pub fn chain_id(&self) -> Felt {
        self.avnu.chain_id()
    }

    /// Get a Cartridge JSON-RPC provider
    pub fn client(&self) -> &CartridgeJsonRpcProvider {
        self.avnu.client()
    }

    /// Get the paymaster URL
    pub fn paymaster_url(&self) -> Url {
        self.avnu.paymaster_url.clone()
    }

    /// Get the forwarder address (from AVNU runner)
    pub fn forwarder_address(&self) -> Felt {
        self.avnu.forwarder_address
    }

    /// Get an executor account for the VRF Account
    pub fn vrf_account(
        &self,
    ) -> SingleOwnerAccount<Arc<JsonRpcClient<HttpTransport>>, LocalWallet> {
        let mut account = SingleOwnerAccount::new(
            self.rpc_client.clone(),
            LocalWallet::from(self.account_private_key.clone()),
            self.vrf_account_address,
            self.chain_id(),
            ExecutionEncoding::New,
        );
        account.set_block_id(BlockId::Tag(BlockTag::PreConfirmed));
        account
    }

    /// Get a pre-funded executor account
    pub async fn executor(
        &self,
    ) -> SingleOwnerAccount<&JsonRpcClient<HttpTransport>, LocalWallet> {
        self.avnu.executor().await
    }

    /// Get the current dice value from the VRF Consumer contract
    pub async fn get_dice_value(&self) -> u64 {
        use starknet::core::types::{BlockId, BlockTag, FunctionCall};
        use starknet::macros::selector;
        use starknet::providers::Provider;

        let result = self
            .rpc_client
            .call(
                FunctionCall {
                    contract_address: self.vrf_consumer_address,
                    entry_point_selector: selector!("get_dice_value"),
                    calldata: vec![],
                },
                BlockId::Tag(BlockTag::PreConfirmed),
            )
            .await
            .expect("Failed to call get_dice_value");

        // The result is a single felt representing the dice value
        result[0].try_into().unwrap_or(0)
    }

    /// Get the VRF public key from the contract (for verification)
    pub async fn get_contract_vrf_public_key(&self) -> (Felt, Felt) {
        use starknet::core::types::{BlockId, BlockTag, FunctionCall};
        use starknet::macros::selector;
        use starknet::providers::Provider;

        let result = self
            .rpc_client
            .call(
                FunctionCall {
                    contract_address: self.vrf_account_address,
                    entry_point_selector: selector!("get_vrf_public_key"),
                    calldata: vec![],
                },
                BlockId::Tag(BlockTag::PreConfirmed),
            )
            .await
            .expect("Failed to call get_vrf_public_key");

        (result[0], result[1])
    }

    /// Get the account public key from the contract (for verification)
    pub async fn get_contract_public_key(&self) -> Felt {
        use starknet::core::types::{BlockId, BlockTag, FunctionCall};
        use starknet::macros::selector;
        use starknet::providers::Provider;

        let result = self
            .rpc_client
            .call(
                FunctionCall {
                    contract_address: self.vrf_account_address,
                    entry_point_selector: selector!("get_public_key"),
                    calldata: vec![],
                },
                BlockId::Tag(BlockTag::PreConfirmed),
            )
            .await
            .expect("Failed to call get_public_key");

        result[0]
    }

    /// Sign an outside execution using the VRF account's private key
    ///
    /// This signs the SNIP-9 typed data hash with Starknet ECDSA.
    pub fn sign_outside_execution(
        &self,
        outside_execution: &crate::tests::vrf_types::OutsideExecution,
    ) -> Vec<Felt> {
        // Compute the message hash according to SNIP-9 v2
        let message_hash =
            outside_execution.get_message_hash(self.chain_id(), self.vrf_account_address);

        // Sign with the VRF account's private key using Starknet ECDSA
        let signature = self.account_private_key.sign(&message_hash).unwrap();

        // Return as [r, s] vector
        vec![signature.r, signature.s]
    }

    /// Sign an outside execution using the player account's private key
    ///
    /// This signs the SNIP-9 typed data hash with Starknet ECDSA for the game player.
    pub fn sign_player_outside_execution(
        &self,
        outside_execution: &crate::tests::vrf_types::OutsideExecution,
    ) -> Vec<Felt> {
        // Compute the message hash according to SNIP-9 v2
        let message_hash =
            outside_execution.get_message_hash(self.chain_id(), self.player_account_address);

        // Sign with the player account's private key using Starknet ECDSA
        let signature = self.player_private_key.sign(&message_hash).unwrap();

        // Return as [r, s] vector
        vec![signature.r, signature.s]
    }
}

/// Compute VRF public key from secret key
fn compute_vrf_public_key(secret_key: u64) -> (Felt, Felt) {
    let secret = scalar_field_from_u64(secret_key);
    let pk = generate_public_key(secret);
    (base_field_to_felt(pk.x), base_field_to_felt(pk.y))
}

/// Convert Felt to stark_vrf BaseField
fn felt_to_base_field(felt: Felt) -> BaseField {
    // The older stark-vrf uses starknet_ff::FieldElement
    use starknet_ff::FieldElement;
    let fe = FieldElement::from_bytes_be(&felt.to_bytes_be()).unwrap();
    base_field_from_field_element(&fe)
}

/// Convert stark_vrf BaseField to Felt
fn base_field_to_felt(field: BaseField) -> Felt {
    let fe = field_element_from_base_field(&field);
    Felt::from_bytes_be(&fe.to_bytes_be())
}

/// Convert u64 to stark_vrf ScalarField
fn scalar_field_from_u64(val: u64) -> ScalarField {
    use starknet_ff::FieldElement;
    let fe = FieldElement::from(val);
    scalar_field_from_field_element(&fe)
}

/// Convert stark_vrf ScalarField to Felt
fn scalar_field_to_felt(field: ScalarField) -> Felt {
    let fe = field_element_from_scalar_field(&field);
    Felt::from_bytes_be(&fe.to_bytes_be())
}

/// Get Katana URL from the AVNU paymaster runner
fn get_katana_url(avnu: &AvnuPaymasterRunner) -> Url {
    avnu.katana_url()
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

/// Declare the VRF Account contract class
async fn declare_vrf_account_class<A>(
    rpc_client: &Arc<JsonRpcClient<HttpTransport>>,
    executor: &A,
) -> Felt
where
    A: Account + ConnectedAccount + Sync,
{
    // Parse the Sierra class
    let sierra_class: SierraClass =
        serde_json::from_str(VRF_ACCOUNT_CLASS).expect("Failed to parse VRF Account Sierra class");
    let class_hash = sierra_class.class_hash().unwrap();
    let flattened_class = sierra_class
        .flatten()
        .expect("Failed to flatten VRF Account Sierra class");

    // Parse the CASM class to compute hash
    let casm_class: starknet::core::types::contract::CompiledClass =
        serde_json::from_str(VRF_ACCOUNT_CASM).expect("Failed to parse VRF Account CASM class");
    let casm_class_hash = casm_class
        .class_hash()
        .expect("Failed to compute VRF Account CASM hash");

    // Check if already declared
    let is_declared = rpc_client
        .get_class(BlockId::Tag(BlockTag::PreConfirmed), class_hash)
        .await
        .is_ok();

    if !is_declared {
        let declare_result = executor
            .declare_v3(Arc::new(flattened_class), casm_class_hash)
            .send()
            .await
            .expect("Failed to declare VRF Account");

        wait_for_tx(rpc_client, declare_result.transaction_hash).await;
    }

    class_hash
}

/// Deploy a VRF Account contract instance
async fn deploy_vrf_account<A>(
    rpc_client: &Arc<JsonRpcClient<HttpTransport>>,
    executor: &A,
    class_hash: Felt,
    account_public_key: Felt,
    salt: Felt,
) -> Felt
where
    A: Account + ConnectedAccount + Sync,
{
    // Constructor: public_key (felt252)
    let unique = false;
    let constructor_calldata: Vec<Felt> = vec![account_public_key];

    let contract_factory =
        ContractFactory::new_with_udc(class_hash, executor, UdcSelector::Legacy);
    let deployment = contract_factory.deploy_v3(constructor_calldata.clone(), salt, unique);
    let deployed_address = deployment.deployed_address();

    let deploy_result = deployment
        .send()
        .await
        .expect("Failed to deploy VRF Account");
    wait_for_tx(rpc_client, deploy_result.transaction_hash).await;

    deployed_address
}

/// Declare and deploy the VRF Consumer contract
async fn declare_and_deploy_vrf_consumer<A>(
    rpc_client: &Arc<JsonRpcClient<HttpTransport>>,
    executor: &A,
    vrf_provider_address: Felt,
) -> (Felt, Felt)
where
    A: Account + ConnectedAccount + Sync,
{
    // Parse the Sierra class
    let sierra_class: SierraClass = serde_json::from_str(VRF_CONSUMER_CLASS)
        .expect("Failed to parse VRF Consumer Sierra class");
    let class_hash = sierra_class.class_hash().unwrap();
    let flattened_class = sierra_class
        .flatten()
        .expect("Failed to flatten VRF Consumer Sierra class");

    // Parse the CASM class to compute hash
    let casm_class: starknet::core::types::contract::CompiledClass =
        serde_json::from_str(VRF_CONSUMER_CASM).expect("Failed to parse VRF Consumer CASM class");
    let casm_class_hash = casm_class
        .class_hash()
        .expect("Failed to compute VRF Consumer CASM hash");

    // Check if already declared
    let is_declared = rpc_client
        .get_class(BlockId::Tag(BlockTag::PreConfirmed), class_hash)
        .await
        .is_ok();

    if !is_declared {
        let declare_result = executor
            .declare_v3(Arc::new(flattened_class), casm_class_hash)
            .send()
            .await
            .expect("Failed to declare VRF Consumer");

        wait_for_tx(rpc_client, declare_result.transaction_hash).await;
    }

    // Deploy the VRF Consumer contract
    // Constructor: vrf_provider (ContractAddress)
    let salt = Felt::from(0x98765u64);
    let unique = false;
    let constructor_calldata: Vec<Felt> = vec![vrf_provider_address];

    let contract_factory =
        ContractFactory::new_with_udc(class_hash, executor, UdcSelector::Legacy);
    let deployment = contract_factory.deploy_v3(constructor_calldata.clone(), salt, unique);
    let deployed_address = deployment.deployed_address();

    let deploy_result = deployment
        .send()
        .await
        .expect("Failed to deploy VRF Consumer");
    wait_for_tx(rpc_client, deploy_result.transaction_hash).await;

    (deployed_address, class_hash)
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

/// Fund an account with ETH/STRK
async fn fund_account<A>(
    rpc_client: &Arc<JsonRpcClient<HttpTransport>>,
    executor: &A,
    account_address: Felt,
) where
    A: Account + ConnectedAccount + Sync,
{
    use cainome::cairo_serde::{CairoSerde, ContractAddress, U256};
    use starknet::macros::selector;

    // Use the FEE_TOKEN_ADDRESS (STRK)
    let fee_token = &crate::tests::account::FEE_TOKEN_ADDRESS;
    let amount = U256 {
        low: 10_000_000_000_000_000_000_u128, // 10 STRK
        high: 0,
    };

    let calldata = [
        <ContractAddress as CairoSerde>::cairo_serialize(&ContractAddress(account_address)),
        <U256 as CairoSerde>::cairo_serialize(&amount),
    ]
    .concat();

    let call = starknet::core::types::Call {
        to: **fee_token,
        selector: selector!("transfer"),
        calldata,
    };

    let result = executor
        .execute_v3(vec![call])
        .send()
        .await
        .expect("Failed to fund VRF account");

    wait_for_tx(rpc_client, result.transaction_hash).await;
}

/// Set the VRF public key on the VRF Account
/// This requires the VRF account to call itself (assert_only_self)
async fn set_vrf_public_key(
    rpc_client: &Arc<JsonRpcClient<HttpTransport>>,
    account_private_key: &SigningKey,
    vrf_account_address: Felt,
    vrf_public_key: (Felt, Felt),
    chain_id: Felt,
) {
    use cainome::cairo_serde::CairoSerde;
    use starknet::macros::selector;

    // Create a SingleOwnerAccount for the VRF account
    let mut vrf_account = SingleOwnerAccount::new(
        rpc_client.as_ref(),
        LocalWallet::from(account_private_key.clone()),
        vrf_account_address,
        chain_id,
        ExecutionEncoding::New,
    );
    vrf_account.set_block_id(BlockId::Tag(BlockTag::PreConfirmed));

    // Build the calldata for set_vrf_public_key(new_pubkey: PublicKey)
    // PublicKey is (x, y) - two felts
    let calldata = vec![vrf_public_key.0, vrf_public_key.1];

    let call = starknet::core::types::Call {
        to: vrf_account_address,
        selector: selector!("set_vrf_public_key"),
        calldata,
    };

    let result = vrf_account
        .execute_v3(vec![call])
        .send()
        .await
        .expect("Failed to set VRF public key");

    wait_for_tx(rpc_client, result.transaction_hash).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_vrf_runner_starts() {
        let runner = VrfRunner::new().await;

        // Verify VRF contracts were deployed
        assert_ne!(runner.vrf_account_address, Felt::ZERO);
        assert_ne!(runner.vrf_consumer_address, Felt::ZERO);

        // Verify VRF public key is set
        assert_ne!(runner.vrf_public_key.0, Felt::ZERO);
        assert_ne!(runner.vrf_public_key.1, Felt::ZERO);
    }

    #[test]
    fn test_vrf_proof_generation() {
        let vrf_secret_key: u64 = 420;
        let vrf_public_key = compute_vrf_public_key(vrf_secret_key);

        // Create a mock runner just for proof generation
        let seed = Felt::from(0x12345u64);

        // Generate proof
        let secret = scalar_field_from_u64(vrf_secret_key);
        let public_key = generate_public_key(secret);

        let ecvrf = StarkVRF::new(public_key).unwrap();
        let seed_field = felt_to_base_field(seed);
        let proof = ecvrf.prove(&secret, &[seed_field]).unwrap();

        // Verify proof was generated
        assert_ne!(proof.0.x, BaseField::from(0u64));

        // Verify it matches the computed public key
        assert_eq!(base_field_to_felt(public_key.x), vrf_public_key.0);
        assert_eq!(base_field_to_felt(public_key.y), vrf_public_key.1);
    }

    #[test]
    fn test_vrf_public_key_matches_cairo_expected() {
        // From vrf/src/vrf_account/tests/common.cairo:
        // lauch vrf-server : cargo run -r -- -s 420
        // pubkey.x =0x66da5d53168d591c55d4c05f3681663ac51bcdccd5ca09e366b71b0c40ccff4
        // pubkey.y =0x6d3eb29920bf55195e5ec76f69e247c0942c7ef85f6640896c058ec75ca2232
        let expected_x = Felt::from_hex("0x66da5d53168d591c55d4c05f3681663ac51bcdccd5ca09e366b71b0c40ccff4").unwrap();
        let expected_y = Felt::from_hex("0x6d3eb29920bf55195e5ec76f69e247c0942c7ef85f6640896c058ec75ca2232").unwrap();

        let vrf_secret_key: u64 = 420;
        let vrf_public_key = compute_vrf_public_key(vrf_secret_key);

        println!("Expected VRF public key:");
        println!("  x: {:?}", expected_x);
        println!("  y: {:?}", expected_y);
        println!("Computed VRF public key:");
        println!("  x: {:?}", vrf_public_key.0);
        println!("  y: {:?}", vrf_public_key.1);

        // These should match!
        assert_eq!(vrf_public_key.0, expected_x, "VRF public key X mismatch");
        assert_eq!(vrf_public_key.1, expected_y, "VRF public key Y mismatch");
    }
}
