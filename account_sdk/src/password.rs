//! Password-based headless authentication for Cartridge Controller.
//!
//! Fetches a password-encrypted private key from Cartridge's API,
//! decrypts it locally, and constructs a Controller with the owner key in memory.

use starknet::signers::SigningKey;
use url::Url;

use crate::artifacts::{Version, CONTROLLERS};
use crate::controller::Controller;
use crate::crypto::decrypt_password_key;
use crate::errors::ControllerError;
use crate::graphql::controller::fetch_password_credential;
use crate::provider::CartridgeJsonRpcProvider;
use crate::signers::{Owner, Signer};

use starknet::core::utils::parse_cairo_short_string;
use starknet::providers::Provider;

impl Controller {
    /// Creates a Controller by authenticating with a Cartridge username and password.
    ///
    /// The owner private key exists only in memory. After creating a session,
    /// the caller should drop this Controller — only the persisted session key
    /// is needed for subsequent transactions.
    pub async fn from_password(
        username: &str,
        password: &str,
        rpc_url: Url,
        api_url: &str,
    ) -> Result<Self, ControllerError> {
        let provider = CartridgeJsonRpcProvider::new(rpc_url.clone());
        let chain_id = provider.chain_id().await?;
        let chain_id_str = parse_cairo_short_string(&chain_id)?;

        let (address, encrypted_key) =
            fetch_password_credential(username, &chain_id_str, api_url).await?;

        let private_key_felt = decrypt_password_key(&encrypted_key, password)?;

        let signing_key = SigningKey::from_secret_scalar(private_key_felt);
        let owner = Owner::Signer(Signer::Starknet(signing_key));

        let class_hash = CONTROLLERS[&Version::LATEST].hash;

        Controller::new(
            username.to_lowercase(),
            class_hash,
            rpc_url,
            owner,
            address,
            None,
        )
        .await
    }
}
