//! GraphQL query for fetching controller signer credentials.

use crate::errors::ControllerError;
use graphql_client::GraphQLQuery;
use starknet_types_core::felt::Felt;

// Required by graphql_client codegen for schema scalar types
#[expect(dead_code, reason = "required by graphql_client schema scalar mapping")]
type Long = u64;
#[expect(dead_code, reason = "required by graphql_client schema scalar mapping")]
type Time = String;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "schema.json",
    query_path = "src/graphql/controller/controller.graphql",
    response_derives = "Debug, Clone, Serialize, PartialEq, Eq, Deserialize"
)]
pub struct FetchController;

/// Fetches the encrypted private key for a password-signer account.
///
/// Returns `(controller_address, encrypted_private_key_base64)`.
pub async fn fetch_password_credential(
    username: &str,
    chain_id: &str,
    api_url: &str,
) -> Result<(Felt, String), ControllerError> {
    let variables = fetch_controller::Variables {
        username: username.to_string(),
        chain_id: chain_id.to_string(),
    };

    let response_data = super::run_query::<FetchController>(variables, api_url.to_string()).await?;

    let controller = response_data.controller.ok_or_else(|| {
        ControllerError::InvalidResponseData(format!("account '{}' not found", username))
    })?;

    let address = Felt::from_hex(&controller.address).map_err(|e| {
        ControllerError::InvalidResponseData(format!("invalid controller address: {e}"))
    })?;

    // Find the password signer
    let signers = controller.signers.unwrap_or_default();
    for signer in &signers {
        if let fetch_controller::FetchControllerControllerSignersMetadata::PasswordCredentials(
            creds,
        ) = &signer.metadata
        {
            if let Some(passwords) = &creds.password {
                if let Some(first) = passwords.first() {
                    return Ok((address, first.encrypted_private_key.clone()));
                }
            }
        }
    }

    Err(ControllerError::InvalidResponseData(format!(
        "no password signer found for account '{}'",
        username,
    )))
}
