use crate::api::Client;
use crate::errors::ControllerError;
use crate::graphql::owner::add_owner::SignerInput;
use anyhow::Result;
use graphql_client::GraphQLQuery;
use starknet_crypto::Felt;

type JSON = String;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "schema.json",
    query_path = "src/graphql/owner/add-owner.graphql",
    variables_derives = "Debug, Clone, PartialEq, Eq, Deserialize",
    response_derives = "Debug, Clone, PartialEq, Eq, Deserialize"
)]
pub struct AddOwner;

pub struct AddOwnerInput {
    pub username: String,
    pub chain_id: String,
    pub signer_guid: Felt,
    pub owner: SignerInput,
}

pub async fn add_owner(
    input: AddOwnerInput,
    cartridge_api_url: String,
) -> Result<add_owner::ResponseData, ControllerError> {
    let client = Client::new(cartridge_api_url);

    let request_body = AddOwner::build_query(add_owner::Variables {
        username: input.username,
        chain_id: input.chain_id,
        signer_guid: input.signer_guid,
        owner: input.owner,
    });

    client.query(&request_body).await
}
