use crate::graphql::{Long, JSON};
use crate::{api::Client, errors::ControllerError};
use graphql_client::GraphQLQuery;
use serde::{Deserialize, Serialize};
use starknet_crypto::Felt;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "schema.json",
    query_path = "src/graphql/registration/register.graphql",
    variables_derives = "Debug, Clone, Deserialize",
    response_derives = "Debug, Clone, Serialize, Deserialize"
)]
pub struct Register;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterInput {
    pub username: String,
    pub chain_id: String,
    pub owner: register::SignerInput,
    pub session: register::SessionInput,
}

pub async fn register(
    input: RegisterInput,
    cartridge_api_url: String,
) -> Result<register::ResponseData, ControllerError> {
    let client = Client::new(cartridge_api_url);

    let request_body = Register::build_query(register::Variables {
        username: input.username,
        chain_id: input.chain_id,
        owner: input.owner,
        session: input.session,
    });

    client.query(&request_body).await
}
