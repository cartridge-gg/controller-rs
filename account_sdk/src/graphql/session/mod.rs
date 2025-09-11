use crate::api::Client;
use crate::errors::ControllerError;
use crate::graphql::session::revoke_sessions::RevokeSessionInput;
use anyhow::Result;
use graphql_client::GraphQLQuery;
use starknet_crypto::Felt;

type Long = u64;
type Time = String;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "schema.json",
    query_path = "src/graphql/session/create-session.graphql",
    response_derives = "Debug, Clone, Serialize, PartialEq, Eq, Deserialize"
)]
pub struct CreateSession;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "schema.json",
    query_path = "src/graphql/session/revoke-sessions.graphql",
    response_derives = "Debug, Clone, Serialize, PartialEq, Eq, Deserialize"
)]
pub struct RevokeSessions;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "schema.json",
    query_path = "src/graphql/session/subscribe-create-session.graphql",
    response_derives = "Debug, Clone, Serialize, PartialEq, Eq, Deserialize"
)]
pub struct SubscribeCreateSession;

pub async fn revoke_sessions(
    sessions: Vec<RevokeSessionInput>,
    cartridge_api_url: String,
) -> Result<revoke_sessions::ResponseData, ControllerError> {
    let client = Client::new(cartridge_api_url);

    let request_body = RevokeSessions::build_query(revoke_sessions::Variables { sessions });

    client.query(&request_body).await
}
