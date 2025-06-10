use crate::api::Client;
use crate::errors::ControllerError;
use crate::graphql::session::revoke_sessions::RevokeSessionInput;
use anyhow::Result;
use graphql_client::GraphQLQuery;
use starknet_crypto::Felt;

type Long = u64;

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

pub struct CreateSessionInput {
    pub username: String,
    pub app_id: String,
    pub chain_id: String,
    pub session: create_session::SessionInput,
}

pub async fn create_session(
    input: CreateSessionInput,
    cartridge_api_url: String,
) -> Result<create_session::ResponseData, ControllerError> {
    let client = Client::new(cartridge_api_url);

    let request_body = CreateSession::build_query(create_session::Variables {
        username: input.username,
        app_id: input.app_id,
        chain_id: input.chain_id,
        session: create_session::SessionInput {
            expires_at: input.session.expires_at,
            allowed_policies_root: input.session.allowed_policies_root,
            metadata_hash: input.session.metadata_hash,
            session_key_guid: input.session.session_key_guid,
            guardian_key_guid: input.session.guardian_key_guid,
            authorization: input.session.authorization,
            app_id: None,
        },
    });

    client.query(&request_body).await
}

pub async fn revoke_sessions(
    sessions: Vec<RevokeSessionInput>,
    cartridge_api_url: String,
) -> Result<revoke_sessions::ResponseData, ControllerError> {
    let client = Client::new(cartridge_api_url);

    let request_body = RevokeSessions::build_query(revoke_sessions::Variables { sessions });

    client.query(&request_body).await
}
