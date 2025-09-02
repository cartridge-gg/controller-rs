use serde::Deserialize;
use serde::Serialize;

use crate::graphql::GraphQLQuery;
use crate::graphql::JSON;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "schema.json",
    query_path = "src/graphql/login/login.graphql",
    variables_derives = "Debug, Clone, Deserialize",
    response_derives = "Debug, Clone, Serialize, Deserialize"
)]
pub struct BeginLogin;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "schema.json",
    query_path = "src/graphql/login/login.graphql",
    variables_derives = "Debug, Clone, Deserialize",
    response_derives = "Debug, Clone, Serialize, Deserialize"
)]
pub struct FinalizeLogin;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BeginLoginResult {
    pub public_key: PublicKeyInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicKeyInfo {
    pub challenge: String,
}
