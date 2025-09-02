pub mod login;
pub mod owner;
pub mod registration;
pub mod session;

pub use graphql_client::{GraphQLQuery, Response};

use crate::{api::Client, errors::ControllerError};

pub type Long = u64;
#[allow(clippy::upper_case_acronyms)]
pub type JSON = serde_json::Value;

pub async fn run_query<T: GraphQLQuery>(
    input: T::Variables,
    cartridge_api_url: String,
) -> Result<T::ResponseData, ControllerError> {
    let client = Client::new(cartridge_api_url);
    let request_body = T::build_query(input);
    client.query(&request_body).await
}
