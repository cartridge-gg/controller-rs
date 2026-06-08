use std::fmt::{self};

use graphql_client::Response;
use reqwest::RequestBuilder;
use serde::{de::DeserializeOwned, Serialize};
use starknet::providers::ProviderError;
use url::Url;

use crate::errors::ControllerError;
use crate::rate_limit::{
    is_provider_rate_limited, is_reqwest_rate_limited, retry_with_policy, RetryPolicy,
};

#[derive(Debug)]
pub struct Client {
    base_url: Url,
    client: reqwest::Client,
}

impl Client {
    pub fn new(base_url: String) -> Self {
        #[cfg(not(target_arch = "wasm32"))]
        let client_builder = reqwest::Client::builder().cookie_store(true);
        #[cfg(target_arch = "wasm32")]
        let client_builder = reqwest::Client::builder();

        Self {
            client: client_builder.build().expect("Failed to build client"),
            base_url: Url::parse(&base_url).expect("valid url"),
        }
    }

    pub async fn query<R, T>(&self, body: &T) -> Result<R, ControllerError>
    where
        R: DeserializeOwned,
        T: Serialize + ?Sized,
    {
        let path = "/query";

        let response = retry_with_policy(
            RetryPolicy::default(),
            || async {
                let response = self.post(path).json(body).send().await?;
                if response.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
                    return Err(ControllerError::ProviderError(ProviderError::RateLimited));
                }
                Ok(response)
            },
            is_controller_rate_limited,
        )
        .await?;

        let res: Response<R> = response.json().await?;
        if let Some(errors) = res.errors {
            Err(ControllerError::Api(GraphQLErrors(errors)))
        } else {
            res.data.ok_or_else(|| {
                ControllerError::Api(GraphQLErrors(vec![graphql_client::Error {
                    message: "No data in response".to_string(),
                    locations: None,
                    path: None,
                    extensions: None,
                }]))
            })
        }
    }

    fn post(&self, path: &str) -> RequestBuilder {
        let url = self.get_url(path);

        #[cfg(target_arch = "wasm32")]
        {
            self.client.post(url).fetch_credentials_include()
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            self.client.post(url)
        }
    }

    fn get_url(&self, path: &str) -> Url {
        let mut url = self.base_url.clone();
        url.path_segments_mut().unwrap().extend(path.split('/'));
        url
    }
}

fn is_controller_rate_limited(error: &ControllerError) -> bool {
    match error {
        ControllerError::ProviderError(error) => is_provider_rate_limited(error),
        ControllerError::ReqwestError(error) => is_reqwest_rate_limited(error),
        _ => error
            .to_string()
            .to_ascii_lowercase()
            .contains("rate limit"),
    }
}

#[derive(Debug, thiserror::Error)]
pub struct GraphQLErrors(Vec<graphql_client::Error>);

impl fmt::Display for GraphQLErrors {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for err in &self.0 {
            writeln!(f, "ControllerError: {}", err.message)?;
        }
        Ok(())
    }
}
