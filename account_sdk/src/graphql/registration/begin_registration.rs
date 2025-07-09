use crate::{api::Client, errors::ControllerError};
use graphql_client::GraphQLQuery;
use serde::{Deserialize, Serialize};
use serde_json;
use webauthn_rs_proto::PublicKeyCredentialCreationOptions;

use base64::{prelude::BASE64_URL_SAFE_NO_PAD, Engine};

use webauthn_rs_proto::{
    AttestationConveyancePreference, AuthenticatorAttachment, AuthenticatorSelectionCriteria,
    PubKeyCredParams, RelyingParty, ResidentKeyRequirement, User, UserVerificationPolicy,
};

#[allow(clippy::upper_case_acronyms)]
type JSON = serde_json::Value;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "schema.json",
    query_path = "src/graphql/registration/begin-registration.graphql",
    variables_derives = "Debug, Clone, Deserialize",
    response_derives = "Debug, Clone, Serialize, Deserialize"
)]
pub struct BeginRegistration;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BeginRegistrationInput {
    pub username: String,
}

pub async fn begin_registration(
    input: BeginRegistrationInput,
    cartridge_api_url: String,
) -> Result<begin_registration::ResponseData, ControllerError> {
    let client = Client::new(cartridge_api_url);

    let request_body = BeginRegistration::build_query(begin_registration::Variables {
        username: input.username,
    });

    client.query(&request_body).await
}

impl TryFrom<begin_registration::ResponseData> for PublicKeyCredentialCreationOptions {
    type Error = ControllerError;

    fn try_from(value: begin_registration::ResponseData) -> Result<Self, Self::Error> {
        let begin_registration_response = value.begin_registration;

        let public_key_options = &begin_registration_response["publicKey"];

        let challenge = public_key_options["challenge"].as_str().ok_or(
            ControllerError::InvalidResponseData("Missing challenge".to_string()),
        )?;
        let rp_name = public_key_options["rp"]["name"].as_str().ok_or(
            ControllerError::InvalidResponseData("Missing rp name".to_string()),
        )?;
        let rp_id =
            public_key_options["rp"]["id"]
                .as_str()
                .ok_or(ControllerError::InvalidResponseData(
                    "Missing rp id".to_string(),
                ))?;
        let user_name = public_key_options["user"]["name"].as_str().ok_or(
            ControllerError::InvalidResponseData("Missing user name".to_string()),
        )?;
        let user_display_name = public_key_options["user"]["displayName"].as_str().ok_or(
            ControllerError::InvalidResponseData("Missing user display name".to_string()),
        )?;
        let timeout = public_key_options["timeout"].as_u64().unwrap_or(300000) as u32;
        let display_name = public_key_options["user"]["displayName"].as_str().ok_or(
            ControllerError::InvalidResponseData("Missing user display name".to_string()),
        )?;

        let challenge_bytes = BASE64_URL_SAFE_NO_PAD.decode(challenge).map_err(|e| {
            ControllerError::InvalidResponseData(format!("Failed to decode challenge: {}", e))
        })?;

        let authenticator_selection = AuthenticatorSelectionCriteria {
            authenticator_attachment: Some(AuthenticatorAttachment::Platform),
            resident_key: Some(ResidentKeyRequirement::Preferred),
            require_resident_key: false,
            user_verification: UserVerificationPolicy::Required,
        };

        let options = PublicKeyCredentialCreationOptions {
            rp: RelyingParty {
                id: rp_id.to_string(),
                name: rp_name.to_string(),
            },
            user: User {
                id: BASE64_URL_SAFE_NO_PAD
                    .encode(display_name.as_bytes())
                    .into_bytes()
                    .into(),
                name: user_name.to_string(),
                display_name: user_display_name.to_string(),
            },
            challenge: challenge_bytes.into(),
            pub_key_cred_params: vec![
                PubKeyCredParams {
                    type_: "public-key".to_string(),
                    alg: -7,
                },
                PubKeyCredParams {
                    type_: "public-key".to_string(),
                    alg: -257,
                },
            ],
            timeout: Some(timeout),
            exclude_credentials: None,
            authenticator_selection: Some(authenticator_selection),
            attestation: Some(AttestationConveyancePreference::None),
            attestation_formats: None,
            extensions: None,
            hints: None,
        };

        Ok(options)
    }
}
