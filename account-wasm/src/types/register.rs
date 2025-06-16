use serde::{Deserialize, Serialize};
use tsify_next::Tsify;
use wasm_bindgen::prelude::*;

#[derive(Tsify, Serialize, Deserialize, Debug, Clone)]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub struct JsRegister(account_sdk::graphql::register::RegisterInput);

impl From<JsRegister> for account_sdk::graphql::register::RegisterInput {
    fn from(value: JsRegister) -> Self {
        value.0
    }
}

#[derive(Tsify, Serialize, Deserialize, Debug, Clone)]
#[tsify(into_wasm_abi, from_wasm_abi)]
#[serde(rename_all = "camelCase")]
pub struct JsRegisterResponse(account_sdk::graphql::register::register::ResponseData);

impl From<account_sdk::graphql::register::register::ResponseData> for JsRegisterResponse {
    fn from(value: account_sdk::graphql::register::register::ResponseData) -> Self {
        JsRegisterResponse(value)
    }
}
