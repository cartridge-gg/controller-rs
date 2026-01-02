use starknet::core::types::ContractExecutionError;

pub mod abigen;
pub mod account;
pub mod api;
pub mod artifacts;
pub mod constants;
pub mod controller;
pub mod errors;
pub mod execute_from_outside;
pub mod factory;
pub mod graphql;
pub mod hash;
pub mod multi_chain;
pub mod owner;
pub mod provider;
pub mod provider_avnu;
pub mod session;
pub mod signers;
pub mod storage;
pub mod transaction_waiter;
pub mod typed_data;
pub mod upgrade;

#[cfg(not(target_arch = "wasm32"))]
#[cfg(any(test, feature = "avnu-paymaster"))]
pub mod tests;

/// Recursively searches through a ContractExecutionError to find a message that contains the specified string.
/// Returns true if the error string is found anywhere in the nested error structure.
pub fn find_error_message_in_execution_error(
    error: &ContractExecutionError,
    search_string: &str,
) -> bool {
    match error {
        ContractExecutionError::Message(msg) => msg.contains(search_string),
        ContractExecutionError::Nested(inner_error) => {
            // Recursively search in the nested error
            find_error_message_in_execution_error(&inner_error.error, search_string)
        }
    }
}
