use account_sdk::errors::ControllerError;
use starknet::{
    core::types::{ExecutionResult, TransactionStatus},
    providers::Provider,
};
use starknet_crypto::Felt;
use web_sys::js_sys;

pub fn set_panic_hook() {
    // When the `console_error_panic_hook` feature is enabled, we can call the
    // `set_panic_hook` function at least once during initialization, and then
    // we will get better error messages if our code ever panics.
    //
    // For more details see
    // https://github.com/rustwasm/console_error_panic_hook#readme
    #[cfg(feature = "console_error_panic_hook")]
    console_error_panic_hook::set_once();
}

pub async fn wait_for_txn(
    provider: Box<impl Provider>,
    txn_hash: Felt,
    timeout: Option<i64>,
) -> Result<(), ControllerError> {
    let timeout = timeout.unwrap_or(20);
    let start_time = chrono::Utc::now().time();
    let mut time = start_time;
    while time < start_time + chrono::Duration::seconds(timeout) {
        let txn_status = provider.get_transaction_status(txn_hash).await?;

        if txn_status == TransactionStatus::AcceptedOnL2(ExecutionResult::Succeeded) {
            return Ok(());
        } else if let TransactionStatus::AcceptedOnL2(ExecutionResult::Reverted { reason }) =
            txn_status
        {
            return Err(ControllerError::TransactionReverted(reason.clone()));
        }

        sleep(200).await;

        time = chrono::Utc::now().time();
    }
    Err(ControllerError::TransactionReverted("Timeout".to_string()))
}

async fn sleep(ms: i32) {
    let promise = js_sys::Promise::new(&mut |resolve, _| {
        web_sys::window()
            .unwrap()
            .set_timeout_with_callback_and_timeout_and_arguments_0(&resolve, ms)
            .unwrap();
    });
    let _ = wasm_bindgen_futures::JsFuture::from(promise).await;
}
