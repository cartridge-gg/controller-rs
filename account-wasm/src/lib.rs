use wasm_bindgen::JsError;

mod alloc;

#[cfg(feature = "controller_account")]
pub mod account;

#[cfg(feature = "controller_account")]
pub mod multi_chain_account;

#[cfg(feature = "controller_account")]
mod factory;

#[cfg(feature = "controller_account")]
mod owner;

#[cfg(feature = "session_account")]
pub mod session;

mod errors;

mod storage;
mod sync;
mod types;

mod utils;

pub type Result<T> = std::result::Result<T, JsError>;

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
