#[allow(warnings)]
#[allow(non_snake_case)]
#[allow(clippy)]
pub mod controller;

#[allow(warnings)]
#[allow(non_snake_case)]
#[allow(clippy)]
#[rustfmt::skip]
#[cfg(any(test, feature = "avnu-paymaster"))]
pub mod erc_20;
