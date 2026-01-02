#[allow(warnings)]
#[allow(non_snake_case)]
#[allow(clippy)]
pub mod controller;

#[allow(warnings)]
#[allow(non_snake_case)]
#[allow(clippy)]
#[rustfmt::skip]
#[cfg(test)]
pub mod erc_20;

// VRF bindings are disabled due to code generation issues with recursive Event type
// The Event enum contains `SRC9Event(Event)` which creates a self-referential type
// TODO: Fix cainome code generation or manually patch the generated code
// #[allow(warnings)]
// #[allow(non_snake_case)]
// #[allow(clippy)]
// #[rustfmt::skip]
// #[cfg(test)]
// pub mod vrf_account;

// #[allow(warnings)]
// #[allow(non_snake_case)]
// #[allow(clippy)]
// #[rustfmt::skip]
// #[cfg(test)]
// pub mod vrf_consumer;
