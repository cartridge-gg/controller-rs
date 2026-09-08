//! Self-funded gas headroom configuration.
//!
//! For self-funded (non-paymaster) transactions, the controller inflates the
//! estimated gas *amount* by this multiplier so estimate-to-execution drift
//! doesn't run the transaction out of resources.
//! The automatic session fallback also buffers gas prices independently.

use crate::errors::ControllerError;
use starknet::core::types::FeeEstimate;

/// Add the same 50% gas-price headroom as the keychain confirmation flow to a
/// raw RPC estimate. Only the automatic self-funded fallback calls this: an
/// explicitly supplied max fee may already be buffered and must be respected.
pub(crate) fn with_gas_price_headroom(mut estimate: FeeEstimate) -> FeeEstimate {
    let add_headroom = |price: u128| price.saturating_add(price / 2);
    estimate.l1_gas_price = add_headroom(estimate.l1_gas_price);
    estimate.l2_gas_price = add_headroom(estimate.l2_gas_price);
    estimate.l1_data_gas_price = add_headroom(estimate.l1_data_gas_price);
    estimate
}

/// Default multiplier: the historical 1.5x headroom. Also the minimum, since a
/// lower value would reduce headroom below the safe baseline.
pub const DEFAULT_GAS_MULTIPLIER: f64 = 1.5;

/// Maximum multiplier. The multiplier only inflates the gas *amount*, never the
/// price. A >10x gap between estimate and actual consumption indicates a
/// mis-estimate rather than normal volatility, and this ceiling also rejects
/// obviously erroneous values (e.g. a raw gas amount passed by mistake).
pub const MAX_GAS_MULTIPLIER: f64 = 10.0;

/// A validated multiplier applied to estimated gas *amounts* (never prices)
/// when a transaction is self-funded by the user.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct GasMultiplier(f64);

impl GasMultiplier {
    /// Creates a validated [`GasMultiplier`]. The value must be finite and
    /// within `[DEFAULT_GAS_MULTIPLIER, MAX_GAS_MULTIPLIER]`.
    pub fn new(value: f64) -> Result<Self, ControllerError> {
        if !value.is_finite() || !(DEFAULT_GAS_MULTIPLIER..=MAX_GAS_MULTIPLIER).contains(&value) {
            return Err(ControllerError::InvalidGasMultiplier {
                value,
                min: DEFAULT_GAS_MULTIPLIER,
                max: MAX_GAS_MULTIPLIER,
            });
        }
        Ok(Self(value))
    }

    /// The underlying multiplier value.
    pub fn value(self) -> f64 {
        self.0
    }

    /// Applies the multiplier to a gas *amount*, truncating to `u64`. This is
    /// the single place the multiplier is applied, so headroom is never
    /// compounded.
    pub fn apply(self, gas_amount: u64) -> u64 {
        (gas_amount as f64 * self.0) as u64
    }
}

impl Default for GasMultiplier {
    fn default() -> Self {
        Self(DEFAULT_GAS_MULTIPLIER)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn price_headroom_preserves_gas_amounts_and_raw_overall_fee() {
        let estimate = with_gas_price_headroom(FeeEstimate {
            l1_gas_consumed: 10,
            l1_gas_price: 96_966_059_925_918,
            l2_gas_consumed: 20,
            l2_gas_price: 101,
            l1_data_gas_consumed: 30,
            l1_data_gas_price: 134_488_580_849,
            overall_fee: 1_000,
        });

        assert_eq!(estimate.l1_gas_price, 145_449_089_888_877);
        assert_eq!(estimate.l2_gas_price, 151);
        assert_eq!(estimate.l1_data_gas_price, 201_732_871_273);
        assert_eq!(estimate.l1_gas_consumed, 10);
        assert_eq!(estimate.l2_gas_consumed, 20);
        assert_eq!(estimate.l1_data_gas_consumed, 30);
        assert_eq!(estimate.overall_fee, 1_000);
    }

    #[test]
    fn price_headroom_handles_zero_and_u128_limits() {
        let estimate = with_gas_price_headroom(FeeEstimate {
            l1_gas_consumed: 0,
            l1_gas_price: 0,
            l2_gas_consumed: 0,
            l2_gas_price: u128::MAX,
            l1_data_gas_consumed: 0,
            l1_data_gas_price: u128::MAX / 2,
            overall_fee: 0,
        });

        assert_eq!(estimate.l1_gas_price, 0);
        assert_eq!(estimate.l2_gas_price, u128::MAX);
        assert_eq!(estimate.l1_data_gas_price, u128::MAX / 2 + u128::MAX / 4);
    }

    #[test]
    fn default_is_historical_headroom() {
        assert_eq!(GasMultiplier::default().value(), 1.5);
    }

    #[test]
    fn new_accepts_default_and_configured_values() {
        assert_eq!(GasMultiplier::new(1.5).unwrap().value(), 1.5);
        assert_eq!(GasMultiplier::new(2.0).unwrap().value(), 2.0);
        assert_eq!(
            GasMultiplier::new(MAX_GAS_MULTIPLIER).unwrap().value(),
            MAX_GAS_MULTIPLIER
        );
    }

    #[test]
    fn new_rejects_values_below_minimum() {
        assert!(matches!(
            GasMultiplier::new(1.0),
            Err(ControllerError::InvalidGasMultiplier { .. })
        ));
        assert!(matches!(
            GasMultiplier::new(1.49),
            Err(ControllerError::InvalidGasMultiplier { .. })
        ));
    }

    #[test]
    fn new_rejects_values_above_maximum() {
        assert!(matches!(
            GasMultiplier::new(MAX_GAS_MULTIPLIER + 0.1),
            Err(ControllerError::InvalidGasMultiplier { .. })
        ));
    }

    #[test]
    fn new_rejects_non_finite_values() {
        assert!(matches!(
            GasMultiplier::new(f64::NAN),
            Err(ControllerError::InvalidGasMultiplier { .. })
        ));
        assert!(matches!(
            GasMultiplier::new(f64::INFINITY),
            Err(ControllerError::InvalidGasMultiplier { .. })
        ));
    }

    #[test]
    fn apply_scales_gas_amount_once() {
        // Default 1.5x headroom.
        assert_eq!(GasMultiplier::default().apply(1000), 1500);
        // Configured 2x headroom applied exactly once.
        assert_eq!(GasMultiplier::new(2.0).unwrap().apply(1000), 2000);
        // Zero stays zero.
        assert_eq!(GasMultiplier::default().apply(0), 0);
    }
}
