use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use starknet::core::types::{FeeEstimate, PriceUnit};
use tsify_next::Tsify;
use wasm_bindgen::prelude::*;

use super::JsFelt;

#[derive(Tsify, Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub enum JsPriceUnit {
    #[serde(rename = "WEI")]
    Wei,
    #[serde(rename = "FRI")]
    Fri,
}

#[allow(non_snake_case)]
#[serde_as]
#[derive(Tsify, Serialize, Deserialize, Debug, Clone)]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub struct JsEstimateFeeDetails {
    pub nonce: JsFelt,
}

#[serde_as]
#[derive(Tsify, Serialize, Deserialize, Debug, Clone)]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub struct JsFeeEstimate {
    pub l1_gas_consumed: u64,
    pub l1_gas_price: u128,
    pub l2_gas_consumed: u64,
    pub l2_gas_price: u128,
    pub l1_data_gas_consumed: u64,
    pub l1_data_gas_price: u128,
    pub overall_fee: u128,
}

#[serde_as]
#[derive(Tsify, Serialize, Deserialize, Debug, Clone, Default)]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub struct JsFeeEstimateLike {
    pub l1_gas_consumed: Option<u64>,
    pub l1_gas_price: Option<u128>,
    pub l2_gas_consumed: Option<u64>,
    pub l2_gas_price: Option<u128>,
    pub l1_data_gas_consumed: Option<u64>,
    pub l1_data_gas_price: Option<u128>,
    pub overall_fee: Option<u128>,
}

fn is_partial_paymaster_fields(
    l1_gas_consumed: Option<u64>,
    l1_gas_price: Option<u128>,
    l2_gas_consumed: Option<u64>,
    l2_gas_price: Option<u128>,
    l1_data_gas_consumed: Option<u64>,
    l1_data_gas_price: Option<u128>,
) -> bool {
    l1_gas_consumed.unwrap_or(0) == 0
        && l1_gas_price.unwrap_or(0) == 0
        && l2_gas_consumed.unwrap_or(0) == 0
        && l2_gas_price.unwrap_or(0) == 0
        && l1_data_gas_consumed.unwrap_or(0) == 0
        && l1_data_gas_price.unwrap_or(0) == 0
}

/// Returns true when the estimate is missing all per-layer gas details or they are all zeroed.
#[wasm_bindgen(js_name = isPartialPaymaster)]
pub fn is_partial_paymaster(estimate: JsFeeEstimateLike) -> bool {
    is_partial_paymaster_fields(
        estimate.l1_gas_consumed,
        estimate.l1_gas_price,
        estimate.l2_gas_consumed,
        estimate.l2_gas_price,
        estimate.l1_data_gas_consumed,
        estimate.l1_data_gas_price,
    )
}

impl From<JsFeeEstimate> for FeeEstimate {
    fn from(estimate: JsFeeEstimate) -> Self {
        Self {
            l1_gas_consumed: estimate.l1_gas_consumed,
            l1_gas_price: estimate.l1_gas_price,
            l2_gas_consumed: estimate.l2_gas_consumed,
            l2_gas_price: estimate.l2_gas_price,
            l1_data_gas_consumed: estimate.l1_data_gas_consumed,
            l1_data_gas_price: estimate.l1_data_gas_price,
            overall_fee: estimate.overall_fee,
        }
    }
}

impl From<FeeEstimate> for JsFeeEstimate {
    fn from(estimate: FeeEstimate) -> Self {
        Self {
            l1_gas_consumed: estimate.l1_gas_consumed,
            l1_gas_price: estimate.l1_gas_price,
            l2_gas_consumed: estimate.l2_gas_consumed,
            l2_gas_price: estimate.l2_gas_price,
            l1_data_gas_consumed: estimate.l1_data_gas_consumed,
            l1_data_gas_price: estimate.l1_data_gas_price,
            overall_fee: estimate.overall_fee,
        }
    }
}

impl From<JsPriceUnit> for PriceUnit {
    fn from(unit: JsPriceUnit) -> Self {
        match unit {
            JsPriceUnit::Wei => Self::Wei,
            JsPriceUnit::Fri => Self::Fri,
        }
    }
}

impl From<PriceUnit> for JsPriceUnit {
    fn from(unit: PriceUnit) -> Self {
        match unit {
            PriceUnit::Wei => Self::Wei,
            PriceUnit::Fri => Self::Fri,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use starknet::core::types::PriceUnit;

    #[test]
    fn test_fee_estimate_conversion() {
        // Create a JsFeeEstimate that matches the JS structure
        let js_estimate = JsFeeEstimate {
            l1_gas_consumed: 0,
            l1_gas_price: 0,
            l2_gas_consumed: 0,
            l2_gas_price: 0,
            l1_data_gas_consumed: 0,
            l1_data_gas_price: 0,
            overall_fee: 0,
        };

        // Test conversion to FeeEstimate
        let fee_estimate: FeeEstimate = js_estimate.into();

        assert_eq!(fee_estimate.l1_gas_consumed, 0);
        assert_eq!(fee_estimate.l1_gas_price, 0);
        assert_eq!(fee_estimate.l2_gas_consumed, 0);
        assert_eq!(fee_estimate.l2_gas_price, 0);
        assert_eq!(fee_estimate.l1_data_gas_consumed, 0);
        assert_eq!(fee_estimate.l1_data_gas_price, 0);
        assert_eq!(fee_estimate.overall_fee, 0);

        // Test conversion back to JsFeeEstimate
        let converted_back: JsFeeEstimate = fee_estimate.into();

        assert_eq!(converted_back.l1_gas_consumed, 0);
        assert_eq!(converted_back.l1_gas_price, 0);
        assert_eq!(converted_back.l2_gas_consumed, 0);
        assert_eq!(converted_back.l2_gas_price, 0);
        assert_eq!(converted_back.l1_data_gas_consumed, 0);
        assert_eq!(converted_back.l1_data_gas_price, 0);
        assert_eq!(converted_back.overall_fee, 0);
    }

    #[test]
    fn test_price_unit_conversion() {
        assert_eq!(PriceUnit::from(JsPriceUnit::Wei), PriceUnit::Wei);
        assert_eq!(PriceUnit::from(JsPriceUnit::Fri), PriceUnit::Fri);

        assert_eq!(JsPriceUnit::from(PriceUnit::Wei), JsPriceUnit::Wei);
        assert_eq!(JsPriceUnit::from(PriceUnit::Fri), JsPriceUnit::Fri);
    }

    #[test]
    fn test_is_partial_paymaster_all_zero() {
        let estimate = JsFeeEstimateLike {
            l1_gas_consumed: Some(0),
            l1_gas_price: Some(0),
            l2_gas_consumed: Some(0),
            l2_gas_price: Some(0),
            l1_data_gas_consumed: Some(0),
            l1_data_gas_price: Some(0),
            overall_fee: Some(123),
        };

        assert!(is_partial_paymaster(estimate));
    }

    #[test]
    fn test_is_partial_paymaster_any_non_zero() {
        let estimate = JsFeeEstimateLike {
            l1_gas_consumed: Some(0),
            l1_gas_price: Some(0),
            l2_gas_consumed: Some(0),
            l2_gas_price: Some(1),
            l1_data_gas_consumed: Some(0),
            l1_data_gas_price: Some(0),
            overall_fee: Some(123),
        };

        assert!(!is_partial_paymaster(estimate));
    }

    #[test]
    fn test_is_partial_paymaster_missing_fields_treated_as_zero() {
        let estimate = JsFeeEstimateLike {
            l1_gas_consumed: None,
            l1_gas_price: None,
            l2_gas_consumed: None,
            l2_gas_price: None,
            l1_data_gas_consumed: None,
            l1_data_gas_price: None,
            overall_fee: Some(123),
        };

        assert!(is_partial_paymaster(estimate));
    }
}
