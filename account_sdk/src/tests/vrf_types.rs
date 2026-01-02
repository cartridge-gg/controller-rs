//! Manual type definitions for VRF contracts.
//! These are defined manually because the auto-generated cainome bindings have issues
//! with recursive Event types.

use cainome::cairo_serde::CairoSerde;
use starknet::core::types::Felt;
use starknet::macros::{selector, short_string};
use starknet_crypto::poseidon_hash_many;

/// VRF Source enum - identifies the source of randomness
#[derive(Clone, Debug, PartialEq)]
pub enum Source {
    /// Use nonce-based seed with the given contract address
    Nonce(cainome::cairo_serde::ContractAddress),
    /// Use salt-based seed with the given salt value
    Salt(Felt),
}

impl CairoSerde for Source {
    type RustType = Self;
    const SERIALIZED_SIZE: Option<usize> = None;

    fn cairo_serialized_size(rust: &Self::RustType) -> usize {
        match rust {
            Source::Nonce(val) => {
                cainome::cairo_serde::ContractAddress::cairo_serialized_size(val) + 1
            }
            Source::Salt(val) => Felt::cairo_serialized_size(val) + 1,
        }
    }

    fn cairo_serialize(rust: &Self::RustType) -> Vec<Felt> {
        match rust {
            Source::Nonce(val) => {
                let mut out = vec![Felt::ZERO]; // discriminant 0
                out.extend(cainome::cairo_serde::ContractAddress::cairo_serialize(val));
                out
            }
            Source::Salt(val) => {
                let mut out = vec![Felt::ONE]; // discriminant 1
                out.extend(Felt::cairo_serialize(val));
                out
            }
        }
    }

    fn cairo_deserialize(
        felts: &[Felt],
        offset: usize,
    ) -> cainome::cairo_serde::Result<Self::RustType> {
        let discriminant: usize = felts[offset].try_into().unwrap();
        match discriminant {
            0 => {
                let val =
                    cainome::cairo_serde::ContractAddress::cairo_deserialize(felts, offset + 1)?;
                Ok(Source::Nonce(val))
            }
            1 => {
                let val = Felt::cairo_deserialize(felts, offset + 1)?;
                Ok(Source::Salt(val))
            }
            _ => Err(cainome::cairo_serde::Error::Deserialize(
                "Invalid Source discriminant".to_string(),
            )),
        }
    }
}

/// Point on the Stark curve
#[derive(Clone, Debug, PartialEq)]
pub struct Point {
    pub x: Felt,
    pub y: Felt,
}

impl CairoSerde for Point {
    type RustType = Self;
    const SERIALIZED_SIZE: Option<usize> = Some(2);

    fn cairo_serialized_size(_rust: &Self::RustType) -> usize {
        2
    }

    fn cairo_serialize(rust: &Self::RustType) -> Vec<Felt> {
        vec![rust.x, rust.y]
    }

    fn cairo_deserialize(
        felts: &[Felt],
        offset: usize,
    ) -> cainome::cairo_serde::Result<Self::RustType> {
        Ok(Point {
            x: felts[offset],
            y: felts[offset + 1],
        })
    }
}

/// VRF Proof structure
#[derive(Clone, Debug, PartialEq)]
pub struct Proof {
    pub gamma: Point,
    pub c: Felt,
    pub s: Felt,
    pub sqrt_ratio_hint: Felt,
}

impl CairoSerde for Proof {
    type RustType = Self;
    const SERIALIZED_SIZE: Option<usize> = Some(5);

    fn cairo_serialized_size(_rust: &Self::RustType) -> usize {
        5
    }

    fn cairo_serialize(rust: &Self::RustType) -> Vec<Felt> {
        let mut out = Point::cairo_serialize(&rust.gamma);
        out.push(rust.c);
        out.push(rust.s);
        out.push(rust.sqrt_ratio_hint);
        out
    }

    fn cairo_deserialize(
        felts: &[Felt],
        offset: usize,
    ) -> cainome::cairo_serde::Result<Self::RustType> {
        let gamma = Point::cairo_deserialize(felts, offset)?;
        Ok(Proof {
            gamma,
            c: felts[offset + 2],
            s: felts[offset + 3],
            sqrt_ratio_hint: felts[offset + 4],
        })
    }
}

/// VRF Public Key
#[derive(Clone, Debug, PartialEq)]
pub struct PublicKey {
    pub x: Felt,
    pub y: Felt,
}

impl CairoSerde for PublicKey {
    type RustType = Self;
    const SERIALIZED_SIZE: Option<usize> = Some(2);

    fn cairo_serialized_size(_rust: &Self::RustType) -> usize {
        2
    }

    fn cairo_serialize(rust: &Self::RustType) -> Vec<Felt> {
        vec![rust.x, rust.y]
    }

    fn cairo_deserialize(
        felts: &[Felt],
        offset: usize,
    ) -> cainome::cairo_serde::Result<Self::RustType> {
        Ok(PublicKey {
            x: felts[offset],
            y: felts[offset + 1],
        })
    }
}

/// OutsideExecution structure for execute_from_outside_v2
#[derive(Clone, Debug, PartialEq)]
pub struct OutsideExecution {
    pub caller: cainome::cairo_serde::ContractAddress,
    pub nonce: Felt,
    pub execute_after: u64,
    pub execute_before: u64,
    pub calls: Vec<Call>,
}

impl CairoSerde for OutsideExecution {
    type RustType = Self;
    const SERIALIZED_SIZE: Option<usize> = None;

    fn cairo_serialized_size(rust: &Self::RustType) -> usize {
        let mut size = 0;
        size += cainome::cairo_serde::ContractAddress::cairo_serialized_size(&rust.caller);
        size += 1; // nonce
        size += 1; // execute_after
        size += 1; // execute_before
        size += Vec::<Call>::cairo_serialized_size(&rust.calls);
        size
    }

    fn cairo_serialize(rust: &Self::RustType) -> Vec<Felt> {
        let mut out = cainome::cairo_serde::ContractAddress::cairo_serialize(&rust.caller);
        out.push(rust.nonce);
        out.push(Felt::from(rust.execute_after));
        out.push(Felt::from(rust.execute_before));
        out.extend(Vec::<Call>::cairo_serialize(&rust.calls));
        out
    }

    fn cairo_deserialize(
        felts: &[Felt],
        offset: usize,
    ) -> cainome::cairo_serde::Result<Self::RustType> {
        let mut offset = offset;
        let caller = cainome::cairo_serde::ContractAddress::cairo_deserialize(felts, offset)?;
        offset += cainome::cairo_serde::ContractAddress::cairo_serialized_size(&caller);
        let nonce = felts[offset];
        offset += 1;
        let execute_after: u64 = felts[offset].try_into().unwrap();
        offset += 1;
        let execute_before: u64 = felts[offset].try_into().unwrap();
        offset += 1;
        let calls = Vec::<Call>::cairo_deserialize(felts, offset)?;
        Ok(OutsideExecution {
            caller,
            nonce,
            execute_after,
            execute_before,
            calls,
        })
    }
}

/// Call structure
#[derive(Clone, Debug, PartialEq)]
pub struct Call {
    pub to: cainome::cairo_serde::ContractAddress,
    pub selector: Felt,
    pub calldata: Vec<Felt>,
}

impl CairoSerde for Call {
    type RustType = Self;
    const SERIALIZED_SIZE: Option<usize> = None;

    fn cairo_serialized_size(rust: &Self::RustType) -> usize {
        let mut size = 0;
        size += cainome::cairo_serde::ContractAddress::cairo_serialized_size(&rust.to);
        size += 1; // selector
        size += 1 + rust.calldata.len(); // length + calldata elements
        size
    }

    fn cairo_serialize(rust: &Self::RustType) -> Vec<Felt> {
        let mut out = cainome::cairo_serde::ContractAddress::cairo_serialize(&rust.to);
        out.push(rust.selector);
        out.push(Felt::from(rust.calldata.len()));
        out.extend(&rust.calldata);
        out
    }

    fn cairo_deserialize(
        felts: &[Felt],
        offset: usize,
    ) -> cainome::cairo_serde::Result<Self::RustType> {
        let mut offset = offset;
        let to = cainome::cairo_serde::ContractAddress::cairo_deserialize(felts, offset)?;
        offset += cainome::cairo_serde::ContractAddress::cairo_serialized_size(&to);
        let selector = felts[offset];
        offset += 1;
        let len: usize = felts[offset].try_into().unwrap();
        offset += 1;
        let calldata: Vec<Felt> = felts[offset..offset + len].to_vec();
        Ok(Call {
            to,
            selector,
            calldata,
        })
    }
}

// =============================================================================
// SNIP-9 / SNIP-12 Hash implementations for outside execution signing
// =============================================================================

/// Starknet domain for typed data hashing
#[derive(Clone, Debug, PartialEq)]
pub struct StarknetDomain {
    pub name: Felt,
    pub version: Felt,
    pub chain_id: Felt,
    pub revision: Felt,
}

impl StarknetDomain {
    // OpenZeppelin's domain type hash: 0x1ff2f602e42168014d405a94f75e8a93d640751d71d16311266e140d8b0a210
    const TYPE_HASH_REV_1: Felt = selector!(
        "\"StarknetDomain\"(\"name\":\"shortstring\",\"version\":\"shortstring\",\"chainId\":\"shortstring\",\"revision\":\"shortstring\")"
    );

    pub fn get_struct_hash(&self) -> Felt {
        poseidon_hash_many(&[
            Self::TYPE_HASH_REV_1,
            self.name,
            self.version,
            self.chain_id,
            self.revision,
        ])
    }
}

impl Call {
    // OpenZeppelin's type hash: 0x3635c7f2a7ba93844c0d064e18e487f35ab90f7c39d00f186a781fc3f0c2ca9
    const TYPE_HASH_REV_1: Felt = selector!(
        "\"Call\"(\"To\":\"ContractAddress\",\"Selector\":\"selector\",\"Calldata\":\"felt*\")"
    );

    /// Compute the struct hash for this call (SNIP-12 rev1)
    pub fn get_struct_hash(&self) -> Felt {
        poseidon_hash_many(&[
            Self::TYPE_HASH_REV_1,
            self.to.0,
            self.selector,
            poseidon_hash_many(&self.calldata),
        ])
    }
}

impl OutsideExecution {
    // OpenZeppelin's type hash: 0x312b56c05a7965066ddbda31c016d8d05afc305071c0ca3cdc2192c3c2f1f0f
    const TYPE_HASH_REV_1: Felt = selector!(
        "\"OutsideExecution\"(\"Caller\":\"ContractAddress\",\"Nonce\":\"felt\",\"Execute After\":\"u128\",\"Execute Before\":\"u128\",\"Calls\":\"Call*\")\"Call\"(\"To\":\"ContractAddress\",\"Selector\":\"selector\",\"Calldata\":\"felt*\")"
    );

    /// Compute the struct hash for this outside execution (SNIP-12 rev1)
    pub fn get_struct_hash(&self) -> Felt {
        let hashed_calls: Vec<Felt> = self.calls.iter().map(|c| c.get_struct_hash()).collect();
        poseidon_hash_many(&[
            Self::TYPE_HASH_REV_1,
            self.caller.0,
            self.nonce,
            Felt::from(self.execute_after),
            Felt::from(self.execute_before),
            poseidon_hash_many(&hashed_calls),
        ])
    }

    /// Compute the message hash for signing (SNIP-9 v2)
    ///
    /// This follows the SNIP-9 standard for execute_from_outside_v2:
    /// - Domain name: "Account.execute_from_outside"
    /// - Domain version: 2
    /// - Revision: 1
    pub fn get_message_hash(&self, chain_id: Felt, account_address: Felt) -> Felt {
        let domain = StarknetDomain {
            name: short_string!("Account.execute_from_outside"),
            version: Felt::TWO,
            chain_id,
            revision: Felt::ONE,
        };

        poseidon_hash_many(&[
            short_string!("StarkNet Message"),
            domain.get_struct_hash(),
            account_address,
            self.get_struct_hash(),
        ])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use starknet::macros::felt;

    #[test]
    fn test_type_hashes_match_openzeppelin() {
        // Verify our type hashes match OpenZeppelin's
        let oz_outside_execution_hash =
            felt!("0x312b56c05a7965066ddbda31c016d8d05afc305071c0ca3cdc2192c3c2f1f0f");
        let oz_call_hash =
            felt!("0x3635c7f2a7ba93844c0d064e18e487f35ab90f7c39d00f186a781fc3f0c2ca9");
        let oz_domain_hash =
            felt!("0x1ff2f602e42168014d405a94f75e8a93d640751d71d16311266e140d8b0a210");

        println!(
            "Our OutsideExecution TYPE_HASH: {:?}",
            OutsideExecution::TYPE_HASH_REV_1
        );
        println!(
            "OZ OutsideExecution TYPE_HASH:  {:?}",
            oz_outside_execution_hash
        );
        println!("Our Call TYPE_HASH: {:?}", Call::TYPE_HASH_REV_1);
        println!("OZ Call TYPE_HASH:  {:?}", oz_call_hash);
        println!(
            "Our StarknetDomain TYPE_HASH: {:?}",
            StarknetDomain::TYPE_HASH_REV_1
        );
        println!("OZ StarknetDomain TYPE_HASH:  {:?}", oz_domain_hash);

        assert_eq!(
            OutsideExecution::TYPE_HASH_REV_1,
            oz_outside_execution_hash,
            "OutsideExecution type hash mismatch"
        );
        assert_eq!(
            Call::TYPE_HASH_REV_1,
            oz_call_hash,
            "Call type hash mismatch"
        );
        assert_eq!(
            StarknetDomain::TYPE_HASH_REV_1,
            oz_domain_hash,
            "StarknetDomain type hash mismatch"
        );
    }
}
