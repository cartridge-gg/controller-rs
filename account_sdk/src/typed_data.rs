use crate::signers::SignError as Error;
use starknet::core::types::typed_data::{
    InlineTypeReference, TypeDefinition, TypedDataError, Value,
};
use starknet::core::types::{Felt, TypedData};

/// Breakdown of components that make up a typed message hash.
#[derive(Debug, Clone)]
pub struct TypedDataHashComponents {
    /// Hash of the `domain_separator` component.
    pub domain_separator_hash: Felt,
    /// Primary type hash.
    pub type_hash: Felt,
    /// Hash of the `message` component.
    pub message_hash: Felt,
    /// Encoded object fields.
    pub encoded_fields: Vec<Felt>,
}

/// Helper function to individually hash parts of a SNIP-12 message to obtain the hash components
/// needed for `TypedData` session policies.
pub fn hash_components(data: &TypedData) -> Result<TypedDataHashComponents, Error> {
    // SNIP-12 is ambiguous about whether non-struct types are allowed to be the primary type.
    // `starknet-rs` allows them but here in controller we restrict it to only be structs.
    let InlineTypeReference::Custom(primary_type_name) = data.primary_type() else {
        return Err(Error::InvalidMessageError("Unexpected primary type".into()));
    };
    let Value::Object(primary_type_value) = data.message() else {
        return Err(Error::InvalidMessageError(
            "Unexpected message value type".into(),
        ));
    };

    let primary_type_hash = data.encoder().types().get_type_hash(primary_type_name)?;

    // Again, controller only allows struct defs.
    //
    // Safe to unwrap as `get_type_hash` already succeeded.
    let TypeDefinition::Struct(primary_type_def) =
        data.encoder().types().get_type(primary_type_name).unwrap()
    else {
        return Err(Error::InvalidMessageError(
            "Enums not allowed as primary type".into(),
        ));
    };

    // This is the hash for the SNIP-12 `message` field. Not to be confused with the final full
    // SNIP-12 hash (from `starknet-rs`'s `.message_hash()` method).
    let message_hash = data
        .encoder()
        .encode_value(data.primary_type(), data.message())?;

    let domain_hash = data.encoder().domain().encoded_hash();

    Ok(TypedDataHashComponents {
        domain_separator_hash: domain_hash,
        type_hash: primary_type_hash,
        message_hash,
        encoded_fields: data
            .encoder()
            .encode_composite_fields(primary_type_def, primary_type_value)?
            .collect::<Result<Vec<Felt>, TypedDataError>>()?,
    })
}
