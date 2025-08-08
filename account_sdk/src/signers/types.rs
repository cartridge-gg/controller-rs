use crate::graphql::{
    owner::{add_owner, remove_owner},
    registration::register::register,
};

pub enum SignerType {
    Starknet,
    StarknetAccount,
    Eip191,
    Webauthn,
    Siws,
    Secp256k1,
    Secp256r1,
    Other(String),
}

impl From<SignerType> for register::SignerType {
    fn from(signer_type: SignerType) -> Self {
        match signer_type {
            SignerType::Starknet => register::SignerType::starknet,
            SignerType::StarknetAccount => register::SignerType::starknet_account,
            SignerType::Eip191 => register::SignerType::eip191,
            SignerType::Webauthn => register::SignerType::webauthn,
            SignerType::Siws => register::SignerType::siws,
            SignerType::Secp256k1 => register::SignerType::secp256k1,
            SignerType::Secp256r1 => register::SignerType::secp256r1,
            SignerType::Other(s) => register::SignerType::Other(s),
        }
    }
}

impl From<SignerType> for add_owner::SignerType {
    fn from(signer_type: SignerType) -> Self {
        match signer_type {
            SignerType::Starknet => add_owner::SignerType::starknet,
            SignerType::StarknetAccount => add_owner::SignerType::starknet_account,
            SignerType::Eip191 => add_owner::SignerType::eip191,
            SignerType::Webauthn => add_owner::SignerType::webauthn,
            SignerType::Siws => add_owner::SignerType::siws,
            SignerType::Secp256k1 => add_owner::SignerType::secp256k1,
            SignerType::Secp256r1 => add_owner::SignerType::secp256r1,
            SignerType::Other(s) => add_owner::SignerType::Other(s),
        }
    }
}

impl From<SignerType> for remove_owner::SignerType {
    fn from(signer_type: SignerType) -> Self {
        match signer_type {
            SignerType::Starknet => remove_owner::SignerType::starknet,
            SignerType::StarknetAccount => remove_owner::SignerType::starknet_account,
            SignerType::Eip191 => remove_owner::SignerType::eip191,
            SignerType::Webauthn => remove_owner::SignerType::webauthn,
            SignerType::Siws => remove_owner::SignerType::siws,
            SignerType::Secp256k1 => remove_owner::SignerType::secp256k1,
            SignerType::Secp256r1 => remove_owner::SignerType::secp256r1,
            SignerType::Other(s) => remove_owner::SignerType::Other(s),
        }
    }
}
