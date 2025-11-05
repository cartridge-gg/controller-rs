use starknet_crypto::Felt;

pub struct Selectors;

impl Selectors {
    pub fn active(app_id: &str) -> String {
        format!("@cartridge/{app_id}/active")
    }

    pub fn account(address: &Felt, chain_id: &Felt) -> String {
        format!("@cartridge/account/0x{address:x}/0x{chain_id:x}")
    }

    pub fn deployment(address: &Felt, chain_id: &Felt) -> String {
        format!("@cartridge/deployment/0x{address:x}/0x{chain_id:x}")
    }

    pub fn admin(address: &Felt, origin: &str) -> String {
        format!(
            "@cartridge/admin/0x{:x}/{}",
            address,
            urlencoding::encode(origin)
        )
    }

    pub fn session(address: &Felt, app_id: &str, chain_id: &Felt) -> String {
        format!(
            "@cartridge/session/0x{:x}/{}/0x{:x}",
            address,
            urlencoding::encode(app_id),
            chain_id
        )
    }

    /// Storage key for multi-chain controller configuration
    pub fn multi_chain_config(app_id: &str) -> String {
        format!("@cartridge/multi_chain/{app_id}/config")
    }
}
