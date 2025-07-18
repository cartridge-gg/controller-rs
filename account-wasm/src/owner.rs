use account_sdk::{graphql::owner::add_owner::SignerInput, signers::Signer};

use crate::{account::CartridgeAccount, errors::JsControllerError, utils::set_panic_hook};

impl CartridgeAccount {
    pub async fn handle_passkey_creation(
        &self,
        rp_id: String,
    ) -> std::result::Result<(Signer, SignerInput), JsControllerError> {
        set_panic_hook();

        let mut controller = self.controller.lock().await;
        let (signer, signer_input) = controller.create_passkey(rp_id, true).await?;
        Ok((signer, signer_input))
    }
}
