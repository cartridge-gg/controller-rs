use starknet::core::{types::InvokeTransactionResult, utils::parse_cairo_short_string};
use starknet_crypto::Felt;

use crate::{
    controller::Controller,
    errors::ControllerError,
    execute_from_outside::FeeSource,
    signers::{NewOwnerSigner, Owner, Signer},
};

impl Controller {
    pub async fn add_owner(
        &mut self,
        signer: Signer,
    ) -> Result<InvokeTransactionResult, ControllerError> {
        let new_owner = Owner::Signer(signer.clone());
        let signature = new_owner
            .sign_new_owner(&self.chain_id, &self.address)
            .await?;

        let call = self
            .contract()
            .add_owner_getcall(&signer.into(), &signature);

        self.execute_from_outside_v3(vec![call], Some(FeeSource::Paymaster))
            .await
    }

    pub async fn add_owner_with_cartridge(
        &mut self,
        signer: crate::graphql::owner::add_owner::SignerInput,
        signer_guid: Felt,
        cartridge_api_url: String,
    ) -> Result<(), ControllerError> {
        let input = crate::graphql::owner::AddOwnerInput {
            username: self.username.clone(),
            chain_id: parse_cairo_short_string(&self.chain_id).unwrap(),
            signer_guid,
            owner: signer,
        };

        let _ = crate::graphql::owner::add_owner(input, cartridge_api_url).await?;

        Ok(())
    }
}
