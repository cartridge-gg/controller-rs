//! PBKDF2 + AES-GCM decryption for Cartridge password-encrypted private keys.
//!
//! Matches the encryption scheme in the Cartridge keychain TypeScript source:
//! `packages/keychain/src/components/connect/create/password/crypto.ts`

use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;
use starknet_types_core::felt::Felt;

const PBKDF2_ITERATIONS: u32 = 100_000;
const SALT_LEN: usize = 16;
const IV_LEN: usize = 12;
const MIN_BLOB_LEN: usize = SALT_LEN + IV_LEN + 1;

/// Errors that can occur during password-based key decryption.
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    /// The encrypted blob is not valid base64.
    #[error("invalid base64 encoding")]
    InvalidBase64(#[from] base64::DecodeError),

    /// The decoded blob is too short to contain salt + IV + ciphertext.
    #[error("encrypted blob too short: expected at least {MIN_BLOB_LEN} bytes, got {0}")]
    BlobTooShort(usize),

    /// AES-GCM decryption failed — wrong password or corrupted data.
    #[error("decryption failed — wrong password or corrupted data")]
    DecryptionFailed,

    /// The decrypted plaintext is not a valid hex felt string.
    #[error("decrypted key is not a valid hex felt: {0}")]
    InvalidKeyFormat(String),
}

/// Decrypts a Cartridge password-encrypted Starknet private key.
///
/// The `encrypted_base64` blob is formatted as `base64(salt[16] || iv[12] || ciphertext)`,
/// matching the web SDK's `encryptPrivateKey()` output.
pub fn decrypt_password_key(encrypted_base64: &str, password: &str) -> Result<Felt, CryptoError> {
    let blob = BASE64.decode(encrypted_base64)?;

    if blob.len() < MIN_BLOB_LEN {
        return Err(CryptoError::BlobTooShort(blob.len()));
    }

    let salt = &blob[..SALT_LEN];
    let iv = &blob[SALT_LEN..SALT_LEN + IV_LEN];
    let ciphertext = &blob[SALT_LEN + IV_LEN..];

    // Derive 256-bit key using PBKDF2-HMAC-SHA256
    let mut derived_key = [0u8; 32];
    pbkdf2_hmac::<Sha256>(
        password.as_bytes(),
        salt,
        PBKDF2_ITERATIONS,
        &mut derived_key,
    );

    // Decrypt with AES-256-GCM
    let cipher =
        Aes256Gcm::new_from_slice(&derived_key).map_err(|_| CryptoError::DecryptionFailed)?;
    let nonce = Nonce::from_slice(iv);
    let plaintext_bytes = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| CryptoError::DecryptionFailed)?;

    // Parse the decrypted hex string as a Felt
    let hex_str = std::str::from_utf8(&plaintext_bytes)
        .map_err(|e| CryptoError::InvalidKeyFormat(e.to_string()))?;

    Felt::from_hex(hex_str).map_err(|e| CryptoError::InvalidKeyFormat(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_ENCRYPTED_BASE64: &str = "AQEBAQEBAQEBAQEBAQEBAQICAgICAgICAgICApxEkNk3u6LMe2VYB74hEX4dZWT5sP91MdeQqiRH4RC6ZF1zD//Tgg2bhZEfeTwZA2tTM3MHeheo0uFnI6Ig7jlSDXYjpB331dT+BT+0Ral9THo=";
    const TEST_PASSWORD: &str = "test-password-123";
    const TEST_PRIVATE_KEY: &str =
        "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn decrypt_should_return_correct_key_for_valid_password() {
        let result = decrypt_password_key(TEST_ENCRYPTED_BASE64, TEST_PASSWORD);
        let expected = Felt::from_hex(TEST_PRIVATE_KEY).unwrap();
        assert_eq!(result.unwrap(), expected);
    }

    #[test]
    fn decrypt_should_fail_when_password_is_wrong() {
        let result = decrypt_password_key(TEST_ENCRYPTED_BASE64, "wrong-password");
        assert!(matches!(result, Err(CryptoError::DecryptionFailed)));
    }

    #[test]
    fn decrypt_should_fail_for_invalid_base64() {
        let result = decrypt_password_key("not-valid-base64!!!", TEST_PASSWORD);
        assert!(matches!(result, Err(CryptoError::InvalidBase64(_))));
    }

    #[test]
    fn decrypt_should_fail_for_blob_too_short() {
        let short_blob = BASE64.encode([0u8; 20]);
        let result = decrypt_password_key(&short_blob, TEST_PASSWORD);
        assert!(matches!(result, Err(CryptoError::BlobTooShort(20))));
    }
}
