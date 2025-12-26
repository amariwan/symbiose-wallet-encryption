use solana_sdk::signature::Keypair;
use std::convert::TryFrom;

use crate::bytes::{decrypt_bytes_with_params, encrypt_bytes_with_params};
use crate::errors::WalletEncryptionError;
use crate::params::{Argon2Params, SecurityParams};

/// Encrypts a Solana wallet keypair using password-based AEAD encryption
pub fn encrypt_wallet(wallet: &Keypair, password: &str) -> Result<Vec<u8>, WalletEncryptionError> {
    encrypt_wallet_with_params(wallet, password, Argon2Params::default())
}

/// Encrypts a Solana wallet keypair using password-based AEAD encryption with custom Argon2 parameters.
pub fn encrypt_wallet_with_params(
    wallet: &Keypair,
    password: &str,
    params: Argon2Params,
) -> Result<Vec<u8>, WalletEncryptionError> {
    let keypair_bytes = wallet.to_bytes();
    encrypt_bytes_with_params(keypair_bytes, password, SecurityParams::from(params))
}

/// Decrypts an encrypted wallet blob back into a Solana keypair
pub fn decrypt_wallet(
    encrypted_data: &[u8],
    password: &str,
) -> Result<Keypair, WalletEncryptionError> {
    decrypt_wallet_with_params(encrypted_data, password, Argon2Params::default())
}

/// Decrypts an encrypted wallet blob back into a Solana keypair using custom Argon2 parameters.
pub fn decrypt_wallet_with_params(
    encrypted_data: &[u8],
    password: &str,
    params: Argon2Params,
) -> Result<Keypair, WalletEncryptionError> {
    let bytes = decrypt_bytes_with_params(encrypted_data, password, SecurityParams::from(params))?;
    let keypair = Keypair::try_from(bytes.as_bytes())
        .map_err(|_| WalletEncryptionError::KeypairRestorationFailed)?;
    Ok(keypair)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::errors::WalletEncryptionError;
    use solana_sdk::signature::Signer;

    #[test]
    fn wallet_roundtrip_with_custom_params() {
        let wallet = Keypair::new();
        let password = "wallet-roundtrip";
        let params = Argon2Params::default();

        let encrypted =
            encrypt_wallet_with_params(&wallet, password, params).expect("encryption should work");
        let decrypted = decrypt_wallet_with_params(&encrypted, password, params)
            .expect("decryption should work");

        assert_eq!(wallet.pubkey(), decrypted.pubkey());
        assert_eq!(wallet.to_bytes(), decrypted.to_bytes());
    }

    #[test]
    fn short_data_is_rejected() {
        let short_data = vec![0u8; 8];
        let result = decrypt_wallet(&short_data, "password");

        assert!(matches!(
            result,
            Err(WalletEncryptionError::InvalidDataFormat)
        ));
    }
}
