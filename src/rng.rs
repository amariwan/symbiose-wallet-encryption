use getrandom::getrandom;
use orion::hazardous::aead::xchacha20poly1305::Nonce;
use orion::kdf::Salt;

use crate::constants::{NONCE_LEN, SALT_LEN};
use crate::errors::WalletEncryptionError;

/// Generates a cryptographically secure random salt for key derivation
pub fn generate_salt() -> Result<Salt, WalletEncryptionError> {
    let mut salt_bytes = [0u8; SALT_LEN];
    getrandom(&mut salt_bytes).map_err(|_| WalletEncryptionError::RandomGenerationFailed)?;

    Salt::from_slice(&salt_bytes)
        .map_err(|e| WalletEncryptionError::CryptoError(format!("Salt creation failed: {}", e)))
}

/// Generates a cryptographically secure random nonce for encryption
pub fn generate_nonce() -> Result<Nonce, WalletEncryptionError> {
    let mut nonce_bytes = [0u8; NONCE_LEN];
    getrandom(&mut nonce_bytes).map_err(|_| WalletEncryptionError::RandomGenerationFailed)?;

    Nonce::from_slice(&nonce_bytes)
        .map_err(|e| WalletEncryptionError::CryptoError(format!("Nonce creation failed: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_salt_and_nonce_have_expected_size() {
        let salt = generate_salt().expect("salt generation should work");
        assert_eq!(salt.as_ref().len(), SALT_LEN);
        assert!(salt.as_ref().iter().any(|&b| b != 0));

        let nonce = generate_nonce().expect("nonce generation should work");
        assert_eq!(nonce.as_ref().len(), NONCE_LEN);
        assert!(nonce.as_ref().iter().any(|&b| b != 0));
    }
}
