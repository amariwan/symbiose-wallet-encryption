use thiserror::Error;

/// Custom error types for wallet encryption/decryption operations
#[derive(Error, Debug)]
pub enum WalletEncryptionError {
    #[error("Failed to generate cryptographically secure random bytes")]
    RandomGenerationFailed,

    #[error("Invalid password or corrupted data")]
    DecryptionFailed,

    #[error("Encrypted data is too short or malformed")]
    InvalidDataFormat,

    #[error("Failed to derive encryption key from password")]
    KeyDerivationFailed,

    #[error("Failed to restore Solana keypair from decrypted data")]
    KeypairRestorationFailed,

    #[error("Internal cryptographic error: {0}")]
    CryptoError(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_messages_are_human_readable() {
        assert_eq!(
            WalletEncryptionError::RandomGenerationFailed.to_string(),
            "Failed to generate cryptographically secure random bytes"
        );

        let crypto_err = WalletEncryptionError::CryptoError("boom".into());
        assert!(crypto_err.to_string().contains("boom"));
    }
}
