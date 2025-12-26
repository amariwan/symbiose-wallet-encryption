//! # Symbiose Wallet Encryption
//!
//! A secure, production-ready Rust library for password-based encryption of Solana wallet private keys.
//!
//! ## Features
//!
//! - **AEAD Encryption**: XChaCha20-Poly1305 for authenticated encryption
//! - **Strong KDF**: Argon2id for password-to-key derivation
//! - **Memory Safety**: Automatic zeroization of sensitive data
//! - **Robust Error Handling**: Clear error types with security-conscious messaging
//!
//! ## Security Guarantees
//!
//! - Each encryption generates a unique salt and nonce
//! - Sensitive data is automatically wiped from memory after use
//! - AEAD provides both confidentiality and authenticity
//! - Industry-standard cryptographic primitives via Orion
//!
//! ## Usage
//!
//! ```rust
//! use solana_sdk::signature::Keypair;
//! use symbiose_wallet_encryption::{encrypt_wallet, decrypt_wallet};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Create or load a wallet
//! let wallet = Keypair::new();
//! let password = "my-secure-password-2025!";
//!
//! // Encrypt the wallet
//! let encrypted_blob = encrypt_wallet(&wallet, password)?;
//!
//! // Decrypt the wallet
//! let decrypted_wallet = decrypt_wallet(&encrypted_blob, password)?;
//!
//! assert_eq!(wallet.to_bytes(), decrypted_wallet.to_bytes());
//! # Ok(())
//! # }
//! ```

mod bytes;
mod constants;
mod errors;
mod kdf;
mod params;
mod rng;
mod sensitive;
mod wallet;

// Re-export public API for a clean, small crate interface
pub use bytes::{
    change_password, change_password_with_params, decrypt_bytes, decrypt_bytes_with_params,
    encrypt_bytes, encrypt_bytes_with_params,
};
pub use constants::{NONCE_LEN, SALT_LEN, TAG_LEN};
pub use errors::WalletEncryptionError;
pub use params::{Argon2Params, SecurityParams};
pub use sensitive::SensitiveData;
pub use wallet::{
    decrypt_wallet, decrypt_wallet_with_params, encrypt_wallet, encrypt_wallet_with_params,
};

#[cfg(test)]
mod tests {
    use super::*;
    use solana_sdk::signature::Keypair;
    use solana_sdk::signature::Signer;

    #[test]
    fn test_successful_encryption_and_decryption() {
        let original_wallet = Keypair::new();
        let password = "test-password-2025!";

        // Encrypt
        let encrypted =
            encrypt_wallet(&original_wallet, password).expect("Encryption should succeed");

        // Verify blob structure
        assert!(encrypted.len() > SALT_LEN + NONCE_LEN + TAG_LEN);

        // Decrypt
        let decrypted_wallet =
            decrypt_wallet(&encrypted, password).expect("Decryption should succeed");

        // Validate
        assert_eq!(
            original_wallet.to_bytes(),
            decrypted_wallet.to_bytes(),
            "Decrypted wallet must match original"
        );

        assert_eq!(
            original_wallet.pubkey(),
            decrypted_wallet.pubkey(),
            "Public keys must match"
        );
    }

    #[test]
    fn test_wrong_password_fails() {
        let wallet = Keypair::new();
        let correct_password = "correct-password";
        let wrong_password = "wrong-password";

        let encrypted =
            encrypt_wallet(&wallet, correct_password).expect("Encryption should succeed");

        let result = decrypt_wallet(&encrypted, wrong_password);

        assert!(
            matches!(result, Err(WalletEncryptionError::DecryptionFailed)),
            "Decryption with wrong password should fail with DecryptionFailed error"
        );
    }

    #[test]
    fn test_tampered_data_fails() {
        let wallet = Keypair::new();
        let password = "test-password";

        let mut encrypted = encrypt_wallet(&wallet, password).expect("Encryption should succeed");

        // Tamper with the last byte (inside the authentication tag)
        let last_idx = encrypted.len() - 1;
        encrypted[last_idx] ^= 0xFF;

        let result = decrypt_wallet(&encrypted, password);

        assert!(
            matches!(result, Err(WalletEncryptionError::DecryptionFailed)),
            "Decryption of tampered data should fail"
        );
    }

    #[test]
    fn test_corrupted_salt_fails() {
        let wallet = Keypair::new();
        let password = "test-password";

        let mut encrypted = encrypt_wallet(&wallet, password).expect("Encryption should succeed");

        // Corrupt the salt (first byte)
        encrypted[0] ^= 0xFF;

        let result = decrypt_wallet(&encrypted, password);

        // Should fail because derived key will be different
        assert!(
            matches!(result, Err(WalletEncryptionError::DecryptionFailed)),
            "Decryption with corrupted salt should fail"
        );
    }

    #[test]
    fn test_too_short_data_fails() {
        let password = "test-password";
        let short_data = vec![0u8; 50]; // Too short to be valid

        let result = decrypt_wallet(&short_data, password);

        assert!(
            matches!(result, Err(WalletEncryptionError::InvalidDataFormat)),
            "Too short data should fail with InvalidDataFormat"
        );
    }

    #[test]
    fn test_empty_data_fails() {
        let password = "test-password";
        let empty_data: Vec<u8> = vec![];

        let result = decrypt_wallet(&empty_data, password);

        assert!(
            matches!(result, Err(WalletEncryptionError::InvalidDataFormat)),
            "Empty data should fail with InvalidDataFormat"
        );
    }

    #[test]
    fn test_unique_salts_and_nonces() {
        let wallet = Keypair::new();
        let password = "same-password";

        // Encrypt the same wallet twice with the same password
        let encrypted1 = encrypt_wallet(&wallet, password).expect("Encryption 1 should succeed");
        let encrypted2 = encrypt_wallet(&wallet, password).expect("Encryption 2 should succeed");

        // The encrypted blobs should be different due to unique salt/nonce
        assert_ne!(
            encrypted1, encrypted2,
            "Two encryptions with same password should produce different blobs"
        );

        // But both should decrypt to the same wallet
        let decrypted1 =
            decrypt_wallet(&encrypted1, password).expect("Decryption 1 should succeed");
        let decrypted2 =
            decrypt_wallet(&encrypted2, password).expect("Decryption 2 should succeed");

        assert_eq!(decrypted1.to_bytes(), decrypted2.to_bytes());
    }

    #[test]
    fn test_different_passwords_produce_different_ciphertexts() {
        let wallet = Keypair::new();
        let password1 = "password-one";
        let password2 = "password-two";

        let encrypted1 = encrypt_wallet(&wallet, password1).expect("Encryption 1 should succeed");
        let encrypted2 = encrypt_wallet(&wallet, password2).expect("Encryption 2 should succeed");

        assert_ne!(encrypted1, encrypted2);

        // Each should only decrypt with its own password
        assert!(decrypt_wallet(&encrypted1, password1).is_ok());
        assert!(decrypt_wallet(&encrypted2, password2).is_ok());
        assert!(decrypt_wallet(&encrypted1, password2).is_err());
        assert!(decrypt_wallet(&encrypted2, password1).is_err());
    }

    #[test]
    fn test_custom_kdf_params_roundtrip() {
        let wallet = Keypair::new();
        let password = "custom-kdf";
        let params = Argon2Params {
            iterations: 3,
            memory_kib: 8_192,
        };

        let encrypted = encrypt_wallet_with_params(&wallet, password, params)
            .expect("Encryption with custom KDF params should succeed");
        let decrypted = decrypt_wallet_with_params(&encrypted, password, params)
            .expect("Decryption with matching KDF params should succeed");

        assert_eq!(wallet.to_bytes(), decrypted.to_bytes());
    }
}
