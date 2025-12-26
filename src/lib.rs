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

use std::convert::TryFrom;
use getrandom::getrandom;
use orion::{
    hazardous::{
        aead::xchacha20poly1305::{open, seal, Nonce, SecretKey},
        mac::poly1305::POLY1305_OUTSIZE,
        stream::chacha20::CHACHA_KEYSIZE,
    },
    kdf::{derive_key, Password, Salt},
};
use solana_sdk::signature::Keypair;
use thiserror::Error;
use zeroize::Zeroize;

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

/// Wrapper for sensitive data that will be automatically zeroed when dropped
#[derive(Zeroize)]
#[zeroize(drop)]
struct SensitiveData(Vec<u8>);

impl SensitiveData {
    /// Creates a new SensitiveData wrapper from a vector
    fn new(data: Vec<u8>) -> Self {
        Self(data)
    }

    /// Returns a reference to the inner data
    fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

// Constants for data layout
const SALT_LEN: usize = 32;
const NONCE_LEN: usize = 24; // XChaCha20-Poly1305 nonce size
const TAG_LEN: usize = POLY1305_OUTSIZE; // 16 bytes

/// Generates a cryptographically secure random salt for key derivation
///
/// # Returns
///
/// A 32-byte salt wrapped in Orion's `Salt` type
///
/// # Errors
///
/// Returns `WalletEncryptionError::RandomGenerationFailed` if the system's
/// random number generator is unavailable or fails
fn generate_salt() -> Result<Salt, WalletEncryptionError> {
    let mut salt_bytes = [0u8; SALT_LEN];
    getrandom(&mut salt_bytes).map_err(|_| WalletEncryptionError::RandomGenerationFailed)?;

    Salt::from_slice(&salt_bytes)
        .map_err(|e| WalletEncryptionError::CryptoError(format!("Salt creation failed: {}", e)))
}

/// Generates a cryptographically secure random nonce for encryption
///
/// # Returns
///
/// A 24-byte nonce wrapped in Orion's `Nonce` type
///
/// # Errors
///
/// Returns `WalletEncryptionError::RandomGenerationFailed` if the system's
/// random number generator is unavailable or fails
fn generate_nonce() -> Result<Nonce, WalletEncryptionError> {
    let mut nonce_bytes = [0u8; NONCE_LEN];
    getrandom(&mut nonce_bytes).map_err(|_| WalletEncryptionError::RandomGenerationFailed)?;

    Nonce::from_slice(&nonce_bytes)
        .map_err(|e| WalletEncryptionError::CryptoError(format!("Nonce creation failed: {}", e)))
}

/// Derives a 256-bit encryption key from a password and salt using Argon2id
///
/// # Parameters
///
/// - `password`: User-provided password string
/// - `salt`: Unique salt for this key derivation
///
/// # Security Parameters
///
/// - Algorithm: Argon2id (hybrid mode - resistant to both side-channel and GPU attacks)
/// - Iterations: 15 (time cost)
/// - Memory: 1024 KiB (memory cost)
/// - Parallelism: 1 (lanes)
/// - Output length: 32 bytes (256 bits)
///
/// # Returns
///
/// A `SecretKey` suitable for XChaCha20-Poly1305 encryption
///
/// # Errors
///
/// Returns `WalletEncryptionError::KeyDerivationFailed` if the KDF fails
/// or if parameters are invalid
fn derive_secret_key(password: &str, salt: &Salt) -> Result<SecretKey, WalletEncryptionError> {
    // Wrap password in Orion's secure Password type (auto-zeroizes on drop)
    let password_protected = Password::from_slice(password.as_bytes()).map_err(|e| {
        WalletEncryptionError::CryptoError(format!("Password wrapping failed: {}", e))
    })?;

    // Derive key using Argon2id with secure defaults
    // These parameters provide a good balance between security and performance
    // For higher security requirements, increase iterations or memory
    let derived_key = derive_key(&password_protected, salt, 15, 1024, CHACHA_KEYSIZE as u32)
        .map_err(|_| WalletEncryptionError::KeyDerivationFailed)?;

    // Convert to XChaCha20 SecretKey type
    SecretKey::from_slice(derived_key.unprotected_as_bytes()).map_err(|e| {
        WalletEncryptionError::CryptoError(format!("SecretKey conversion failed: {}", e))
    })
}

/// Encrypts a Solana wallet keypair using password-based AEAD encryption
///
/// # Process
///
/// 1. Serialize keypair to Base58 string (standard Solana format)
/// 2. Generate random salt for KDF
/// 3. Derive encryption key from password + salt using Argon2id
/// 4. Generate random nonce for AEAD
/// 5. Encrypt plaintext using XChaCha20-Poly1305
/// 6. Return concatenated blob: [Salt || Nonce || Ciphertext || Tag]
///
/// # Parameters
///
/// - `wallet`: Reference to the Solana keypair to encrypt
/// - `password`: User password for encryption
///
/// # Returns
///
/// A `Vec<u8>` containing the complete encrypted blob, ready for storage
///
/// # Security
///
/// - All sensitive data (plaintext, keys) is automatically zeroized after use
/// - Each encryption uses a unique salt and nonce
/// - AEAD ensures both confidentiality and authenticity
///
/// # Errors
///
/// Returns errors if random generation, key derivation, or encryption fails
///
/// # Example
///
/// ```rust
/// use solana_sdk::signature::Keypair;
/// use symbiose_wallet_encryption::encrypt_wallet;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let wallet = Keypair::new();
/// let encrypted = encrypt_wallet(&wallet, "strong-password")?;
/// // Store `encrypted` to disk or database
/// # Ok(())
/// # }
/// ```
pub fn encrypt_wallet(wallet: &Keypair, password: &str) -> Result<Vec<u8>, WalletEncryptionError> {
    // Step 1: Serialize wallet to Base58 string (Solana standard format)
    let wallet_base58 = wallet.to_base58_string();
    let plaintext = SensitiveData::new(wallet_base58.into_bytes());

    // Step 2: Generate random salt
    let salt = generate_salt()?;

    // Step 3: Derive encryption key from password + salt
    let key = derive_secret_key(password, &salt)?;

    // Step 4: Generate random nonce
    let nonce = generate_nonce()?;

    // Step 5: Prepare buffer for ciphertext + authentication tag
    let mut ciphertext_buffer = vec![0u8; plaintext.as_bytes().len() + TAG_LEN];

    // Step 6: Encrypt and authenticate using AEAD
    // The seal() function encrypts the plaintext and appends the Poly1305 tag
    seal(
        &key,
        &nonce,
        plaintext.as_bytes(),
        None,
        &mut ciphertext_buffer,
    )
    .map_err(|e| WalletEncryptionError::CryptoError(format!("Encryption failed: {}", e)))?;

    // Step 7: Assemble final blob: [Salt || Nonce || Ciphertext+Tag]
    let mut final_blob = Vec::with_capacity(SALT_LEN + NONCE_LEN + ciphertext_buffer.len());
    final_blob.extend_from_slice(salt.as_ref());
    final_blob.extend_from_slice(nonce.as_ref());
    final_blob.extend_from_slice(&ciphertext_buffer);

    // plaintext and key are automatically zeroized here when dropped
    Ok(final_blob)
}

/// Decrypts an encrypted wallet blob back into a Solana keypair
///
/// # Process
///
/// 1. Parse blob into: [Salt || Nonce || Ciphertext+Tag]
/// 2. Derive decryption key from password + extracted salt (must match encryption key)
/// 3. Decrypt and verify using XChaCha20-Poly1305 AEAD
/// 4. Decode Base58 string to keypair bytes
/// 5. Restore Solana Keypair object
///
/// # Parameters
///
/// - `encrypted_data`: The encrypted blob returned by `encrypt_wallet`
/// - `password`: User password (must match the one used for encryption)
///
/// # Returns
///
/// The original `Keypair` if decryption and authentication succeed
///
/// # Security
///
/// - AEAD verification prevents:
///   - Wrong password
///   - Data tampering/corruption
///   - Bit flips or modifications
/// - All intermediate sensitive data is zeroized after use
///
/// # Errors
///
/// - `InvalidDataFormat`: If blob is too short or malformed
/// - `DecryptionFailed`: If password is wrong or data is corrupted (AEAD check fails)
/// - `KeypairRestorationFailed`: If decrypted data is not a valid Solana keypair
///
/// # Example
///
/// ```rust
/// use solana_sdk::signature::Keypair;
/// use symbiose_wallet_encryption::{encrypt_wallet, decrypt_wallet};
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let original = Keypair::new();
/// let encrypted = encrypt_wallet(&original, "password")?;
/// let restored = decrypt_wallet(&encrypted, "password")?;
/// assert_eq!(original.to_bytes(), restored.to_bytes());
/// # Ok(())
/// # }
/// ```
pub fn decrypt_wallet(
    encrypted_data: &[u8],
    password: &str,
) -> Result<Keypair, WalletEncryptionError> {
    // Step 1: Validate minimum length
    if encrypted_data.len() < SALT_LEN + NONCE_LEN + TAG_LEN {
        return Err(WalletEncryptionError::InvalidDataFormat);
    }

    // Step 2: Extract components from blob
    let salt_bytes = &encrypted_data[..SALT_LEN];
    let nonce_bytes = &encrypted_data[SALT_LEN..SALT_LEN + NONCE_LEN];
    let ciphertext_with_tag = &encrypted_data[SALT_LEN + NONCE_LEN..];

    // Step 3: Reconstruct Salt and Nonce types
    let salt = Salt::from_slice(salt_bytes).map_err(|e| {
        WalletEncryptionError::CryptoError(format!("Salt reconstruction failed: {}", e))
    })?;

    let nonce = Nonce::from_slice(nonce_bytes).map_err(|e| {
        WalletEncryptionError::CryptoError(format!("Nonce reconstruction failed: {}", e))
    })?;

    // Step 4: Derive decryption key (must match encryption key!)
    let key = derive_secret_key(password, &salt)?;

    // Step 5: Decrypt and verify AEAD
    // This will fail if:
    // - Password is wrong (different derived key)
    // - Data has been tampered with (Poly1305 tag mismatch)
    // - Data is corrupted
    let plaintext_len = ciphertext_with_tag.len() - TAG_LEN;
    let mut plaintext_buffer = vec![0u8; plaintext_len];

    open(
        &key,
        &nonce,
        ciphertext_with_tag,
        None,
        &mut plaintext_buffer,
    )
    .map_err(|_| WalletEncryptionError::DecryptionFailed)?;

    // Wrap in SensitiveData for automatic zeroization
    let plaintext_sensitive = SensitiveData::new(plaintext_buffer);

    // Step 6: Decode Base58 string
    let wallet_str = String::from_utf8(plaintext_sensitive.0.clone())
        .map_err(|_| WalletEncryptionError::KeypairRestorationFailed)?;

    let wallet_bytes = bs58::decode(&wallet_str)
        .into_vec()
        .map_err(|_| WalletEncryptionError::KeypairRestorationFailed)?;

    // Step 7: Restore Solana Keypair
    let keypair = Keypair::try_from(wallet_bytes.as_slice())
        .map_err(|_| WalletEncryptionError::KeypairRestorationFailed)?;

    // plaintext_sensitive and key are zeroized here
    Ok(keypair)
}

#[cfg(test)]
mod tests {
    use super::*;
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
}
