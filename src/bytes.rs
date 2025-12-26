use orion::hazardous::aead::xchacha20poly1305::{open, seal};

use crate::constants::{NONCE_LEN, SALT_LEN, TAG_LEN};
use crate::errors::WalletEncryptionError;
use crate::kdf::derive_secret_key;
use crate::params::SecurityParams;
use crate::rng::{generate_nonce, generate_salt};
use crate::sensitive::SensitiveData;

/// Encrypt arbitrary bytes using password-based AEAD encryption.
pub fn encrypt_bytes<T: AsRef<[u8]>>(
    plaintext: T,
    password: &str,
) -> Result<Vec<u8>, WalletEncryptionError> {
    encrypt_bytes_with_params(plaintext, password, SecurityParams::default())
}

/// Encrypt arbitrary bytes using password-based AEAD encryption with custom parameters.
pub fn encrypt_bytes_with_params<T: AsRef<[u8]>>(
    plaintext: T,
    password: &str,
    params: SecurityParams,
) -> Result<Vec<u8>, WalletEncryptionError> {
    // Step 1: Capture plaintext (zeroized on drop)
    let plaintext = SensitiveData::new(plaintext.as_ref().to_vec());

    // Step 2: Generate random salt
    let salt = generate_salt()?;

    // Step 3: Derive encryption key from password + salt
    let key = derive_secret_key(password, &salt, params.into())?;

    // Step 4: Generate random nonce
    let nonce = generate_nonce()?;

    // Step 5: Prepare buffer for ciphertext + authentication tag
    let mut ciphertext_buffer = vec![0u8; plaintext.as_bytes().len() + TAG_LEN];

    // Step 6: Encrypt and authenticate using AEAD
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

    Ok(final_blob)
}

/// Decrypt to bytes, returning `SensitiveData` which zeroizes on drop.
pub fn decrypt_bytes(
    encrypted_data: &[u8],
    password: &str,
) -> Result<SensitiveData, WalletEncryptionError> {
    decrypt_bytes_with_params(encrypted_data, password, SecurityParams::default())
}

/// Decrypt to bytes with custom parameters, returning `SensitiveData`.
pub fn decrypt_bytes_with_params(
    encrypted_data: &[u8],
    password: &str,
    params: SecurityParams,
) -> Result<SensitiveData, WalletEncryptionError> {
    // Step 1: Validate minimum length
    if encrypted_data.len() < SALT_LEN + NONCE_LEN + TAG_LEN {
        return Err(WalletEncryptionError::InvalidDataFormat);
    }

    // Step 2: Extract components from blob
    let salt_bytes = &encrypted_data[..SALT_LEN];
    let nonce_bytes = &encrypted_data[SALT_LEN..SALT_LEN + NONCE_LEN];
    let ciphertext_with_tag = &encrypted_data[SALT_LEN + NONCE_LEN..];

    // Step 3: Reconstruct Salt and Nonce types
    let salt = orion::kdf::Salt::from_slice(salt_bytes).map_err(|e| {
        WalletEncryptionError::CryptoError(format!("Salt reconstruction failed: {}", e))
    })?;

    let nonce =
        orion::hazardous::aead::xchacha20poly1305::Nonce::from_slice(nonce_bytes).map_err(|e| {
            WalletEncryptionError::CryptoError(format!("Nonce reconstruction failed: {}", e))
        })?;

    // Step 4: Derive decryption key (must match encryption key!)
    let key = derive_secret_key(password, &salt, params.into())?;

    // Step 5: Decrypt and verify AEAD
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

    Ok(SensitiveData::new(plaintext_buffer))
}

/// Rotate the password by decrypting and re-encrypting with a new password.
pub fn change_password(
    encrypted_data: &[u8],
    old_password: &str,
    new_password: &str,
) -> Result<Vec<u8>, WalletEncryptionError> {
    change_password_with_params(
        encrypted_data,
        old_password,
        SecurityParams::default(),
        new_password,
        SecurityParams::default(),
    )
}

/// Rotate the password with explicit old/new parameters.
pub fn change_password_with_params(
    encrypted_data: &[u8],
    old_password: &str,
    old_params: SecurityParams,
    new_password: &str,
    new_params: SecurityParams,
) -> Result<Vec<u8>, WalletEncryptionError> {
    let plaintext = decrypt_bytes_with_params(encrypted_data, old_password, old_params)?;
    let reencrypted = encrypt_bytes_with_params(plaintext.as_bytes(), new_password, new_params)?;
    Ok(reencrypted)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASSWORD: &str = "unit-test-password";

    #[test]
    fn roundtrip_encrypt_decrypt_bytes() {
        let plaintext = b"hello-bytes";
        let encrypted = encrypt_bytes(plaintext, PASSWORD).expect("encryption should work");
        let decrypted = decrypt_bytes(&encrypted, PASSWORD).expect("decryption should work");

        assert_eq!(plaintext, decrypted.as_bytes());
    }

    #[test]
    fn change_password_reencrypts_ciphertext() {
        let plaintext = b"rotate-me";
        let encrypted = encrypt_bytes(plaintext, PASSWORD).expect("encryption should work");

        let new_password = "new-pass";
        let rotated =
            change_password(&encrypted, PASSWORD, new_password).expect("password rotation works");

        assert!(decrypt_bytes(&rotated, new_password).is_ok());
        let wrong_password_result = decrypt_bytes(&rotated, PASSWORD);
        assert!(matches!(
            wrong_password_result,
            Err(WalletEncryptionError::DecryptionFailed)
        ));
    }

    #[test]
    fn rejecting_too_short_input() {
        let too_short = vec![0u8; SALT_LEN + NONCE_LEN + TAG_LEN - 1];
        let result = decrypt_bytes(&too_short, PASSWORD);

        assert!(matches!(
            result,
            Err(WalletEncryptionError::InvalidDataFormat)
        ));
    }
}
