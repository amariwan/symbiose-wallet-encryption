use orion::hazardous::aead::xchacha20poly1305::SecretKey;
use orion::hazardous::stream::chacha20::CHACHA_KEYSIZE;
use orion::kdf::{derive_key, Password, Salt};

use crate::errors::WalletEncryptionError;
use crate::params::Argon2Params;

/// Derives a 256-bit encryption key from a password and salt using Argon2id.
pub fn derive_secret_key(
    password: &str,
    salt: &Salt,
    params: Argon2Params,
) -> Result<SecretKey, WalletEncryptionError> {
    let password_protected = Password::from_slice(password.as_bytes()).map_err(|e| {
        WalletEncryptionError::CryptoError(format!("Password wrapping failed: {}", e))
    })?;

    let derived_key = derive_key(
        &password_protected,
        salt,
        params.iterations,
        params.memory_kib,
        CHACHA_KEYSIZE as u32,
    )
    .map_err(|_| WalletEncryptionError::KeyDerivationFailed)?;

    SecretKey::from_slice(derived_key.unprotected_as_bytes()).map_err(|e| {
        WalletEncryptionError::CryptoError(format!("SecretKey conversion failed: {}", e))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::Argon2Params;
    use orion::hazardous::stream::chacha20::CHACHA_KEYSIZE;
    use orion::kdf::Salt;

    #[test]
    fn derives_deterministic_key_for_fixed_inputs() {
        let salt_bytes = [7u8; 32];
        let salt = Salt::from_slice(&salt_bytes).expect("salt creation should work");
        let params = Argon2Params::default();

        let key1 = derive_secret_key("password", &salt, params).expect("kdf should work");
        let key2 = derive_secret_key("password", &salt, params).expect("kdf should work");

        assert_eq!(key1.unprotected_as_bytes(), key2.unprotected_as_bytes());
        assert_eq!(key1.unprotected_as_bytes().len(), CHACHA_KEYSIZE);
    }
}
