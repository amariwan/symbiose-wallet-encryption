# Symbiose Wallet Encryption

![Rust](https://img.shields.io/badge/rust-%23000000.svg?style=for-the-badge&logo=rust&logoColor=white)
![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)

A production-ready, secure Rust library for password-based encryption of Solana wallet private keys using industry-standard cryptographic primitives.

## 🔒 Security Features

- **AEAD Encryption**: XChaCha20-Poly1305 for authenticated encryption with associated data
- **Strong KDF**: Argon2id for password-to-key derivation (resistant to GPU/ASIC attacks)
- **Memory Safety**: Automatic zeroization of sensitive data (passwords, keys, plaintexts)
- **Authenticity Guarantee**: Poly1305 MAC prevents data tampering
- **Unique IVs**: Each encryption generates fresh random salt and nonce

## 📦 Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
symbiose-wallet-encryption = "0.1.0"
solana-sdk = "2.0"
```

## 🚀 Quick Start

```rust
use solana_sdk::signature::Keypair;
use symbiose_wallet_encryption::{encrypt_wallet, decrypt_wallet};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create or load a wallet
    let wallet = Keypair::new();
    let password = "your-strong-password";

    // Encrypt
    let encrypted_blob = encrypt_wallet(&wallet, password)?;

    // Store encrypted_blob safely (filesystem, cloud, database)
    std::fs::write("wallet.enc", &encrypted_blob)?;

    // Load and decrypt later
    let encrypted_data = std::fs::read("wallet.enc")?;
    let restored_wallet = decrypt_wallet(&encrypted_data, password)?;

    assert_eq!(wallet.to_bytes(), restored_wallet.to_bytes());
    Ok(())
}
```

## 🏗️ Architecture

### Encryption Process

```
[User Password] + [Random Salt (32B)]
         ↓
   [Argon2id KDF]
         ↓
[256-bit Encryption Key]
         ↓
[Keypair Plaintext] + [Random Nonce (24B)] + [Key]
         ↓
  [XChaCha20-Poly1305]
         ↓
[Encrypted Blob] = [Salt || Nonce || Ciphertext || Auth Tag]

The library encrypts the raw 64-byte keypair directly to avoid leaving Base58 strings in memory, improving zeroization guarantees and reducing overhead.
```

### Data Layout

| Component        | Size (bytes) | Description                          |
|------------------|--------------|--------------------------------------|
| Salt             | 32           | Random salt for KDF                  |
| Nonce            | 24           | Random nonce for XChaCha20           |
| Ciphertext       | Variable     | Encrypted keypair data               |
| Authentication Tag | 16         | Poly1305 MAC for integrity           |

**Total overhead**: 72 bytes + ciphertext length

## 🔐 Cryptographic Details

### Key Derivation (Argon2id)

- **Algorithm**: Argon2id (hybrid mode)
- **Iterations**: 15
- **Memory**: 65_536 KiB (64 MiB)
- **Parallelism**: 1 lane
- **Output**: 256-bit key

Parameters are configurable via `Argon2Params`; lower them for constrained devices or raise memory for stronger GPU resistance.

### AEAD (XChaCha20-Poly1305)

- **Cipher**: XChaCha20 stream cipher
- **MAC**: Poly1305 authenticator
- **Nonce size**: 192 bits (24 bytes)
- **Tag size**: 128 bits (16 bytes)

## 🧪 Testing

Run all tests:

```bash
cargo test
```

Run with detailed output:

```bash
cargo test -- --nocapture
```

Run the interactive demo:

```bash
cargo run
```

Run the basic usage example:

```bash
cargo run --example basic_usage
```

## 📊 Test Coverage

The library includes comprehensive tests for:

- ✅ Successful encryption/decryption workflow
- ✅ Wrong password rejection (AEAD failure)
- ✅ Data tampering detection
- ✅ Salt corruption detection
- ✅ Unique salt/nonce generation
- ✅ Invalid data format handling
- ✅ Empty data rejection
- ✅ Multiple passwords support

## 🛡️ Security Best Practices

### Password Requirements

We recommend enforcing:
- **Minimum length**: 12 characters
- **Complexity**: Mix of uppercase, lowercase, numbers, symbols
- **Uniqueness**: Don't reuse passwords across services

For weaker passwords, consider increasing Argon2 parameters:

```rust
// In lib.rs, modify derive_secret_key():
derive_key(&password_protected, salt, 20, 2048, CHACHA_KEYSIZE as u32) // Harder KDF
```

### Memory Safety

All sensitive data is automatically zeroized:
- ✅ Plaintext private keys
- ✅ User passwords
- ✅ Derived encryption keys
- ✅ Intermediate buffers

This is enforced via:
- Orion's `SecretKey` and `Password` types
- Custom `SensitiveData` wrapper with `#[zeroize(drop)]`

### Storage Recommendations

The encrypted blob is safe to store in:
- ✅ Local filesystem (with OS permissions)
- ✅ Cloud storage (encrypted at rest)
- ✅ Databases
- ✅ USB drives / hardware wallets
- ✅ Version control (if needed, though not recommended)

**Without the password, the blob is cryptographically secure.**

## ⚠️ Security Considerations

### What This Library Protects Against

- ✅ Offline brute-force attacks (via strong KDF)
- ✅ Data tampering (via AEAD)
- ✅ Bit-flip attacks (via Poly1305 MAC)
- ✅ Chosen-ciphertext attacks (via AEAD)
- ✅ Memory dumps (via zeroization)

### What This Library Does NOT Protect Against

- ❌ Keyloggers capturing the password
- ❌ Memory exploits before zeroization
- ❌ Physical access to unlocked systems
- ❌ Weak user passwords (partially mitigated by Argon2)
- ❌ Side-channel attacks (not audited for timing attacks)

### Audit Status

⚠️ **This library has not undergone a professional security audit.**

For production use in high-value systems, we recommend:
1. Independent security audit
2. Penetration testing
3. Code review by cryptography experts

## 🔧 Dependencies

| Crate        | Version | Purpose                              |
|--------------|---------|--------------------------------------|
| `orion`      | 0.17    | Cryptographic primitives             |
| `solana-sdk` | 2.0     | Solana keypair handling              |
| `getrandom`  | 0.2     | Secure random number generation      |
| `hex`        | 0.4     | Hex previews in demo/example         |
| `anyhow`     | 1.0     | Error handling                       |
| `zeroize`    | 1.7     | Secure memory zeroing                |

## 📚 API Documentation

Generate and view documentation:

```bash
cargo doc --open
```

### Main Functions

#### `encrypt_wallet`

```rust
pub fn encrypt_wallet(
    wallet: &Keypair,
    password: &str
) -> Result<Vec<u8>, WalletEncryptionError>
```

Encrypts a Solana keypair with a password. Returns a binary blob safe for storage.

#### `decrypt_wallet`

```rust
pub fn decrypt_wallet(
    encrypted_data: &[u8],
    password: &str
) -> Result<Keypair, WalletEncryptionError>
```

Decrypts an encrypted blob back into a Solana keypair. Fails if password is wrong or data is tampered.

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass: `cargo test`
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🔗 Related Projects

- [Orion](https://github.com/orion-rs/orion) - Usable, easy and safe pure-Rust crypto
- [Solana SDK](https://github.com/solana-labs/solana) - Solana blockchain SDK
- [RustCrypto](https://github.com/RustCrypto) - Cryptography implementations in Rust

## 📮 Contact

- **Author**: Symbiose Team
- **Blog**: See the full explanation at [tasiomind.com/blog/orion-encryption](https://tasiomind.com/blog/orion-encryption)
- **Issues**: [GitHub Issues](https://github.com/amariwan/symbiose-wallet-encryption/issues)

## 🙏 Acknowledgments

- Built with [Orion](https://github.com/orion-rs/orion) by brycx
- Inspired by industry standards: Signal Protocol, age encryption
- Designed for the Symbiose multi-chain ecosystem

---

**⚡ Made with Rust for the Symbiose project**
