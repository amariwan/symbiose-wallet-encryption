# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Security Model

This library provides password-based encryption for Solana wallet private keys. It is designed to protect against:

- ✅ Offline brute-force attacks (via Argon2id KDF)
- ✅ Data tampering (via XChaCha20-Poly1305 AEAD)
- ✅ Chosen-ciphertext attacks (via authenticated encryption)
- ✅ Memory dumps of sensitive data (via zeroization)

However, it **cannot** protect against:

- ❌ Keyloggers or malware capturing passwords during input
- ❌ Compromised systems with root/admin access
- ❌ Side-channel attacks (timing, power analysis)
- ❌ Weak user passwords (partially mitigated by strong KDF)

## Audit Status

⚠️ **This library has NOT undergone a professional security audit.**

For production deployments involving high-value assets, we **strongly recommend**:

1. Independent security audit by qualified cryptographers
2. Penetration testing
3. Code review by domain experts
4. Regular updates and dependency monitoring

## Reporting a Vulnerability

We take security seriously. If you discover a security vulnerability, please:

### Do:

- ✅ Email security details to: [security@your-domain.com] (or use GitHub Security Advisories)
- ✅ Provide detailed reproduction steps
- ✅ Allow reasonable time for a fix before public disclosure (90 days standard)
- ✅ Encrypt sensitive communications using our PGP key (if available)

### Don't:

- ❌ Open a public GitHub issue for security vulnerabilities
- ❌ Disclose the vulnerability publicly before we've had time to address it
- ❌ Exploit the vulnerability beyond proof-of-concept

## Response Timeline

- **Initial Response**: Within 48 hours
- **Status Update**: Within 7 days
- **Fix Target**: Within 30 days for critical issues, 90 days for others

## Security Best Practices for Users

### Password Management

```rust
// ❌ BAD: Weak password
let password = "password123";

// ✅ GOOD: Strong, unique password
let password = generate_strong_password(); // Use a password manager!
```

### Secure Storage

```rust
// ❌ BAD: Storing unencrypted
std::fs::write("wallet.txt", wallet.to_bytes())?;

// ✅ GOOD: Always encrypt before storage
let encrypted = encrypt_wallet(&wallet, password)?;
std::fs::write("wallet.enc", encrypted)?;
```

### Memory Safety

```rust
// ✅ GOOD: Library handles zeroization automatically
// All sensitive data is automatically cleared when dropped
{
    let decrypted = decrypt_wallet(&blob, password)?;
    // Use wallet...
} // <-- Sensitive data zeroized here
```

### Error Handling

```rust
// ❌ BAD: Exposing error details to users
match decrypt_wallet(&blob, password) {
    Err(e) => println!("Decryption failed: {}", e), // Might leak info
}

// ✅ GOOD: Generic error message
match decrypt_wallet(&blob, password) {
    Err(_) => eprintln!("Invalid password or corrupted data"),
}
```

## Cryptographic Dependencies

This library relies on:

- **Orion**: Pure Rust crypto library
  - Last audit: [Check Orion's security page]
  - Known issues: Monitor https://github.com/orion-rs/orion/security

- **solana-sdk**: Solana blockchain SDK
  - Security: Maintained by Solana Labs

## Known Limitations

1. **No Hardware Security Module (HSM) support**
   - Private keys exist in RAM during encryption/decryption
   - Consider hardware wallets for ultra-high security

2. **No Multi-Factor Authentication (MFA)**
   - Single password is the only authentication factor
   - Consider implementing TOTP or U2F at the application level

3. **No Key Rotation**
   - Re-encryption requires manual process
   - Plan for periodic password updates

4. **Platform-Specific Considerations**
   - Memory locking not guaranteed on all platforms
   - Consider using `mlock()` wrappers for critical deployments

## Security Updates

We will publish security advisories for:

- Critical vulnerabilities (CVSS ≥ 9.0): Immediate patch
- High severity (CVSS 7.0-8.9): Within 7 days
- Medium severity (CVSS 4.0-6.9): Within 30 days
- Low severity (CVSS < 4.0): Next regular release

## Contact

- Security Email: [security@your-domain.com]
- PGP Key: [Your PGP fingerprint]
- GitHub Security Advisories: https://github.com/amariwan/symbiose-wallet-encryption/security/advisories

---

*This security policy was last updated: December 26, 2025*
