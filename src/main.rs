//! Main demo application for Symbiose Wallet Encryption
//!
//! This binary demonstrates the complete encryption/decryption workflow
//! and runs various security test scenarios.

use solana_sdk::signature::{Keypair, Signer};
use symbiose_wallet_encryption::{decrypt_wallet, encrypt_wallet};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("╔════════════════════════════════════════════════════════════╗");
    println!("║     Symbiose Wallet Encryption - Security Demo            ║");
    println!("╚════════════════════════════════════════════════════════════╝\n");

    // ========================================================================
    // Test 1: Basic Encryption/Decryption Workflow
    // ========================================================================
    println!("📋 Test 1: Basic Encryption/Decryption Workflow");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

    // Create a new Solana wallet
    let original_wallet = Keypair::new();
    println!("✓ Generated new Solana wallet");
    println!("  Public Key: {}", original_wallet.pubkey());
    println!(
        "  Private Key (first 8 bytes): {:02x?}...",
        &original_wallet.to_bytes()[..8]
    );

    // Set password (in production, get this securely from user input)
    let password = "mein-super-geheimes-passwort-2025!";
    println!("\n✓ Using password: '{}'", password);

    // Encrypt the wallet
    println!("\n🔒 Encrypting wallet...");
    let encrypted_blob = encrypt_wallet(&original_wallet, password)?;
    println!("✓ Encryption successful!");
    println!("  Encrypted blob size: {} bytes", encrypted_blob.len());
    println!("  Blob structure: [Salt(32) + Nonce(24) + Ciphertext + Tag(16)]");
    println!(
        "  Blob preview (hex): {}...",
        hex::encode(&encrypted_blob[..32])
    );

    // Decrypt the wallet
    println!("\n🔓 Decrypting wallet...");
    let decrypted_wallet = decrypt_wallet(&encrypted_blob, password)?;
    println!("✓ Decryption successful!");
    println!("  Public Key: {}", decrypted_wallet.pubkey());

    // Validate
    if original_wallet.to_bytes() == decrypted_wallet.to_bytes() {
        println!("\n✅ Validation PASSED: Decrypted wallet matches original!");
    } else {
        println!("\n❌ Validation FAILED: Wallets don't match!");
        return Err("Validation failed".into());
    }

    // ========================================================================
    // Test 2: Wrong Password (Expected to Fail)
    // ========================================================================
    println!("\n\n📋 Test 2: Wrong Password Attack");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

    let wrong_password = "falsches-passwort";
    println!(
        "🔓 Attempting decryption with wrong password: '{}'",
        wrong_password
    );

    match decrypt_wallet(&encrypted_blob, wrong_password) {
        Ok(_) => {
            println!("❌ SECURITY BREACH: Decryption should have failed!");
            return Err("Security test failed".into());
        }
        Err(e) => {
            println!("✅ Attack blocked successfully!");
            println!("  Error: {}", e);
            println!("  This is expected behavior - AEAD verification failed");
        }
    }

    // ========================================================================
    // Test 3: Data Tampering (Expected to Fail)
    // ========================================================================
    println!("\n\n📋 Test 3: Data Tampering Attack");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

    let mut tampered_blob = encrypted_blob.clone();
    let tamper_position = tampered_blob.len() - 1;
    let original_byte = tampered_blob[tamper_position];
    tampered_blob[tamper_position] ^= 0xFF;

    println!("🔧 Tampering with encrypted data...");
    println!(
        "  Position: byte {} (in authentication tag)",
        tamper_position
    );
    println!(
        "  Original: 0x{:02x} → Tampered: 0x{:02x}",
        original_byte, tampered_blob[tamper_position]
    );

    println!("\n🔓 Attempting decryption with correct password but tampered data...");
    match decrypt_wallet(&tampered_blob, password) {
        Ok(_) => {
            println!("❌ SECURITY BREACH: Tampered data should be rejected!");
            return Err("Security test failed".into());
        }
        Err(e) => {
            println!("✅ Tampering detected and blocked!");
            println!("  Error: {}", e);
            println!("  Poly1305 authentication tag verification failed");
        }
    }

    // ========================================================================
    // Test 4: Salt Corruption (Expected to Fail)
    // ========================================================================
    println!("\n\n📋 Test 4: Salt Corruption Attack");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

    let mut corrupted_salt_blob = encrypted_blob.clone();
    corrupted_salt_blob[0] ^= 0xFF;
    corrupted_salt_blob[15] ^= 0x55;

    println!("🔧 Corrupting salt bytes...");
    println!("  Modified bytes: 0, 15 in the salt region");

    println!("\n🔓 Attempting decryption with corrupted salt...");
    match decrypt_wallet(&corrupted_salt_blob, password) {
        Ok(_) => {
            println!("❌ SECURITY BREACH: Corrupted salt should cause failure!");
            return Err("Security test failed".into());
        }
        Err(e) => {
            println!("✅ Salt corruption detected!");
            println!("  Error: {}", e);
            println!("  Derived key differs due to salt change → AEAD fails");
        }
    }

    // ========================================================================
    // Test 5: Unique Salts/Nonces
    // ========================================================================
    println!("\n\n📋 Test 5: Unique Salts/Nonces per Encryption");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

    println!("🔒 Encrypting the same wallet twice with the same password...");
    let encrypted1 = encrypt_wallet(&original_wallet, password)?;
    let encrypted2 = encrypt_wallet(&original_wallet, password)?;

    if encrypted1 == encrypted2 {
        println!("❌ SECURITY ISSUE: Identical ciphertexts detected!");
        println!("  This could leak information about identical plaintexts.");
        return Err("Uniqueness test failed".into());
    } else {
        println!("✅ Ciphertexts are different!");
        println!(
            "  Encryption 1 (first 32 bytes): {}",
            hex::encode(&encrypted1[..32])
        );
        println!(
            "  Encryption 2 (first 32 bytes): {}",
            hex::encode(&encrypted2[..32])
        );
        println!("  Reason: Unique random salt and nonce per encryption");
    }

    // Both should decrypt correctly
    println!("\n🔓 Verifying both decrypt correctly...");
    let decrypted1 = decrypt_wallet(&encrypted1, password)?;
    let decrypted2 = decrypt_wallet(&encrypted2, password)?;

    if decrypted1.to_bytes() == decrypted2.to_bytes()
        && decrypted1.to_bytes() == original_wallet.to_bytes()
    {
        println!("✅ Both ciphertexts decrypt to the correct wallet!");
    } else {
        println!("❌ Decryption mismatch!");
        return Err("Decryption consistency failed".into());
    }

    // ========================================================================
    // Test 6: Empty/Invalid Data
    // ========================================================================
    println!("\n\n📋 Test 6: Empty/Invalid Data Handling");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

    println!("🔓 Testing with empty data...");
    match decrypt_wallet(&[], password) {
        Ok(_) => {
            println!("❌ Empty data should be rejected!");
            return Err("Empty data test failed".into());
        }
        Err(e) => {
            println!("✅ Empty data rejected: {}", e);
        }
    }

    println!("\n🔓 Testing with too short data (50 bytes)...");
    let short_data = vec![0u8; 50];
    match decrypt_wallet(&short_data, password) {
        Ok(_) => {
            println!("❌ Too short data should be rejected!");
            return Err("Short data test failed".into());
        }
        Err(e) => {
            println!("✅ Too short data rejected: {}", e);
        }
    }

    // ========================================================================
    // Summary
    // ========================================================================
    println!("\n\n╔════════════════════════════════════════════════════════════╗");
    println!("║                    TEST SUMMARY                            ║");
    println!("╠════════════════════════════════════════════════════════════╣");
    println!("║  ✅ Encryption/Decryption: PASSED                          ║");
    println!("║  ✅ Wrong Password Attack: BLOCKED                         ║");
    println!("║  ✅ Data Tampering Attack: BLOCKED                         ║");
    println!("║  ✅ Salt Corruption Attack: BLOCKED                        ║");
    println!("║  ✅ Unique Salts/Nonces: VERIFIED                          ║");
    println!("║  ✅ Invalid Data Handling: VERIFIED                        ║");
    println!("╠════════════════════════════════════════════════════════════╣");
    println!("║  🔒 All security tests passed successfully!                ║");
    println!("║  💎 Your wallet encryption is production-ready.            ║");
    println!("╚════════════════════════════════════════════════════════════╝");

    Ok(())
}
