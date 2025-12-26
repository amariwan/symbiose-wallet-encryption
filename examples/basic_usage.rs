//! Example: Basic usage of symbiose-wallet-encryption
//!
//! Run with: cargo run --example basic_usage

use solana_sdk::signature::Keypair;
use symbiose_wallet_encryption::{decrypt_wallet, encrypt_wallet};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Symbiose Wallet Encryption - Basic Usage ===\n");

    // Step 1: Create or load a Solana wallet
    println!("Step 1: Creating a new Solana wallet...");
    let wallet = Keypair::new();
    println!("  ✓ Wallet created");
    println!("  Public Key: {}\n", wallet.pubkey());

    // Step 2: Set a password
    // In a real application, get this securely from user input
    let password = "my-secure-password-2025!";
    println!("Step 2: Setting password");
    println!("  Password: {}\n", password);

    // Step 3: Encrypt the wallet
    println!("Step 3: Encrypting wallet...");
    let encrypted_blob = encrypt_wallet(&wallet, password)?;
    println!("  ✓ Encryption successful");
    println!("  Encrypted size: {} bytes", encrypted_blob.len());
    println!("  Hex preview: {}...\n", hex::encode(&encrypted_blob[..32]));

    // At this point, you can safely store encrypted_blob to:
    // - Local filesystem
    // - Cloud storage
    // - Database
    // - USB drive / hardware wallet
    println!("💾 You can now safely store this encrypted blob anywhere");
    println!("   It's protected by your password and AEAD encryption.\n");

    // Step 4: Decrypt the wallet (when needed)
    println!("Step 4: Decrypting wallet...");
    let restored_wallet = decrypt_wallet(&encrypted_blob, password)?;
    println!("  ✓ Decryption successful");
    println!("  Public Key: {}\n", restored_wallet.pubkey());

    // Step 5: Verify integrity
    println!("Step 5: Verifying integrity...");
    if wallet.to_bytes() == restored_wallet.to_bytes() {
        println!("  ✅ Success! Wallet restored perfectly.\n");
    } else {
        eprintln!("  ❌ Error: Wallet mismatch!");
        return Err("Integrity check failed".into());
    }

    // Bonus: Show what happens with wrong password
    println!("Bonus: Testing with wrong password...");
    let wrong_password = "wrong-password";
    match decrypt_wallet(&encrypted_blob, wrong_password) {
        Ok(_) => {
            eprintln!("  ❌ This should not happen!");
            return Err("Security breach".into());
        }
        Err(e) => {
            println!("  ✅ Correctly rejected: {}\n", e);
        }
    }

    println!("=== All operations completed successfully! ===");

    Ok(())
}
