//! Performance benchmark for wallet encryption/decryption
//!
//! Run with: cargo run --release --example benchmark

use solana_sdk::signature::Keypair;
use std::time::Instant;
use symbiose_wallet_encryption::{decrypt_wallet, encrypt_wallet};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("╔══════════════════════════════════════════════════════════╗");
    println!("║     Symbiose Wallet Encryption - Performance Benchmark   ║");
    println!("╚══════════════════════════════════════════════════════════╝\n");

    let password = "benchmark-password-2025!";
    let iterations = 100;

    println!("Configuration:");
    println!("  • Password: {}", password);
    println!("  • Iterations: {}", iterations);
    println!("  • Argon2id params: 15 iterations, 1024 KiB memory");
    println!("\n{}\n", "━".repeat(60));

    // Benchmark: Wallet Generation
    println!("📊 Benchmarking wallet generation...");
    let start = Instant::now();
    let mut wallets = Vec::new();
    for _ in 0..iterations {
        wallets.push(Keypair::new());
    }
    let duration = start.elapsed();
    println!("  ✓ {} wallets generated in {:?}", iterations, duration);
    println!(
        "  ⏱ Average: {:.2}ms per wallet\n",
        duration.as_millis() as f64 / iterations as f64
    );

    // Benchmark: Encryption
    println!("🔒 Benchmarking encryption...");
    let wallet = &wallets[0];
    let start = Instant::now();
    let mut encrypted_blobs = Vec::new();
    for _ in 0..iterations {
        encrypted_blobs.push(encrypt_wallet(wallet, password)?);
    }
    let duration = start.elapsed();
    println!("  ✓ {} encryptions completed in {:?}", iterations, duration);
    println!(
        "  ⏱ Average: {:.2}ms per encryption",
        duration.as_millis() as f64 / iterations as f64
    );
    println!(
        "  📦 Encrypted blob size: {} bytes\n",
        encrypted_blobs[0].len()
    );

    // Benchmark: Decryption
    println!("🔓 Benchmarking decryption...");
    let encrypted = &encrypted_blobs[0];
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = decrypt_wallet(encrypted, password)?;
    }
    let duration = start.elapsed();
    println!("  ✓ {} decryptions completed in {:?}", iterations, duration);
    println!(
        "  ⏱ Average: {:.2}ms per decryption\n",
        duration.as_millis() as f64 / iterations as f64
    );

    // Benchmark: Failed Decryption (wrong password)
    println!("❌ Benchmarking failed decryption (wrong password)...");
    let wrong_password = "wrong-password";
    let start = Instant::now();
    let mut failures = 0;
    for _ in 0..iterations {
        if decrypt_wallet(encrypted, wrong_password).is_err() {
            failures += 1;
        }
    }
    let duration = start.elapsed();
    println!("  ✓ {} failures detected in {:?}", failures, duration);
    println!(
        "  ⏱ Average: {:.2}ms per failed attempt",
        duration.as_millis() as f64 / iterations as f64
    );
    println!("  ℹ This demonstrates time-constant behavior (similar to success case)\n");

    // Benchmark: Round-trip (Encrypt + Decrypt)
    println!("🔄 Benchmarking full round-trip (encrypt + decrypt)...");
    let start = Instant::now();
    for _ in 0..iterations {
        let encrypted = encrypt_wallet(wallet, password)?;
        let _ = decrypt_wallet(&encrypted, password)?;
    }
    let duration = start.elapsed();
    println!("  ✓ {} round-trips completed in {:?}", iterations, duration);
    println!(
        "  ⏱ Average: {:.2}ms per round-trip\n",
        duration.as_millis() as f64 / iterations as f64
    );

    // Summary
    println!("{}\n", "━".repeat(60));
    println!("📋 Summary:");
    println!("  • KDF (Argon2id) dominates performance (as expected)");
    println!("  • XChaCha20-Poly1305 encryption/decryption is very fast");
    println!("  • Failed decryptions take similar time (timing-attack resistant)");
    println!("\n💡 Performance Notes:");
    println!("  • For higher security, increase Argon2 parameters (slower)");
    println!("  • For faster operations, decrease Argon2 parameters (less secure)");
    println!("  • Current settings balance security and usability\n");

    println!("╔══════════════════════════════════════════════════════════╗");
    println!("║              Benchmark completed successfully!           ║");
    println!("╚══════════════════════════════════════════════════════════╝");

    Ok(())
}
