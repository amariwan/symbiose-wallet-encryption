# Contributing to Symbiose Wallet Encryption

Thank you for your interest in contributing to this project! We welcome contributions of all kinds.

## Getting Started

1. **Fork the repository**
2. **Clone your fork**
   ```bash
   git clone https://github.com/YOUR_USERNAME/symbiose-wallet-encryption.git
   cd symbiose-wallet-encryption
   ```
3. **Build the project**
   ```bash
   cargo build
   ```
4. **Run tests**
   ```bash
   cargo test
   ```

## Development Workflow

### Making Changes

1. Create a new branch for your feature/fix:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. Make your changes and ensure:
   - Code compiles without warnings
   - All tests pass
   - New features have tests
   - Code is properly documented

3. Run formatters and linters:
   ```bash
   cargo fmt
   cargo clippy -- -D warnings
   ```

4. Commit your changes:
   ```bash
   git commit -m "feat: add your feature description"
   ```

### Commit Messages

We follow conventional commits:

- `feat:` New features
- `fix:` Bug fixes
- `docs:` Documentation changes
- `test:` Test additions/changes
- `refactor:` Code refactoring
- `perf:` Performance improvements
- `chore:` Build/tooling changes

### Pull Requests

1. Push to your fork:
   ```bash
   git push origin feature/your-feature-name
   ```

2. Create a Pull Request on GitHub

3. Ensure CI passes

4. Wait for code review

## Code Guidelines

### Security First

- Never log or print sensitive data (keys, passwords, plaintexts)
- Always use `SensitiveData` wrapper for sensitive values
- Ensure proper zeroization
- Add comments explaining security-critical code

### Rust Style

- Follow official Rust style guide
- Use `cargo fmt` for formatting
- Address all `cargo clippy` warnings
- Add documentation comments (`///`) for public APIs

### Testing

- Write unit tests for new functionality
- Test both success and failure cases
- Include edge cases
- Document test purposes with comments

Example:
```rust
#[test]
fn test_encryption_with_empty_password() {
    // Empty passwords should still work (though not recommended)
    let wallet = Keypair::new();
    let encrypted = encrypt_wallet(&wallet, "").unwrap();
    let decrypted = decrypt_wallet(&encrypted, "").unwrap();
    assert_eq!(wallet.to_bytes(), decrypted.to_bytes());
}
```

### Documentation

- Document all public functions with `///`
- Include examples in doc comments
- Update README.md for user-facing changes
- Add inline comments for complex logic

## Testing Checklist

Before submitting:

- [ ] `cargo build` succeeds
- [ ] `cargo test` all pass
- [ ] `cargo clippy` has no warnings
- [ ] `cargo fmt` has been run
- [ ] Documentation is updated
- [ ] Examples run successfully
- [ ] SECURITY.md is updated if needed

## Reporting Bugs

1. Check if the bug is already reported
2. Create a new issue with:
   - Clear description
   - Steps to reproduce
   - Expected vs actual behavior
   - Environment details (OS, Rust version)
   - **DO NOT** include sensitive data

## Feature Requests

1. Check if feature is already requested
2. Open an issue describing:
   - Use case
   - Proposed implementation
   - Potential security implications
   - Compatibility concerns

## Security Vulnerabilities

**DO NOT** open public issues for security vulnerabilities.

Instead:
- Email: [security@your-domain.com]
- Use GitHub Security Advisories
- Provide detailed information privately

See [SECURITY.md](SECURITY.md) for full policy.

## Code Review Process

1. Maintainers will review your PR
2. Address feedback promptly
3. Once approved, PR will be merged
4. Your contribution will be credited

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

## Questions?

Feel free to:
- Open a discussion
- Comment on issues
- Join our community (if applicable)

Thank you for contributing! 🎉
