# Deferred Features

This document tracks features that were identified during development but deferred for later implementation.

## Secret Type Validation

**Status**: Deferred
**Phase**: 2 (Operational maturity)

Currently, `secret_type` is metadata-only. The following validation could be added:

### SSH Private Key Validation
- Verify PEM format (`-----BEGIN ... PRIVATE KEY-----`)
- Support OpenSSH, RSA, ECDSA, Ed25519 key formats
- Optional passphrase-protected key detection

### API Token Validation
- Optional format hints (e.g., GitHub `ghp_*`, AWS `AKIA*`)
- Length validation

**Implementation notes**:
- Add `validate_secret_value(value: str, secret_type: str) -> bool` in `security.py`
- Make validation opt-in via config flag to avoid breaking existing workflows
- Return warnings (not errors) for format mismatches initially

## Client-Side Encryption

**Status**: Deferred
**Phase**: 2 (Operational maturity)

Belt-and-suspenders encryption where secrets are encrypted before leaving the client.

### Approach Options

1. **User-provided passphrase**
   - Derive key via Argon2/scrypt
   - Simple UX but passphrase must be remembered
   - CLI: `aegis-cli secrets add --encrypt`

2. **Key file**
   - User manages a key file (e.g., `~/.aegis/secret.key`)
   - More secure but adds key management burden
   - CLI: `aegis-cli secrets add --encrypt-key ~/.aegis/secret.key`

3. **Age encryption**
   - Use [age](https://github.com/FiloSottile/age) for encryption
   - Modern, audited, supports hardware keys
   - CLI: `aegis-cli secrets add --age-recipient age1...`

### Server-Side Changes
- Store encrypted blob as-is (Aegis doesn't need to decrypt)
- Add `client_encrypted: bool` field to Secret model
- Retrieval returns ciphertext; client decrypts

### Implementation notes:
- Start with passphrase approach for simplicity
- Encryption happens in CLI before API call
- Server stores double-encrypted: client encryption + Fernet at rest
