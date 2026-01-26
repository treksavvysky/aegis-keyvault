# Aegis KeyVault

*Securely centralize your SSH keys, passwords, and other sensitive project variables.*

Repository: https://github.com/treksavvysky/aegis-keyvault

---

## Table of Contents

1. [Overview](#overview)
2. [Key Features](#key-features)
3. [Quick Start](#quick-start)
4. [Usage](#usage)
5. [Architecture](#architecture)
6. [Security Model](#security-model)
7. [Roadmap](#roadmap)
8. [Contributing](#contributing)
9. [License](#license)

---

## Overview

**Aegis KeyVault** is a lightweight secrets-management service purpose-built for DevOps workflows that rely heavily on SSH.
Its main scope is to **store, encrypt, and serve confidential data**—primarily:

* **SSH private/public key pairs**
* **System & service passwords**
* **Project-specific environment variables (API tokens, DB credentials, etc.)**

By isolating secrets in a single, auditable store, Aegis KeyVault eliminates “secret sprawl,” hard-coded credentials, and the risk of leaking sensitive data across repos or CI/CD pipelines.

---

## Key Features

| Category                        | What You Get                                                                  |
| ------------------------------- | ----------------------------------------------------------------------------- |
| **End-to-End Encryption**       | Secrets are encrypted at rest (AES-256-GCM) and in transit (TLS).             |
| **Granular Access Control**     | Role-based policies allow precise scoping (per-user, per-key, per-project).   |
| **One-Shot Token Retrieval**    | Issue short-lived tokens for CI jobs; tokens evaporate after a single use.    |
| **Audit Logging**               | Every read/write/delete is timestamped and signed for compliance.             |
| **Pluggable Storage Back-Ends** | Use the built-in SQLite store, or swap in PostgreSQL / S3 with a config flag. |
| **CLI & REST API**              | Script it locally or call it from any language / pipeline.                    |
| **Easy Bootstrap**              | Single-binary release or Docker Compose stack—up in seconds.                  |

---

## Quick Start

1. **Clone the repo**

   ```bash
   git clone https://github.com/treksavvysky/aegis-keyvault.git
   cd aegis-keyvault
   ```

2. **Create a virtual environment and install dependencies**

   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
   ```

3. **Run the API server**

   ```bash
   uvicorn aegis_keyvault.api:app --reload
   ```

4. **Check health**

   ```bash
   curl http://127.0.0.1:8000/health
   ```

---

## Usage

### CLI Highlights

| Command                                | Description               |                        |
| -------------------------------------- | ------------------------- | ---------------------- |
| \`vault cli put --path <path> \[--file | --value]\`                | Store/update a secret. |
| `vault cli get <path>`                 | Read a secret (stdout).   |                        |
| `vault cli ls <path>`                  | List keys under a prefix. |                        |
| `vault cli rm <path>`                  | Delete a secret.          |                        |

### Environment Variables

| Variable                | Purpose                                          |
| ----------------------- | ------------------------------------------------ |
| `VAULT_ADDR`            | Base URL (e.g. `https://vault.mycorp.local`).    |
| `VAULT_TOKEN`           | Auth token (root or scoped).                     |
| `VAULT_TLS_SKIP_VERIFY` | Set to `true` for self-signed certs in dev only. |

---

## Architecture

```
┌──────────────┐      HTTPS/TLS     ┌──────────────┐
│  CI / CLI    ├───────────────────►│  REST API    │
└──────────────┘                    │  & AuthN/Z   │
        ▲                           └─────┬────────┘
        │ gRPC (optional)                 │
        │                                 ▼
┌──────────────┐                    ┌──────────────┐
│  Admin UI    │◄──WebSockets──────►│  Core Store  │
└──────────────┘                    └──────────────┘
```

* **Core Store**: pluggable driver (SQLite | PostgreSQL | S3).
* **AuthN/Z**: JWT & HMAC-signed policies, backed by libsodium.
* **API**: Restful JSON with OpenAPI 3 spec; optional gRPC for high throughput.

---

## Security Model

1. Secrets are symmetrically encrypted before write; the master key is sealed by a hardware-rooted KMS (e.g., AWS KMS, HashiCorp Transit, TPM).
2. Tokens carry minimal scope & TTL.
3. Defence in depth: TLS, mTLS (optional), plus configurable IP allow-lists.
4. Regular automated secret rotation hooks available via webhooks.

---

## Roadmap

* [ ] **OTP-backed Auth**: TOTP & WebAuthn for root login.
* [ ] **Secret Versioning**: diff & rollback previous values.
* [ ] **Kubernetes Operator**: auto-inject secrets into pods.
* [ ] **SOPS Integration**: decrypt secrets in Git Ops workflows.

---

## Contributing

We ♥ PRs! Please open an issue first to discuss major changes.

1. Fork → feature branch → PR.
2. Run `make test` (100 % coverage required).
3. Sign the CLA.

---

## License

Aegis KeyVault is released under the **MIT License**. See `LICENSE` for details.

---

<div align="center">
Made with ☕ & ⚙️ by the Aegis KeyVault team
</div>
