# Cartridge Controller

A Rust implementation of a smart contract account system for Starknet, providing account abstraction with session-based authentication, multi-owner support, and cross-platform compatibility.

## Features

- **Account Abstraction** - Smart contract accounts with programmable validation
- **Session Management** - Temporary signing keys with time-bounded, policy-based access control
- **Multi-Owner Support** - Multiple authentication methods per account:
  - Starknet native keys
  - WebAuthn/FIDO2 passkeys
  - EIP-191 Ethereum wallet signatures
- **Paymaster Integration** - Sponsored transactions via outside execution (SNIP-9)
- **Cross-Platform** - Works in browsers (WASM) and native Rust environments
- **GraphQL Backend** - Integration with Cartridge API for account and session management

## Architecture

The project consists of three main components:

| Component       | Description                                                                           |
| --------------- | ------------------------------------------------------------------------------------- |
| `account_sdk/`  | Core Rust library for account management, session handling, and Starknet interactions |
| `account-wasm/` | WebAssembly bindings exposing SDK functionality to JavaScript/TypeScript              |
| `contracts/`    | Cairo smart contracts for the controller system                                       |

## Prerequisites

| Tool    | Version             |
| ------- | ------------------- |
| Rust    | 1.92+               |
| Scarb   | 2.9.4               |
| Node.js | v20.11.1            |
| Katana  | 1.7.0 (for testing) |

## Installation

### NPM (WASM Package)

```bash
# Latest stable release
npm install @cartridge/controller-wasm

# Latest dev release
npm install @cartridge/controller-wasm@dev
```

### Rust (Cargo)

Add to your `Cargo.toml`:

```toml
[dependencies]
account_sdk = { git = "https://github.com/cartridge-gg/controller" }
```

## Development

### Building

```bash
# Build the entire workspace
cargo build

# Build WASM packages
cd account-wasm && ./build.sh

# Generate Cairo contract artifacts
make generate_artifacts
```

### Testing

```bash
# Run all tests
cargo test

# Run session-specific tests with logging
make test-session
```

### Linting

```bash
# Set up pre-commit hooks
make setup-pre-commit

# Run all linters
make lint

# Run specific linters
make lint-rust      # Rust (rustfmt + clippy)
make lint-cairo     # Cairo (scarb fmt)
make lint-prettier  # Documentation (prettier)
```

## Project Structure

```
.
├── account_sdk/          # Core Rust SDK
│   ├── src/
│   │   ├── account/      # Account and session internals
│   │   ├── graphql/      # Cartridge API integration
│   │   ├── signers/      # Multi-auth support (Starknet, WebAuthn, EIP-191)
│   │   ├── storage/      # Storage backends (memory, localStorage, file)
│   │   ├── controller.rs # Main controller implementation
│   │   └── session.rs    # Session management
│   └── artifacts/        # Compiled contract classes
├── account-wasm/         # WASM bindings for JS/TS
├── contracts/            # Cairo smart contracts
│   └── resolver/         # Name resolver contract
└── scripts/              # Utility scripts
```

## Documentation

For complete documentation, visit [docs.cartridge.gg](https://docs.cartridge.gg).

## License

Copyright Cartridge Gaming Company 2022. All rights reserved.

This software is available for non-commercial use under specific conditions. See [LICENSE](LICENSE) for details.
