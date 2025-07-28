# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a Rust-based project that implements a Cartridge Controller system for Starknet account abstraction. It consists of three main components:

1. **Smart Contracts** (`contracts/`): Cairo contracts for the controller account system including session management, multiple owners, and external owners
2. **Account SDK** (`account_sdk/`): Core Rust library implementing account management, session handling, WebAuthn integration, and Starknet interactions
3. **WASM Bindings** (`account-wasm/`): WebAssembly bindings that expose the SDK functionality to JavaScript/TypeScript environments

## Development Commands

### Building the Project
- `cargo build` - Build the entire workspace
- `cargo test` - Run all tests
- `make generate_artifacts` - Build Cairo contracts and generate artifacts
- `make test-session` - Run session-specific tests with logging

### WASM Development
- `cd account-wasm && ./build.sh` - Build optimized WASM packages for both controller and session accounts
- The build script creates two separate packages: `pkg-controller` and `pkg-session`

### Cairo Contracts
- `scarb --manifest-path ./contracts/controller/Scarb.toml build` - Build controller contracts
- `scarb --manifest-path ./contracts/resolver/Scarb.toml build` - Build resolver contracts

### Code Quality and Linting
- `make setup-pre-commit` - Set up pre-commit hooks for automatic code formatting and linting
- `make lint` - Run all linting checks (rustfmt, clippy, scarb fmt, prettier)
- `make lint-rust` - Run Rust-specific linting (rustfmt + clippy + doc check)
- `make lint-cairo` - Run Cairo-specific linting (scarb fmt)
- `make lint-prettier` - Run prettier linting for documentation files
- `make lint-check` - Check all formatting without applying changes

### GraphQL Schema Management
- `./scripts/pull_schema.sh` - Update GraphQL schema from Cartridge API

## Architecture

### Core Components

**Controller (`account_sdk/src/controller.rs`)**: Main account implementation that handles:
- Account deployment and management
- Multi-owner support with WebAuthn
- Transaction signing and execution
- Session creation and management

**Session System (`account_sdk/src/session.rs`)**: Implements session-based authentication:
- Temporary signing keys with policies
- Time-bounded access control
- Method-specific permissions
- Guardian support

**Storage Layer (`account_sdk/src/storage/`)**: Abstracted storage with multiple backends:
- In-memory storage for testing
- Local storage for browser environments  
- File-based storage for native applications

**Signers (`account_sdk/src/signers/`)**: Multiple authentication methods:
- Starknet native keys
- WebAuthn for hardware security keys
- EIP-191 for Ethereum wallet integration
- External signers for third-party wallets

### Key Features

- **Account Abstraction**: Smart contract accounts with programmable validation
- **Session Management**: Temporary keys with granular permissions
- **Multi-Owner Support**: Multiple authentication methods per account
- **WebAuthn Integration**: Hardware security key support
- **Cross-Platform**: Works in browsers (WASM) and native environments

### Testing

The project uses extensive integration testing with Katana (local Starknet node):
- `account_sdk/src/tests/` contains integration tests
- Tests use the `runners/katana.rs` framework for local blockchain simulation
- Session tests validate off-chain signing and on-chain execution

### GraphQL Integration

The SDK integrates with Cartridge's backend API for:
- Account registration and management
- Owner addition/removal
- Session creation and revocation
- Transaction indexing

All GraphQL operations are in `account_sdk/src/graphql/` with generated types from the schema.

## Pre-commit Hooks

This project uses custom pre-commit hooks to ensure code quality and consistency. The hooks automatically format and lint code before commits.

### Setup

To set up pre-commit hooks, run:

```bash
make setup-pre-commit
```

This will:
- Configure git to use the custom hooks directory (`.githooks`)
- Install required tooling (rustfmt, clippy)
- Check for optional tools (scarb, prettier)

### What the hooks do

The pre-commit hook automatically runs on staged files and performs:

1. **Rust files (`.rs`)**: 
   - Format with `rustfmt`
   - Lint with `clippy` (fails on warnings)

2. **Cairo files (`.cairo`)**:
   - Format with `scarb fmt` (if scarb is available)

3. **Documentation files (`.md`, `.yml`, `.yaml`, `.json`)**:
   - Format with `prettier` (if prettier is available)
   - Excludes `CLAUDE.md` from formatting

### Manual linting

You can run linting manually at any time:

```bash
# Run all linting
make lint

# Run specific linters
make lint-rust       # Rust only
make lint-cairo      # Cairo only  
make lint-prettier   # Documentation only

# Check formatting without applying changes
make lint-check
```

### Hook behavior

- Hooks only process **staged files**
- If formatting changes files, you'll need to re-add and commit them
- Hooks will fail if clippy finds warnings or errors
- Missing optional tools (scarb, prettier) are gracefully handled

### Troubleshooting

- If hooks fail, check the output for specific errors
- Ensure all required tools are installed (rustfmt, clippy)
- For Cairo formatting issues, ensure scarb is installed and accessible
- For documentation formatting, install prettier with `npm install -g prettier`