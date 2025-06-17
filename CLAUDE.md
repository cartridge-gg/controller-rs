# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a Rust-based smart contract account controller for Starknet, featuring session management, WebAuthn authentication, and WASM bindings. The project consists of:

- **Smart Contracts** (Cairo): Account controller contracts with session management and various owner types
- **Rust SDK** (`account_sdk`): Core Rust library for interacting with controller accounts
- **WASM Bindings** (`account-wasm`): WebAssembly bindings for browser integration

## Architecture

### Core Components

- `account_sdk/` - Main Rust SDK with account management, session handling, and provider abstractions
- `contracts/controller/` - Cairo smart contracts for the account controller
- `contracts/resolver/` - Cairo resolver contract for account resolution
- `account-wasm/` - WASM bindings that expose SDK functionality to JavaScript

### Key Modules

- **Account Management**: `account_sdk/src/account/` - Core account abstraction with session support
- **Signers**: `account_sdk/src/signers/` - Various signer implementations (Starknet, WebAuthn, EIP-191)
- **Storage**: `account_sdk/src/storage/` - Multiple storage backends (in-memory, file, localStorage)
- **Session Management**: Session-based transaction authorization with merkle tree policies

## Development Commands

### Building

```bash
# Build all Rust components
cargo build

# Build Cairo contracts and generate artifacts
make generate_artifacts

# Build WASM packages
cd account-wasm && ./build.sh
```

### Testing

```bash
# Run all Rust tests
cargo test

# Run specific test module
cargo test session

# Run session tests with artifacts generation
make test-session

# Run tests with output (no capture)
cargo test session -- --nocapture
```

### Cairo Development

```bash
# Build Cairo contracts
scarb --manifest-path ./contracts/controller/Scarb.toml build

# Clean build artifacts
make clean
```

### WASM Development

```bash
# Build WASM packages (requires wasm-pack and wasm-opt)
cd account-wasm && ./build.sh

# Install required tools if missing
npm install -g wasm-opt
```

## Testing Infrastructure

Tests are organized in `account_sdk/src/tests/` with:
- Integration tests for various account features
- Test runners for Katana and Cartridge networks in `tests/runners/`
- Test data fixtures in `tests/runners/test_data/`

Use `--nocapture` flag to see test output and logs during development.

## Key Features

- **Session Management**: Off-chain session creation with on-chain validation
- **Multiple Owner Types**: Support for Starknet keys, WebAuthn, and external owners
- **WebAssembly Support**: Browser-compatible WASM bindings
- **Flexible Storage**: Multiple storage backend implementations
- **Outside Execution**: Execute transactions from external accounts