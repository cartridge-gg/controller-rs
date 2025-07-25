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