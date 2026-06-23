#!/usr/bin/env bash

set -euo pipefail

WORKSPACE_DIR="${BUILD_WORKSPACE_DIRECTORY:-$(pwd)}"
cd "$WORKSPACE_DIR"

if ! cargo llvm-cov --version >/dev/null 2>&1; then
    echo "cargo-llvm-cov not found. Install it with: cargo install cargo-llvm-cov"
    exit 1
fi

cargo llvm-cov -p account_sdk --features webauthn,filestorage,avnu-paymaster --lcov --output-path lcov.info
