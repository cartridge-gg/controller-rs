#!/usr/bin/env bash

set -euo pipefail

WORKSPACE_DIR="${BUILD_WORKSPACE_DIRECTORY:-$(pwd)}"

if ! command -v wasm-pack >/dev/null 2>&1; then
    echo "wasm-pack not found. Install it with: cargo install --locked wasm-pack"
    exit 1
fi

if ! command -v wasm-opt >/dev/null 2>&1; then
    echo "wasm-opt not found. Install it with: npm install -g wasm-opt"
    exit 1
fi

cd "$WORKSPACE_DIR/account-wasm"

./build.sh
