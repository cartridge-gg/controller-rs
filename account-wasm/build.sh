#!/bin/sh

set -ex

# Ensure wasm-opt is installed
if ! command -v wasm-opt &>/dev/null; then
    echo "Installing wasm-opt..."
    npm install -g wasm-opt
fi

# Change to the account-wasm directory
cd "$(dirname "$0")"

# Create output directories if they don't exist
mkdir -p pkg-controller
mkdir -p pkg-session

# Build account bundle
RUSTFLAGS='-C link-arg=-s -C opt-level=z -C codegen-units=1 -C target-feature=+bulk-memory' \
    wasm-pack build --target bundler --out-dir "$(pwd)/pkg-controller" --release --features "controller_account,wee_alloc"

# Build session bundle
RUSTFLAGS='-C link-arg=-s -C opt-level=z -C codegen-units=1 -C target-feature=+bulk-memory' \
    wasm-pack build --target bundler --out-dir "$(pwd)/pkg-session" --out-name session_wasm --release --features "session_account,wee_alloc"

rm -f pkg-controller/.gitignore
rm -f pkg-session/.gitignore
