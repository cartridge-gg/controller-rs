#!/bin/sh

set -ex

# Ensure wasm-opt is installed
if
    ! command -v wasm-opt &
    >/dev/null
then
    echo "Installing wasm-opt..."
    npm install -g wasm-opt
fi

# Build account bundle
RUSTFLAGS='-C link-arg=-s -C opt-level=z -C codegen-units=1' \
    wasm-pack build --target bundler --out-dir ./pkg-controller --release --features "controller_account,wee_alloc"

# Optimize controller bundle
wasm-opt -Oz --enable-bulk-memory -o ./pkg-controller/account_wasm_bg.wasm ./pkg-controller/account_wasm_bg.wasm

# Build session bundle
RUSTFLAGS='-C link-arg=-s -C opt-level=z -C codegen-units=1' \
    wasm-pack build --target bundler --out-dir ./pkg-session --out-name session_wasm --release --features "session_account,wee_alloc"

# Optimize session bundle
wasm-opt -Oz --enable-bulk-memory -o ./pkg-session/session_wasm_bg.wasm ./pkg-session/session_wasm_bg.wasm
