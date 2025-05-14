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

# --- Controller ---
# ESM build (for bundlers and <script type="module">)
RUSTFLAGS='-C link-arg=-s -C opt-level=z -C codegen-units=1' \
    wasm-pack build --target bundler --out-dir ./pkg-controller/esm --out-name index --release --features "controller_account,wee_alloc"
# Optimize controller ESM bundle
wasm-opt -Oz --enable-bulk-memory -o ./pkg-controller/esm/index_bg.wasm ./pkg-controller/esm/index_bg.wasm
rm -f ./pkg-controller/esm/.gitignore

# CJS build (for Node.js require)
RUSTFLAGS='-C link-arg=-s -C opt-level=z -C codegen-units=1' \
    wasm-pack build --target nodejs --out-dir ./pkg-controller/cjs --out-name index --release --features "controller_account,wee_alloc"
# Optimize controller CJS bundle
wasm-opt -Oz --enable-bulk-memory -o ./pkg-controller/cjs/index_bg.wasm ./pkg-controller/cjs/index_bg.wasm
rm -f ./pkg-controller/cjs/.gitignore

# --- Session ---
# ESM build
RUSTFLAGS='-C link-arg=-s -C opt-level=z -C codegen-units=1' \
    wasm-pack build --target bundler --out-dir ./pkg-session/esm --out-name index --release --features "session_account,wee_alloc"
# Optimize session ESM bundle
wasm-opt -Oz --enable-bulk-memory -o ./pkg-session/esm/index_bg.wasm ./pkg-session/esm/index_bg.wasm
rm -f ./pkg-session/esm/.gitignore

# CJS build
RUSTFLAGS='-C link-arg=-s -C opt-level=z -C codegen-units=1' \
    wasm-pack build --target nodejs --out-dir ./pkg-session/cjs --out-name index --release --features "session_account,wee_alloc"
# Optimize session CJS bundle
wasm-opt -Oz --enable-bulk-memory -o ./pkg-session/cjs/index_bg.wasm ./pkg-session/cjs/index_bg.wasm
rm -f ./pkg-session/cjs/.gitignore

# Remove top-level .gitignore files if they exist (though wasm-pack usually puts them in --out-dir)
rm -f pkg-controller/.gitignore
rm -f pkg-session/.gitignore
