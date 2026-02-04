#!/usr/bin/env bash

set -euo pipefail

WORKSPACE_DIR="${BUILD_WORKSPACE_DIRECTORY:-$(pwd)}"
cd "$WORKSPACE_DIR"

cargo test -p account_sdk --features webauthn,filestorage,avnu-paymaster
