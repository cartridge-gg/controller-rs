#!/usr/bin/env bash

set -euo pipefail

WORKSPACE_DIR="${BUILD_WORKSPACE_DIRECTORY:-$(pwd)}"
cd "$WORKSPACE_DIR"

CHECK_ONLY=false
RUN_RUST=false
RUN_CAIRO=false
RUN_PRETTIER=false

show_usage() {
    cat <<'USAGE'
Usage: lint.sh [OPTIONS]

Options:
  --rust          Run Rust linting only (fmt + clippy)
  --cairo         Run Cairo formatting only (scarb fmt)
  --prettier      Run prettier formatting only
  --all           Run all linting (default if no specific options)
  --check-only    Check formatting without applying changes
  --help          Show this help message
USAGE
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --rust)
            RUN_RUST=true
            ;;
        --cairo)
            RUN_CAIRO=true
            ;;
        --prettier)
            RUN_PRETTIER=true
            ;;
        --all)
            RUN_RUST=true
            RUN_CAIRO=true
            RUN_PRETTIER=true
            ;;
        --check-only)
            CHECK_ONLY=true
            ;;
        --help)
            show_usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            show_usage
            exit 1
            ;;
    esac
    shift
 done

if [ "$RUN_RUST" = false ] && [ "$RUN_CAIRO" = false ] && [ "$RUN_PRETTIER" = false ]; then
    RUN_RUST=true
    RUN_CAIRO=true
    RUN_PRETTIER=true
fi

run_rust() {
    if [ "$CHECK_ONLY" = true ]; then
        cargo fmt --all -- --check
    else
        cargo fmt --all
    fi

    cargo clippy -p account_sdk --all-targets --features webauthn,filestorage -- -D warnings
}

run_cairo() {
    if ! command -v scarb >/dev/null 2>&1; then
        echo "scarb not found; skipping Cairo formatting."
        return 0
    fi

    for contract_dir in contracts/*/; do
        if [ -d "$contract_dir" ] && [ -f "$contract_dir/Scarb.toml" ]; then
            if [ "$CHECK_ONLY" = true ]; then
                (cd "$contract_dir" && scarb fmt --check)
            else
                (cd "$contract_dir" && scarb fmt)
            fi
        fi
    done
}

run_prettier() {
    if ! command -v prettier >/dev/null 2>&1; then
        echo "prettier not found; skipping documentation formatting."
        return 0
    fi

    if [ "$CHECK_ONLY" = true ]; then
        prettier --check "**/*.{md,yml,yaml,json}" --ignore-path .prettierignore
    else
        prettier --write "**/*.{md,yml,yaml,json}" --ignore-path .prettierignore
    fi
}

EXIT_CODE=0

if [ "$RUN_RUST" = true ]; then
    if ! run_rust; then
        EXIT_CODE=1
    fi
fi

if [ "$RUN_CAIRO" = true ]; then
    if ! run_cairo; then
        EXIT_CODE=1
    fi
fi

if [ "$RUN_PRETTIER" = true ]; then
    if ! run_prettier; then
        EXIT_CODE=1
    fi
fi

exit $EXIT_CODE
