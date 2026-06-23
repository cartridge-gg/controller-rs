#!/usr/bin/env bash

set -euo pipefail

MODE="all"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --controller)
            MODE="controller"
            ;;
        --session)
            MODE="session"
            ;;
        --all)
            MODE="all"
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
    shift
 done

WORKSPACE_DIR="${BUILD_WORKSPACE_DIRECTORY:-$(pwd)}"

"$WORKSPACE_DIR/scripts/bazel/build_wasm.sh"

cd "$WORKSPACE_DIR/account-wasm"

if [ "$MODE" = "all" ] || [ "$MODE" = "controller" ]; then
    tar -czf pkg-controller.tar.gz pkg-controller
fi

if [ "$MODE" = "all" ] || [ "$MODE" = "session" ]; then
    tar -czf pkg-session.tar.gz pkg-session
fi
