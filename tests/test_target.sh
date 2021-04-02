#!/bin/sh
if [ $# -ne 0 ]; then
    echo "Usage: [TARGET=triple] [NO_MIO=1] [NO_TEST=1] $0"
    exit 1
fi
if [ ! -z "$TARGET" ]; then
    TARGET="--target $TARGET"
fi
export RUST_BACKTRACE=1

set -x
cargo check $TARGET
cargo check $TARGET --tests --bins --examples
if [ -z "$NO_MIO" ] && [ -z "$NO_TEST" ]; then
    cargo check $TARGET --all-features
    cargo test $TARGET --all-features --no-fail-fast -- --test-threads 1
    cargo run --bin characteristics
elif [ ! -z "$NO_MIO" ] && [ -z "$NO_TEST" ]; then
    cargo test $TARGET --no-fail-fast -- --test-threads 1
    cargo run --bin characteristics
elif [ ! -z "$NO_TEST"] && [ -z "$NO_MIO" ]; then
    cargo check $TARGET --all-features --tests --bins --examples
fi
