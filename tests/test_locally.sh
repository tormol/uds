#!/bin/sh
MSRV="1.36.0"

set -e
export RUST_BACKTRACE=1

check_targets="x86_64-unknown-freebsd x86_64-unknown-netbsd \
               x86_64-apple-darwin x86_64-sun-solaris \
               aarch64-unknown-linux-gnu arm-unknown-linux-gnueabi"
# not available: dragonfly, openbsd and illumos
for target in $check_targets; do
    echo "checking $target"
    cargo check --target "$target" --tests --examples
    cargo check --target "$target" --tests --examples --features mio
    cargo check --target "$target" --tests --examples --features mio-uds
    cargo check --target "$target" --features mio_07
    cargo check --target "$target" --all-features
    RUSTFLAGS='--cfg features="os-poll"' cargo check --target "$target" --tests --examples --features mio_07
    RUSTFLAGS='--cfg features="os-poll"' cargo check --target "$target" --tests --examples --all-features
    echo
done

test_targets="x86_64-unknown-linux-gnu x86_64-unknown-linux-musl \
              i686-unknown-linux-gnu i686-unknown-linux-musl"
for target in $test_targets; do
    echo "testing $target"
    cargo check --target "$target" --all-features -- --quiet
    RUSTFLAGS='--cfg features="os-poll"' cargo test --target "$target" --all-features -- --quiet
    echo
done

export RUSTFLAGS='--cfg features="os-poll"' 

test_release_target="x86_64-unknown-linux-gnux32" # segfaults in debug mode
echo "testing $test_release_target (in release mode)"
cargo test --target "$test_release_target" --release --all-features -- --quiet
echo

echo "checking with minimum supported Rust version $MSRV"
rm Cargo.lock
cargo "+$MSRV" check --all-features --tests --examples
# requiring stable for tests or examples is OK though,
# just remove the option then.
echo

echo "checking with minimum version dependencies"
rm Cargo.lock
cargo +nightly check -Z minimal-versions
cargo +nightly check -Z minimal-versions --features mio
# no version of mio-uds compiles with minimal versions
rm Cargo.lock
echo

echo "report OS and std characteristics"
exec cargo run --bin characteristics
