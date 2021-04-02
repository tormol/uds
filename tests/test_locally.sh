#!/bin/sh
MSRV="1.39.0"
CAFLAGS="-j1"
export RUST_BACKTRACE=1

set -ev

test_targets="x86_64-unknown-linux-gnu x86_64-unknown-linux-musl \
              i686-unknown-linux-gnu i686-unknown-linux-musl"
for target in $test_targets; do
    echo "testing $target"
    cargo check $CAFLAGS --target "$target"
    cargo check $CAFLAGS --target "$target" --all-features
    RUSTFLAGS='--cfg feature="os-poll"' cargo test $CAFLAGS --target "$target" --all-features -- --quiet
    echo
done

test_nightly_target="x86_64-unknown-linux-gnux32" # segfaults fixed with LLVM 12
echo "testing $test_nightly_target (on nightly)"
RUSTFLAGS='--cfg feature="os-poll"'  cargo +nightly test $CAFLAGS --target "$test_nightly_target" --release --all-features -- --quiet
echo

echo "checking with minimum supported Rust version $MSRV"
rm Cargo.lock
RUSTFLAGS='--cfg feature="os-poll"' cargo "+$MSRV" check $CAFLAGS --all-features
echo

check_targets="x86_64-unknown-freebsd x86_64-unknown-netbsd \
               x86_64-apple-darwin x86_64-sun-solaris \
               aarch64-unknown-linux-gnu arm-unknown-linux-gnueabi \
               aarch64-linux-android i686-linux-android"
# not available: dragonfly, openbsd and illumos
for target in $check_targets; do
    echo "checking $target"
    cargo check $CAFLAGS --target "$target" --tests --examples
    cargo check $CAFLAGS --target "$target" --all-features
    RUSTFLAGS='--cfg feature="os-poll"' cargo check $CAFLAGS --target "$target" --tests --examples --all-features
    echo
done

export RUSTFLAGS='--cfg feature="os-poll"'

echo "checking with minimum version dependencies"
rm Cargo.lock
cargo +nightly check $CAFLAGS -Z minimal-versions
cargo +nightly check $CAFLAGS -Z minimal-versions --features mio
# no version of mio-uds compiles with minimal versions
cargo +nightly check $CAFLAGS -Z minimal-versions --features mio_07
rm Cargo.lock
echo

echo "report OS and std characteristics"
exec cargo run --target x86_64-unknown-linux-gnu --bin characteristics
