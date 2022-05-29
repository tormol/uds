#!/bin/sh
MSRV="1.56.0"
CAFLAGS=""
export RUST_BACKTRACE=1

# for i686 tests gcc-multilib must be installed
# for x32 tests syscall.x32=y must be added to the boot parameters: https://wiki.debian.org/X32Port

set -ev

test_targets="x86_64-unknown-linux-gnu x86_64-unknown-linux-musl \
              i686-unknown-linux-gnu i686-unknown-linux-musl"
for target in $test_targets; do
    echo "testing $target"
    cargo check $CAFLAGS --target "$target"
    cargo check $CAFLAGS --target "$target" --all-features
    cargo test $CAFLAGS --target "$target" --all-features -- --quiet
    echo
done

test_nightly_target="x86_64-unknown-linux-gnux32" # segfaults fixed with LLVM 12
echo "testing $test_nightly_target (on nightly)"
cargo +nightly test $CAFLAGS --target "$test_nightly_target" --release --all-features -- --quiet
echo

echo "checking with minimum supported Rust version $MSRV"
rm Cargo.lock
cargo "+$MSRV" check $CAFLAGS --all-features
echo

echo "linting"
cargo clippy --all-features || exit $?
echo

check_targets="x86_64-unknown-freebsd x86_64-unknown-netbsd \
               x86_64-apple-darwin x86_64-sun-solaris \
               aarch64-unknown-linux-gnu arm-unknown-linux-gnueabi \
               aarch64-linux-android i686-linux-android"
# not available: dragonfly, openbsd and illumos
for target in $check_targets; do
    echo "checking $target"
    cargo check $CAFLAGS --target "$target" --tests --examples
    cargo check $CAFLAGS --target "$target" --tests --examples --all-features
    echo
done

echo "checking with minimum version dependencies"
rm Cargo.lock
cargo +nightly check $CAFLAGS -Z minimal-versions
cargo +nightly check $CAFLAGS -Z minimal-versions --features mio
# no version of mio-uds compiles with minimal versions
cargo +nightly check $CAFLAGS -Z minimal-versions --features mio_07
cargo +nightly check $CAFLAGS -Z minimal-versions --features mio_08
rm Cargo.lock
echo

echo "report OS and std characteristics"
exec cargo run --target x86_64-unknown-linux-gnu --bin characteristics
