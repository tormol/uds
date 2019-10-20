#!/bin/sh

export RUST_BACKTRACE=1

check_targets="x86_64-unknown-freebsd x86_64-unknown-netbsd x86_64-apple-darwin aarch64-unknown-linux-gnu arm-unknown-linux-gnueabi"
# not available: dragonfly and openbsd
# lacks libc support: x86_64-sun-solaris
for target in $check_targets; do
    echo "checking $target"
    cargo check --target "$target" --all-features || exit $?
done

test_targets="x86_64-unknown-linux-gnu x86_64-unknown-linux-musl i686-unknown-linux-gnu i686-unknown-linux-musl"
for target in $test_targets; do
    echo "testing $target"
    cargo test --target "$target" --all-features -- --quiet || exit $?
done

target="x86_64-unknown-linux-gnux32"
echo "testing $target in release mode"
cargo test --target "$target" --release --all-features -- --quiet || exit $?

echo "checking without optional features"
exec cargo check --no-default-features
