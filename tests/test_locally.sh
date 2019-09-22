#!/bin/sh

export RUST_BACKTRACE=1

check_targets="x86_64-unknown-freebsd x86_64-unknown-netbsd x86_64-apple-darwin"
# not available: dragonfly and openbsd
# lacks libc support: x86_64-sun-solaris
for target in $check_targets; do
    echo "checking $target"
    cargo check --target "$target" || exit 1
done

test_targets="x86_64-unknown-linux-gnu x86_64-unknown-linux-gnux32 x86_64-unknown-linux-musl i686-unknown-linux-gnu i686-unknown-linux-musl"
for target in $test_targets; do
    echo "testing $target"
    cargo test --target "$target" -- --quiet || exit 1
done
