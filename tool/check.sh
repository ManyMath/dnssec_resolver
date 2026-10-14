#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
dart pub get
dart format --output=none --set-exit-if-changed lib test hook tool example
dart analyze --fatal-infos
cargo +1.90.0 fmt --manifest-path native/Cargo.toml --all -- --check
cargo +1.90.0 clippy --locked --manifest-path native/Cargo.toml --all-targets -- -D warnings
cargo +1.90.0 test --locked --manifest-path native/Cargo.toml
dart test --reporter expanded
