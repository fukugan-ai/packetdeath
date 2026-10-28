#!/bin/sh
# Build the screens into webapp/ui/dist, ready for `packetdeath-webapp --static webapp/ui/dist`.
#
# Rollback: `rm -r webapp/ui/dist`; the server then answers 404 for the screens and keeps serving /api/.
# Needs the wasm32-unknown-unknown target and a `wasm-bindgen` command of the same version as the crate (0.2.129).
set -eu
here=$(cd "$(dirname "$0")" && pwd)
cd "$here"
cargo build --release --target wasm32-unknown-unknown -j 2
rm -rf dist
mkdir -p dist/pkg
wasm-bindgen --target web --no-typescript --out-dir dist/pkg target/wasm32-unknown-unknown/release/packetdeath_ui.wasm
cp assets/index.html assets/boot.js assets/style.css assets/favicon.svg dist/
ls -l dist dist/pkg
