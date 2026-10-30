#!/usr/bin/env bash
# Puts the prover and the circuit files in zk/, each from where it is published:
# snarkjs 0.7.6 from npm, and the circuit's witness generator and proving key from paranoiddotred/paranoid at a fixed commit.
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p zk
tmp=$(mktemp -d)
(cd "$tmp" && npm pack snarkjs@0.7.6 --silent >/dev/null && tar xzf snarkjs-0.7.6.tgz package/build/snarkjs.min.js)
cp "$tmp/package/build/snarkjs.min.js" zk/snarkjs.min.js
rm -rf "$tmp"
base=https://raw.githubusercontent.com/paranoiddotred/paranoid/e0289e1716deda19f667f962cf43e478c31438b8/build
curl -fsSL -o zk/request.wasm "$base/request_js/request.wasm"
curl -fsSL -o zk/request.zkey "$base/request.zkey"
shasum -a 256 zk/*
