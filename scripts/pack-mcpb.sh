#!/usr/bin/env bash
# Packs the Claude Desktop extension: paranoid.mcpb holds mcpb/manifest.json, the icon, and connect.mjs and
# bin.mjs exactly as they are in this repository.
set -euo pipefail
cd "$(dirname "$0")/.."
rm -rf build/mcpb && mkdir -p build/mcpb/server
cp mcpb/manifest.json mcpb/icon.png build/mcpb/
cp connect.mjs bin.mjs build/mcpb/server/
npx -y @anthropic-ai/mcpb@2.1.2 validate build/mcpb/manifest.json
npx -y @anthropic-ai/mcpb@2.1.2 pack build/mcpb paranoid.mcpb
shasum -a 256 paranoid.mcpb build/mcpb/server/connect.mjs
