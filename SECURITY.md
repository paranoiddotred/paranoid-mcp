# Security

Scope: `connect.mjs`, the connector and MCP server that keeps your PARANOID secret and makes a proof for
every question. The Solana program and the circuit have their own policy in
[paranoiddotred/paranoid](https://github.com/paranoiddotred/paranoid/blob/main/SECURITY.md).

## Reporting a problem

Please report it privately through **Report a vulnerability** on this repository's Security tab, not in a
public issue. Include the steps to reproduce and the client you used.

## What it protects

- The secret that owns your questions stays in `~/.paranoid/connector.json`, readable only by you. It is
  asked for on first run instead of taken from the command line, so it never lands in shell history.
- Every request gets a key made for it alone, with a new random value, so the gateway cannot tie two
  requests together.
- A question number is written to disk before its proof exists, so the same number is never offered twice,
  even after a crash. The public list of spent questions is read before every key, so a number another device
  already spent is skipped instead of slashing the membership.
- The prover and circuit files are checked against SHA-256 hashes written into `connect.mjs` before anything
  runs.
- The local OpenAI endpoint refuses requests sent from web pages, so a site you visit cannot spend your
  questions through it.
- `buy` signs one x402 payment, a single USDC transfer to the gateway, and only when your MCP client calls it.
