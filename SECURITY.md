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
  requests together through their keys or tell which member sent them.
- A question number is written to disk before its proof exists, so the same number is never offered twice,
  even after a crash. The public list of spent questions is read before every key, so a number another device
  already spent is skipped instead of slashing the membership. If a proof fails before anything is sent, the
  numbers are given back. If the gateway refuses a key because the member list changed, the same numbers are
  proven again with the same random value, which gives the gateway the very same points and costs nothing.
- The prover is snarkjs 0.7.6 exactly as published on npm (`build/snarkjs.min.js`, SHA-256 `3f61bbd9…`), and
  the circuit files are the ones published in [paranoiddotred/paranoid](https://github.com/paranoiddotred/paranoid)
  (`build/request_js/request.wasm`, `build/request.zkey`). Their SHA-256 hashes are written into `connect.mjs`,
  and nothing runs unless the downloaded files match.
- The prover runs in a separate JavaScript realm that holds no Node.js object: no network, no files, no
  process, and nothing that leads back to them. The secret goes in as numbers and only the proof comes out, so
  even a prover that misbehaved could not send the secret anywhere.
- The local OpenAI endpoint refuses requests sent from web pages, so a site you visit cannot spend your
  questions through it.
- `buy` signs one x402 payment, a single USDC transfer, only when your MCP client calls it. It signs only a
  payment in USDC, to the gateway wallet `E9UMSt9mEQoUcoW8ACqaRTPPwyK9KkuD3XBFp8U2V5iX`, for no more than the
  price the program on chain sets plus the 0.30 USDC setup fee. A gateway that asks for anything else gets
  nothing signed.

## What stays visible

- **Your network address.** The proofs hide which member asks, but every request still leaves from your own
  address. To keep that apart as well, send the connector's traffic through Tor or a VPN: on Node.js 22.21, 24
  or newer, set `HTTPS_PROXY` to the proxy (for Tor, its `HTTPTunnelPort`) and `NODE_USE_ENV_PROXY=1`. The web
  app does this for you with its IP shield.
- **Who bought.** Buying shows which wallet paid for a membership, as any payment on Solana does. It never
  shows which questions that membership asks. Pay from a wallet with no history if the purchase itself must
  stay apart from you.
- **Chain reads.** By default the connector reads Solana through paranoid.red's relay. Set `PARANOID_RPC` to
  your own node to read the member list, the price and the day straight from the chain.
