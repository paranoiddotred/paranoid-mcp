# Security

Scope: `connect.mjs`, the connector and MCP server that keeps your PARANOID secret and makes a proof for
every question. The Solana program and the circuit have their own policy in
[paranoiddotred/paranoid](https://github.com/paranoiddotred/paranoid/blob/main/SECURITY.md).

## Reporting a problem

Please report it privately through **Report a vulnerability** on this repository's Security tab, not in a
public issue. Include the steps to reproduce and the client you used.

## What it protects

- The secret that owns your questions stays in `~/.paranoid/connector.json`, readable only by you (owner-only
  file permissions on macOS and Linux; on Windows the file sits in your user profile). It is asked for on first
  run instead of taken from the command line, so it never lands in shell history.
- Every request gets a key made for it alone, with a new random value, so the gateway cannot tie two
  requests together through their keys or tell which member sent them. Every request also goes out on a
  connection of its own, so two requests never share a socket either.
- A question number is written to disk before its proof exists, so the same number is never offered twice,
  even after a crash. The public list of spent questions is read before every key, so a number another device
  already spent is skipped instead of slashing the membership. If a proof fails before anything is sent, the
  numbers are given back. If the gateway refuses a key because the member list changed, the same numbers are
  proven again with the same random value, which gives the gateway the very same points and costs nothing. A
  key the gateway never answered, because of a network or server error, keeps its numbers for the next request
  in the same way.
- The prover is snarkjs 0.7.6 exactly as published on npm (`build/snarkjs.min.js`, SHA-256 `3f61bbd9…`), and
  the circuit files are the ones published in [paranoiddotred/paranoid](https://github.com/paranoiddotred/paranoid)
  (`build/request_js/request.wasm`, `build/request.zkey`). Their SHA-256 hashes are written into `connect.mjs`,
  and nothing runs unless the downloaded files match.
- The prover runs in a separate JavaScript realm that holds no Node.js object, so it cannot open a
  connection, a file or a process of its own. The secret goes in as numbers and the proof is the only thing
  that comes out. What keeps that proof honest is the pin above: the prover is the published snarkjs 0.7.6, byte
  for byte.
- The local OpenAI endpoint refuses requests sent from web pages, so a site you visit cannot spend your
  questions through it.
- `buy` signs one x402 payment, a single USDC transfer, only when your MCP client calls it. It signs only a
  payment in USDC, to the gateway wallet `E9UMSt9mEQoUcoW8ACqaRTPPwyK9KkuD3XBFp8U2V5iX`, for no more than the
  price the program on chain sets plus the 0.30 USDC setup fee. That price is read from Solana through
  `PARANOID_RPC` if you set one and otherwise through a public Solana node, never through paranoid.red, and the
  account it comes from must belong to the PARANOID program. A gateway that asks for anything else, or sends a
  quote that cannot be read, gets nothing signed.

## What stays visible

- **Your network address.** The proofs hide which member asks, but every request still leaves from your own
  address. To keep that apart as well, send the connector's traffic through Tor or a VPN: on Node.js 22.21, 24
  or newer, set `HTTPS_PROXY` to the proxy (for Tor, its `HTTPTunnelPort`) and `NODE_USE_ENV_PROXY=1`. This uses
  Node.js's own proxy support, and CI checks on every push that the requests then go through the proxy. If a
  proxy is set but this Node.js would send requests around it, the connector refuses to start. The web
  app does this for you with its IP shield.
- **Who bought.** Buying shows which wallet paid for a membership, as any payment on Solana does. It never
  shows which questions that membership asks. Pay from a wallet with no history if the purchase itself must
  stay apart from you.
- **Chain reads.** By default the connector reads Solana through paranoid.red's relay. Set `PARANOID_RPC` to
  your own node to read the member list, the price and the day straight from the chain.
