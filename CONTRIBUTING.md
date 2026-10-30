# Contributing

Thank you for looking. Bug reports, fixes and reports of how it behaves in your MCP client are all welcome.

## Before you open a pull request

1. `connect.mjs` must stay one file with no dependencies that runs on Node.js 20 or newer. Check it with
   `node --check connect.mjs` and run `node test/smoke.mjs` and `node test/bin.mjs`, which CI also runs on Node.js 20, 22 and 24.
2. Try the change in a real client. `claude mcp add paranoid -- node $PWD/connect.mjs mcp` adds it to Claude
   Code; the four tools (ask, models, balance, buy) should list and answer.
3. Keep one change per pull request, and write commit messages as
   [conventional commits](https://www.conventionalcommits.org), for example `fix: keep the old membership when a purchase is refused`.

The hashes of the prover and circuit files near the top of `connect.mjs` must match the files paranoid.red
serves. Do not change them by hand. The program and the circuit live in
[paranoiddotred/paranoid](https://github.com/paranoiddotred/paranoid).

## Security problems

Please do not open a public issue. Use **Report a vulnerability** on the Security tab, as SECURITY.md
explains.
