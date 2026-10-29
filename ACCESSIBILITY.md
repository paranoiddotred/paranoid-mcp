# Accessibility

PARANOID MCP is a command-line program and a set of MCP tools, so everything it says is plain text.

- Every message is a full sentence on its own line, with no meaning carried by color, symbols or layout, so it
  reads the same in a screen reader, a braille display or a log file.
- The MCP tools take and return text only. How they are shown and read aloud is up to your MCP client
  (Claude Code, Cursor or another), and their own accessibility settings apply.
- It runs anywhere Node.js 20 or newer runs: macOS, Linux and Windows, in any terminal.
- Nothing has a time limit except one: an x402 payment must be sent within about a minute of the price being
  quoted, which is a Solana rule. If it expires, calling `buy` again gets a fresh quote.

## Reporting a barrier

If something here is hard to use with your setup, please open an issue that says what you tried, which
assistive technology and client you use, and what got in the way.
