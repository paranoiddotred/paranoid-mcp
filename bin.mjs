#!/usr/bin/env node
// What `npx github:paranoiddotred/paranoid-mcp` and the Claude Desktop extension run. It starts connect.mjs
// unchanged. When PARANOID_CODE holds the connector code from the Keys tab on paranoid.red, it first saves that
// membership the way pasting the code into `node connect.mjs` does, so clients that cannot show a prompt, like
// Claude Desktop, can be set up from a settings field.
import { chmodSync, existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

// A settings field left empty can arrive as "" or as its unreplaced "${user_config...}" placeholder.
for (const name of ["PARANOID_CODE", "PARANOID_PAYER"]) {
  const value = process.env[name]?.trim();
  if (!value || value.startsWith("${")) delete process.env[name];
}

const code = process.env.PARANOID_CODE?.trim();
if (code) {
  const [a, b] = code.split(".");
  if (!/^\d+$/.test(a ?? "") || !/^\d+$/.test(b ?? "") || BigInt(a) === 0n) {
    console.error("PARANOID_CODE is not a connector code. Copy it from the Keys tab on paranoid.red: it looks like <digits>.<digits>.");
    process.exit(1);
  }
  const secret = BigInt(a).toString();
  const next = Number(b);
  const home = process.env.PARANOID_HOME ?? join(homedir(), ".paranoid");
  const file = join(home, "connector.json");
  const had = existsSync(file) ? JSON.parse(readFileSync(file, "utf8")) : null;
  if (had?.secret === secret) {
    // The same membership runs on: keep its counter and its unanswered keys, and only ever move the counter up.
    if (next > Number(had.next)) writeFileSync(file, JSON.stringify({ ...had, next }), { mode: 0o600 });
  } else {
    // A different membership that was here is kept beside the new one, never overwritten.
    if (had) renameSync(file, `${file}.${Date.now()}`);
    mkdirSync(home, { recursive: true, mode: 0o700 });
    writeFileSync(file, JSON.stringify({ secret, next, pending: [] }), { mode: 0o600 });
  }
  chmodSync(file, 0o600);
}
await import("./connect.mjs");
