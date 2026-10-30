// Runs connect.mjs the way a user does, with no dependencies and no real membership: the MCP server
// must list its four tools, and the local OpenAI port must refuse requests that come from web pages.
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { request } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const CONNECTOR = fileURLToPath(new URL("../connect.mjs", import.meta.url));
const home = mkdtempSync(join(tmpdir(), "paranoid-smoke-"));

/** Starts connect.mjs with `input` on stdin and resolves once `ready(output)` returns a value. */
function run(args, env, ready, input = []) {
  const child = spawn(process.execPath, [CONNECTOR, ...args], { env: { ...process.env, PARANOID_HOME: home, ...env } });
  for (const line of input) child.stdin.write(line + "\n");
  return new Promise((resolve, reject) => {
    let out = "";
    const timer = setTimeout(() => { child.kill(); reject(new Error(`no answer in 20 s:\n${out}`)); }, 20_000);
    child.stdout.on("data", (chunk) => {
      out += chunk;
      const value = ready(out);
      if (value) { clearTimeout(timer); resolve({ child, value }); }
    });
    child.on("exit", (code) => { clearTimeout(timer); reject(new Error(`connect.mjs exited with ${code}:\n${out}`)); });
  });
}

// The MCP server answers tools/list with ask, balance, buy and models.
const reply = (out) => out.split("\n").slice(0, -1).map((line) => JSON.parse(line)).find((m) => m.id === 2);
const mcp = await run(["mcp"], {}, reply, [
  JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2024-11-05", capabilities: {}, clientInfo: { name: "smoke", version: "1" } } }),
  JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/list" }),
]);
mcp.child.kill();
assert.deepEqual(mcp.value.result.tools.map((t) => t.name).sort(), ["ask", "balance", "buy", "models"]);
console.log("ok: the MCP server lists ask, balance, buy and models");

// The local port serves programs on this computer and refuses web pages. The membership is made up,
// so nothing can be spent even if a check failed.
writeFileSync(join(home, "connector.json"), JSON.stringify({ secret: "12345", next: 0 }));
const port = 40_000 + Math.floor(Math.random() * 20_000);
const proxy = await run([], { PARANOID_PORT: String(port) }, (out) => out.includes("PARANOID connector on"));
const status = (method, path, headers) =>
  new Promise((resolve, reject) => {
    const req = request({ host: "127.0.0.1", port, method, path, headers }, (res) => { res.resume(); resolve(res.statusCode); });
    req.on("error", reject);
    req.end(method === "POST" ? "{}" : undefined);
  });
try {
  for (const [who, headers] of [
    ["a web page", { origin: "https://example.com" }],
    ["a page that hides its origin", { origin: "null" }],
    ["a domain rebound to this computer", { host: `example.com:${port}` }],
    ["a look-alike of localhost", { origin: "http://localhost.example.com" }],
  ]) {
    assert.equal(await status("POST", "/v1/chat/completions", { "content-type": "text/plain", ...headers }), 403, who);
  }
  assert.notEqual(await status("GET", "/v1/models", {}), 403, "a program on this computer");
  assert.notEqual(await status("GET", "/v1/models", { origin: "http://localhost:3000" }), 403, "a page on this computer");
  console.log("ok: the local port refuses web pages and serves this computer");
} finally {
  proxy.child.kill();
}

// A proxy that fetch would ignore stops the connector instead of letting requests leave from this address.
const ignored = spawn(process.execPath, [CONNECTOR, "mcp"], { env: { ...process.env, PARANOID_HOME: home, HTTPS_PROXY: "http://127.0.0.1:9", NODE_USE_ENV_PROXY: "" } });
let said = "";
ignored.stderr.on("data", (chunk) => { said += chunk; });
const code = await new Promise((resolve) => ignored.on("exit", resolve));
assert.equal(code, 1);
assert.match(said, /would not go through it/);
console.log("ok: a proxy that would be ignored stops the connector");
