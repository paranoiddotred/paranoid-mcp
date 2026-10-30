// Checks bin.mjs, the launcher npx and the Claude Desktop extension run: it must start the MCP server with or
// without PARANOID_CODE, save a pasted membership the way connect.mjs does, never lower a question counter or
// drop unanswered keys, keep a different membership aside, and refuse a malformed code without touching anything.
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { existsSync, mkdtempSync, readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const BIN = fileURLToPath(new URL("../bin.mjs", import.meta.url));

/** Runs bin.mjs mcp, asks for tools/list, and returns the tool names (or the exit code if it stops first). */
function listTools(home, code) {
  const env = { ...process.env, PARANOID_HOME: home };
  delete env.PARANOID_CODE;
  if (code !== undefined) env.PARANOID_CODE = code;
  const child = spawn(process.execPath, [BIN, "mcp"], { env });
  child.stdin.write(JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2024-11-05", capabilities: {}, clientInfo: { name: "bin-test", version: "1" } } }) + "\n");
  child.stdin.write(JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/list" }) + "\n");
  return new Promise((resolve, reject) => {
    let out = "", err = "";
    const timer = setTimeout(() => { child.kill(); reject(new Error(`no answer:\n${out}\n${err}`)); }, 20_000);
    child.stderr.on("data", (c) => (err += c));
    child.stdout.on("data", (c) => {
      out += c;
      const reply = out.split("\n").slice(0, -1).map((l) => JSON.parse(l)).find((m) => m.id === 2);
      if (reply) { clearTimeout(timer); child.kill(); resolve({ tools: reply.result.tools.map((t) => t.name).sort() }); }
    });
    child.on("exit", (code) => { clearTimeout(timer); resolve({ exit: code, err }); });
  });
}
const state = (home) => JSON.parse(readFileSync(join(home, "connector.json"), "utf8"));
const TOOLS = ["ask", "balance", "buy", "models"];

// Without a code it is plain connect.mjs.
{
  const home = mkdtempSync(join(tmpdir(), "paranoid-bin-"));
  assert.deepEqual((await listTools(home)).tools, TOOLS);
  assert.equal(existsSync(join(home, "connector.json")), false);
  for (const empty of ["", "  ", "${user_config.connector_code}"]) {
    assert.deepEqual((await listTools(home, empty)).tools, TOOLS, JSON.stringify(empty));
    assert.equal(existsSync(join(home, "connector.json")), false);
  }
  console.log("ok: without PARANOID_CODE, or with an empty settings field, it starts connect.mjs and saves nothing");
}

const home = mkdtempSync(join(tmpdir(), "paranoid-bin-"));
assert.deepEqual((await listTools(home, "00012345.7")).tools, TOOLS);
assert.deepEqual(state(home), { secret: "12345", next: 7, pending: [] });
assert.equal(statSync(join(home, "connector.json")).mode & 0o777, 0o600);
console.log("ok: a pasted code is saved like connect.mjs saves it, readable only by you");

writeFileSync(join(home, "connector.json"), JSON.stringify({ secret: "12345", next: 20, pending: [{ start: 18, cost: 2, x: "99" }] }));
assert.deepEqual((await listTools(home, "12345.7")).tools, TOOLS);
assert.deepEqual(state(home), { secret: "12345", next: 20, pending: [{ start: 18, cost: 2, x: "99" }] });
console.log("ok: starting again with an older code never lowers the counter or drops an unanswered key");

assert.deepEqual((await listTools(home, "12345.31")).tools, TOOLS);
assert.deepEqual(state(home), { secret: "12345", next: 31, pending: [{ start: 18, cost: 2, x: "99" }] });
console.log("ok: a newer code moves the counter up and keeps the unanswered key");

assert.deepEqual((await listTools(home, "777.0")).tools, TOOLS);
assert.deepEqual(state(home), { secret: "777", next: 0, pending: [] });
const kept = readdirSync(home).filter((f) => f.startsWith("connector.json."));
assert.equal(kept.length, 1);
assert.equal(JSON.parse(readFileSync(join(home, kept[0]), "utf8")).secret, "12345");
console.log("ok: a different membership is saved and the old one is kept beside it");

for (const bad of ["abc.1", "12345", "0.4", "12.x", "-5.1"]) {
  const before = readFileSync(join(home, "connector.json"), "utf8");
  const run = await listTools(home, bad);
  assert.equal(run.exit, 1, bad);
  assert.match(run.err, /not a connector code/);
  assert.equal(readFileSync(join(home, "connector.json"), "utf8"), before);
}
console.log("ok: a malformed code stops it with a clear message and changes nothing");
