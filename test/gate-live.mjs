// Checks the connector's chip check and sealing against the live gateway, with a stand-in for each party that
// could lie on the way: the site (it hands over the chip's proof), the Solana RPC (it hands over the list of
// approved builds) and the relay (it carries the sealed blobs). Each stand-in passes the real traffic through and
// changes one thing; the connector must refuse every change before anything is sent, or throw the answer away.
// No membership is needed and no question is spent: `check` sends a sealed GET /api/v1/models.
//   node test/gate-live.mjs
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { cpSync, mkdirSync, mkdtempSync } from "node:fs";
import http from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const CONNECTOR = fileURLToPath(new URL("../connect.mjs", import.meta.url));
const SITE = "https://paranoid.red";
const RPC = "https://api.mainnet-beta.solana.com";
const RELAY = "https://relay.oblivious.network/potent-sky-71";
const home = mkdtempSync(join(tmpdir(), "paranoid-gate-"));
// The Intel verifier is not on paranoid.red until the site ships it; until then use the copies fetch-zk.sh made.
mkdirSync(join(home, "zk"));
for (const f of ["dcap-qvl-web.js", "dcap-qvl-web_bg.wasm"]) cpSync(fileURLToPath(new URL(`../zk/${f}`, import.meta.url)), join(home, "zk", f));

let mode = "";
const read = (req) => new Promise((ok) => { const p = []; req.on("data", (c) => p.push(c)); req.on("end", () => ok(Buffer.concat(p))); });
function serve(handler) {
  const s = http.createServer(async (req, res) => {
    try { await handler(req, res, await read(req)); } catch (e) { res.writeHead(502); res.end(String(e)); }
  });
  return new Promise((ok) => s.listen(0, "127.0.0.1", () => ok({ s, url: `http://127.0.0.1:${s.address().port}` })));
}

// The site: passes everything through, but can change the chip's proof.
const site = await serve(async (req, res) => {
  const up = await fetch(SITE + req.url);
  let body = Buffer.from(await up.arrayBuffer());
  if (req.url.startsWith("/api/gate/attest") && mode.startsWith("site:")) {
    const a = JSON.parse(body);
    if (mode === "site:compose") a.app_compose = a.app_compose.replace("services", "services ");
    if (mode === "site:nonce") a.nonce = "00".repeat(32);
    if (mode === "site:key") a.key_config = Buffer.from(Buffer.from(a.key_config, "base64").map((b, i) => (i === 10 ? b ^ 1 : b))).toString("base64");
    if (mode === "site:quote") a.quote = a.quote.slice(0, 600) + (a.quote[600] === "0" ? "1" : "0") + a.quote.slice(601);
    if (mode === "site:collateral") delete a.collateral;
    body = Buffer.from(JSON.stringify(a));
  }
  res.writeHead(up.status, { "content-type": up.headers.get("content-type") ?? "application/json" });
  res.end(body);
});

// The Solana RPC: passes everything through, but can change the record account.
const rpc = await serve(async (req, res, body) => {
  if (mode === "rpc:down") { res.writeHead(503); return res.end(); }
  const j = await (await fetch(RPC, { method: "POST", headers: { "content-type": "application/json" }, body })).json();
  const v = j.result?.value;
  if (v && mode.startsWith("rpc:")) {
    const d = Buffer.from(v.data[0], "base64");
    if (mode === "rpc:authority") d[5] ^= 1;
    if (mode === "rpc:build") for (let i = 0; i < d[37]; i++) d[38 + i * 240 + 16] ^= 1; // each build's compose hash
    if (mode === "rpc:owner") v.owner = "11111111111111111111111111111111";
    v.data[0] = d.toString("base64");
  }
  res.writeHead(200, { "content-type": "application/json" });
  res.end(JSON.stringify(j));
});

// The relay: carries the sealed blob to the real relay and the answer back, and keeps what it saw.
let seen = Buffer.alloc(0);
const relay = await serve(async (req, res, body) => {
  seen = Buffer.concat([seen, body]);
  const up = await fetch(RELAY, { method: "POST", headers: { "content-type": req.headers["content-type"], incremental: "?1" }, body });
  let answer = Buffer.from(await up.arrayBuffer());
  seen = Buffer.concat([seen, answer]);
  if (mode === "relay:cut") answer = answer.subarray(0, answer.length - 40);
  if (mode === "relay:flip") answer[answer.length - 20] ^= 1;
  res.writeHead(up.status, { "content-type": up.headers.get("content-type") ?? "" });
  res.end(answer);
});

function check(env) {
  return new Promise((ok) => {
    const c = spawn(process.execPath, [CONNECTOR, "check"], {
      env: { ...process.env, PARANOID_HOME: home, PARANOID_SITE: site.url, PARANOID_LIST_RPC: rpc.url, PARANOID_RELAYS: relay.url, ...env },
    });
    let out = "";
    c.stdout.on("data", (d) => (out += d));
    c.stderr.on("data", (d) => (out += d));
    c.on("exit", (code) => ok({ code, out: out.trim() }));
  });
}

let passed = 0;
async function expect(name, m, env, code, text) {
  mode = m;
  const r = await check(env);
  assert.equal(r.code, code, `${name}: exit ${r.code}\n${r.out}`);
  assert.match(r.out, text, `${name}\n${r.out}`);
  passed++;
  console.log(`ok ${passed} ${name}: ${r.out.split("\n").at(-1)}`);
}

await expect("honest parties", "", {}, 0, /build v1\.2\.1 approved on Solana[\s\S]*chip answered: \d+ models/);
assert.ok(seen.length > 0 && !seen.includes(Buffer.from("/api/v1/models")) && !seen.includes(Buffer.from('"object"')), "the relay saw the request or the answer in the clear");
console.log(`ok ${++passed} the relay carried ${seen.length} bytes and none of them was readable`);
await expect("site changes the compose file", "site:compose", {}, 1, /setup does not match its boot log/);
await expect("site answers for another nonce", "site:nonce", {}, 1, /not the one the gateway's chip vouches for/);
await expect("site swaps in its own sealing key", "site:key", {}, 1, /not the one the gateway's chip vouches for/);
await expect("site changes one byte of the quote", "site:quote", {}, 1, /Intel's signature|chip vouches|boot log|not on PARANOID's list/);
await expect("site withholds Intel's collateral", "site:collateral", {}, 1, /collateral .* not available/);
await expect("RPC says another key wrote the list", "rpc:authority", {}, 1, /not the one PARANOID's multisig writes/);
await expect("RPC hands over an account of another program", "rpc:owner", {}, 1, /not the one PARANOID's multisig writes/);
await expect("RPC changes the approved builds", "rpc:build", {}, 1, /not on PARANOID's list on Solana/);
await expect("RPC is down", "rpc:down", {}, 1, /could not be read from Solana/);
await expect("first relay is down, the second carries it", "", { PARANOID_RELAYS: `http://127.0.0.1:9,${relay.url}` }, 0, /chip answered/);
await expect("every relay is down", "", { PARANOID_RELAYS: "http://127.0.0.1:9" }, 1, /No relay answered/);
await expect("relay cuts the answer short", "relay:cut", {}, 1, /cut short|changed on the way/);
await expect("relay changes a byte of the answer", "relay:flip", {}, 1, /changed on the way/);

console.log(`${passed}/${passed} passed`);
for (const x of [site, rpc, relay]) x.s.close();
