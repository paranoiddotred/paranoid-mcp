// PARANOID connector: keeps any OpenAI-compatible app connected to PARANOID, with a fresh anonymous key for
// every request. One file, no packages: Node.js 20.18, 22.8 or newer.
//
//   curl -O https://paranoid.red/connect.mjs
//   node connect.mjs          the first run asks for the code from the Keys tab and saves it to ~/.paranoid (owner-only)
//   PARANOID_PAYER=wallet.json node connect.mjs buy 500
//                             or, with no site at all: makes a new secret here and pays USDC for 500 questions with x402
//   node connect.mjs mcp      serves the same questions as MCP tools on stdin and stdout (ask, models, balance, buy)
//                             for Claude Code, Cursor and other MCP clients; see /docs/agents
//
// Then point Zed, your app, an agent or curl at http://127.0.0.1:4141/v1. Any API key string works. For each chat
// request the connector proves the model's price in questions from your membership, here on your computer, with
// a new random key, and forwards it to the gateway. Keys never outlive one request, so the day change never breaks
// your app and no two keys share anything that could tie them together. The requests still leave from your own
// network address; to keep that apart from them too, send them through Tor or a VPN (HTTPS_PROXY with
// NODE_USE_ENV_PROXY=1 on Node.js 22.21, 24 or newer).
//
// One membership, one place: after moving your code here, the site forgets it in that browser. Spending the same
// question twice gives the secret away and the membership is slashed, so the connector also reads the public list
// of spent questions before every key and skips anything another device already used.
//
// Built from connect.src.mjs by build.mjs, which embeds the Poseidon constants and pins the prover and circuit hashes.

import http from "node:http";
import vm from "node:vm";
import { createHash, createPrivateKey, randomFillSync, sign } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync, chmodSync, renameSync, unlinkSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { createInterface } from "node:readline/promises";

const SITE = (process.env.PARANOID_SITE ?? "https://paranoid.red").replace(/\/$/, "");
const RPC = process.env.PARANOID_RPC ?? `${SITE}/api/rpc`;
const PROGRAM = process.env.PARANOID_PROGRAM ?? "9JJqzEoDGkTE8CMLATRw7CqFhcyWVegfhFuEeGfBfVGm";
const CONFIG = process.env.PARANOID_CONFIG ?? "EevCQ789SrwghbBHQjVonGFgxNExeqtAcAyJnvuCwuER";
const PORT = Number(process.env.PARANOID_PORT ?? 4141);
const HOME = process.env.PARANOID_HOME ?? join(homedir(), ".paranoid");
const STATE = join(HOME, "connector.json");
// What `buy` agrees to pay: USDC, to this gateway wallet, at most the program's price plus this setup fee.
const USDC = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
const GATEWAY = process.env.PARANOID_GATEWAY ?? "E9UMSt9mEQoUcoW8ACqaRTPPwyK9KkuD3XBFp8U2V5iX";
const SETUP_USDC = 300_000n;

// A proxy you set must actually carry the traffic. fetch follows HTTPS_PROXY only on Node.js 22.21, 24 or newer
// and only with NODE_USE_ENV_PROXY=1; anywhere else it would go straight out from your own address, so stop.
{
  const env = (n) => process.env[n] ?? process.env[n.toLowerCase()];
  if (env("HTTPS_PROXY") || env("HTTP_PROXY") || env("ALL_PROXY")) {
    const [major, minor] = process.versions.node.split(".").map(Number);
    const honoured = (major === 22 && minor >= 21) || major >= 24;
    const on = process.env.NODE_USE_ENV_PROXY === "1" || process.execArgv.includes("--use-env-proxy");
    if (!env("HTTPS_PROXY") || !honoured || !on) {
      console.error("A proxy is set, but this connector's requests would not go through it. Set HTTPS_PROXY (an HTTP proxy, such as Tor's HTTPTunnelPort) and NODE_USE_ENV_PROXY=1, on Node.js 22.21, 24 or newer.");
      process.exit(1);
    }
  }
}
// The prover and the circuit the gateway verifies against. Downloads must match these before anything runs.
const ZK = {
  "snarkjs.min.js": "__SHA_SNARKJS__",
  "request.wasm": "__SHA_WASM__",
  "request.zkey": "__SHA_ZKEY__",
};

// ---- Poseidon over BN254 with circomlib's parameters (inputs 1, 2 and 3), vendored from poseidon-lite 0.3.0 (MIT)

const K = __POSEIDON_CONSTANTS__;
const F = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const decodeK = (s) => BigInt("0x" + Array.from(Uint8Array.from(atob(s), (c) => c.charCodeAt(0)), (x) => x.toString(16).padStart(2, "0")).join(""));
const loadK = (k) => ({ C: k.C.map(decodeK), M: k.M.map((r) => r.map(decodeK)) });
const P1 = loadK(K.t2), P2 = loadK(K.t3), P3 = loadK(K.t4);
const pow5 = (v) => { const o = v * v; return (v * o * o) % F; };
function poseidon(inputs, { C, M }) {
  const t = inputs.length + 1;
  const nP = [56, 57, 56][t - 2];
  let state = [0n, ...inputs.map((x) => ((x % F) + F) % F)];
  for (let x = 0; x < 8 + nP; x++) {
    for (let y = 0; y < t; y++) {
      state[y] = state[y] + C[x * t + y];
      if (x < 4 || x >= 4 + nP || y === 0) state[y] = pow5(state[y]);
    }
    state = M.map((row) => row.reduce((acc, m, i) => acc + m * state[i], 0n) % F);
  }
  return state[0];
}
const poseidon1 = (a) => poseidon(a, P1), poseidon2 = (a) => poseidon(a, P2), poseidon3 = (a) => poseidon(a, P3);

// ---- the member tree, request proofs and the key format (web/lib/paranoid/sdk.ts)

const DEPTH = 20, W = 4;
const fieldToBytes = (v) => Uint8Array.from(v.toString(16).padStart(64, "0").match(/../g), (h) => parseInt(h, 16));
const bytesToField = (b) => BigInt("0x" + (Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("") || "0"));
function randomField() {
  const b = new Uint8Array(31);
  crypto.getRandomValues(b);
  const v = bytesToField(b);
  return v === 0n ? 1n : v;
}
const commitmentOf = (secret) => poseidon1([secret]);
const EXTERNAL = poseidon2([0n, 0x706172616e6f69642e7632n]);
const ticketNullifier = (secret, i) => poseidon1([poseidon3([secret, EXTERNAL, BigInt(i)])]);
const leafOf = (commitment, endEpoch, questions) => poseidon3([commitment, BigInt(endEpoch), BigInt(questions)]);
const ZEROS = [0n];
for (let i = 0; i < DEPTH; i++) ZEROS.push(poseidon2([ZEROS[i], ZEROS[i]]));

function buildTree(leaves) {
  const levels = [new Map([...leaves].filter(([, v]) => v !== 0n))];
  for (let i = 0; i < DEPTH; i++) {
    const next = new Map();
    for (const k of levels[i].keys()) {
      const p = k >> 1;
      if (next.has(p)) continue;
      next.set(p, poseidon2([levels[i].get(2 * p) ?? ZEROS[i], levels[i].get(2 * p + 1) ?? ZEROS[i]]));
    }
    levels.push(next);
  }
  return {
    root: levels[DEPTH].get(0) ?? ZEROS[DEPTH],
    path(index) {
      const pathElements = [], pathIndices = [];
      for (let i = 0; i < DEPTH; i++) {
        pathElements.push(levels[i].get(index ^ 1) ?? ZEROS[i]);
        pathIndices.push(index & 1);
        index >>= 1;
      }
      return { pathElements, pathIndices };
    },
  };
}
const treeOf = (members) => buildTree(new Map(members.filter((m) => m.status === "active").map((m) => [m.leafIndex, leafOf(m.commitment, m.endEpoch, m.questions)])));

async function proveSpend(a, prove) {
  const { pathElements, pathIndices } = a.tree.path(a.leafIndex);
  const { proof, publicSignals } = await prove({
    root: a.tree.root.toString(), epoch: a.epoch, x: a.x.toString(), limit: a.limit, weight: a.weight,
    secret: a.secret.toString(), endEpoch: a.endEpoch, questions: a.questions, start: a.start,
    pathElements: pathElements.map(String), pathIndices,
  });
  const s = publicSignals.map(BigInt); // nullifiers[4], ys[4], root, epoch, x, limit, weight
  const weight = Number(s[12]);
  return { nullifiers: s.slice(0, weight), ys: s.slice(W, W + weight), root: s[8], epoch: Number(s[9]), x: s[10], limit: Number(s[11]), weight, proof };
}

// "sk-paranoid-" + base64url( 1 | n | root 32 | epoch 4 | limit 2 | x 32 | n * (weight 1 | proof 256 | weight * (nullifier 32 | y 32)) )
const proofFields = (p) => [p.pi_a[0], p.pi_a[1], p.pi_b[0][0], p.pi_b[0][1], p.pi_b[1][0], p.pi_b[1][1], p.pi_c[0], p.pi_c[1]].map(BigInt);
function packKey(spends) {
  const h = spends[0];
  const u32 = (v) => Uint8Array.of(v >>> 24, (v >>> 16) & 255, (v >>> 8) & 255, v & 255);
  const parts = [Uint8Array.of(1, spends.length), fieldToBytes(h.root), u32(h.epoch), Uint8Array.of(h.limit >> 8, h.limit & 255), fieldToBytes(h.x)];
  for (const s of spends) {
    parts.push(Uint8Array.of(s.weight), ...proofFields(s.proof).map(fieldToBytes));
    for (let j = 0; j < s.weight; j++) parts.push(fieldToBytes(s.nullifiers[j]), fieldToBytes(s.ys[j]));
  }
  return "sk-paranoid-" + Buffer.concat(parts).toString("base64url");
}

// ---- chain reads over plain JSON-RPC (through the site's relay by default), cached briefly

async function rpc(method, params) {
  const res = await fetch(RPC, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }) });
  const j = await res.json();
  if (j.error) throw new Error(`Solana RPC ${method}: ${j.error.message ?? JSON.stringify(j.error)}`);
  return j.result;
}
const b64 = (s) => new Uint8Array(Buffer.from(s, "base64"));
async function chainNow() {
  const slot = await rpc("getSlot", [{ commitment: "confirmed" }]);
  return (await rpc("getBlockTime", [slot]).catch(() => null)) ?? Math.floor(Date.now() / 1000);
}
let cache = null;
async function chain(fresh = false) {
  if (!fresh && cache && Date.now() - cache.at < 30_000) return cache;
  const [acc, all] = await Promise.all([
    rpc("getAccountInfo", [CONFIG, { encoding: "base64", commitment: "confirmed" }]),
    rpc("getProgramAccounts", [PROGRAM, { encoding: "base64", commitment: "confirmed", filters: [{ dataSize: 94 }] }]),
  ]);
  if (!acc?.value) throw new Error("PARANOID config not found on chain.");
  const c = b64(acc.value.data[0]);
  const cv = new DataView(c.buffer, c.byteOffset, c.byteLength);
  const cfg = { genesis: Number(cv.getBigInt64(41, true)), epochSeconds: cv.getUint32(49, true), rate: cv.getBigUint64(53, true), limit: cv.getUint16(61, true) };
  // Member: disc 8 | bump 1 | depositor 32 | commitment 32 | leaf_index u32 | start_epoch u32 | end_epoch u32 | questions u64 | status u8
  const members = all.map(({ account }) => {
    const d = b64(account.data[0]);
    const v = new DataView(d.buffer, d.byteOffset, d.byteLength);
    return { commitment: bytesToField(d.subarray(41, 73)), leafIndex: v.getUint32(73, true), endEpoch: v.getUint32(81, true), questions: Number(v.getBigUint64(85, true)), status: d[93] === 0 ? "active" : "slashed" };
  });
  return (cache = { at: Date.now(), cfg, members });
}
const epochAt = (cfg, t) => Math.max(0, Math.floor((t - cfg.genesis) / cfg.epochSeconds));

/** One past the last question of this secret the gateway has seen at or after `from` (256 unseen in a row ends
 *  it), or `from` itself. Numbers below `from` are already behind this counter, so they are not hashed again. */
async function seenNext(secret, questions, from) {
  const res = await fetch(`${SITE}/api/v1/used`, { cache: "no-store" });
  if (!res.ok) throw new Error(`Could not read the list of used questions (${res.status}).`);
  const used = new Set((await res.text()).split("\n").filter(Boolean));
  let next = from;
  for (let i = from, gap = 0; i < questions && gap < 256; i++) {
    if (used.has(ticketNullifier(secret, i).toString(16))) { next = i + 1; gap = 0; } else gap++;
  }
  return next;
}

// ---- the prover: the site's own snarkjs build and circuit, checked against the pinned hashes

async function zkFile(name) {
  const path = join(HOME, "zk", name);
  if (!existsSync(path)) {
    mkdirSync(join(HOME, "zk"), { recursive: true, mode: 0o700 });
    const res = await fetch(`${SITE}/zk/${name}`);
    if (!res.ok) throw new Error(`Could not download ${name} (${res.status}).`);
    writeFileSync(path, Buffer.from(await res.arrayBuffer()));
  }
  const data = readFileSync(path);
  const got = createHash("sha256").update(data).digest("hex");
  if (got !== ZK[name]) throw new Error(`${name} does not match the published file. Delete ${path} and start again.`);
  return data;
}
// The prover runs in a context of its own realm (DONT_CONTEXTIFY) that holds no object from this one: no fetch,
// no process, no file access, nothing whose constructor leads back here. The few browser functions snarkjs
// looks for are written inside it, randomness and the circuit files go in as bytes copied into arrays it made,
// and the proof comes out as a string. It cannot open a connection, a file or a process of its own, so the proof
// is the only thing that leaves it, and the prover itself is pinned to the published snarkjs 0.7.6 bytes.
const SANDBOX = `
globalThis.btoa = (s) => { const c = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"; let o = "";
  for (let i = 0; i < s.length; i += 3) { const a = s.charCodeAt(i), b = s.charCodeAt(i + 1), d = s.charCodeAt(i + 2);
    o += c[a >> 2] + c[((a & 3) << 4) | (b >> 4 || 0)] + (i + 1 < s.length ? c[((b & 15) << 2) | (d >> 6 || 0)] : "=") + (i + 2 < s.length ? c[d & 63] : "="); }
  return o; };
globalThis.TextEncoder = class { encode(s = "") { const u = unescape(encodeURIComponent(s)); const a = new Uint8Array(u.length); for (let i = 0; i < u.length; i++) a[i] = u.charCodeAt(i); return a; } };
globalThis.TextDecoder = class { decode(a) { if (!a) return ""; const b = a instanceof Uint8Array ? a : new Uint8Array(a.buffer ?? a, a.byteOffset ?? 0, a.byteLength); let s = ""; for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i]); try { return decodeURIComponent(escape(s)); } catch { return s; } } };
globalThis.setTimeout = (f, ...args) => { Promise.resolve().then(() => f(...args)); return 0; };
globalThis.__pool = new Uint8Array(1 << 16); globalThis.__pos = 0;
globalThis.crypto = { getRandomValues(a) { const b = new Uint8Array(a.buffer, a.byteOffset, a.byteLength); for (let i = 0; i < b.length; i++) { if (__pos >= __pool.length) throw new Error("random pool empty"); b[i] = __pool[__pos++]; } return a; } };
`;
let snark = null;
function prover() {
  return (snark ??= (async () => {
    if (!vm.constants?.DONT_CONTEXTIFY) throw new Error("The connector needs Node.js 20.18, 22.8 or newer.");
    const [js, wasm, zkey] = await Promise.all(Object.keys(ZK).map(zkFile));
    const ctx = vm.createContext(vm.constants.DONT_CONTEXTIFY);
    const run = (code) => vm.runInContext(code, ctx);
    run(SANDBOX);
    const into = (name, bytes) => run(`globalThis.${name} = new Uint8Array(${bytes.length}); ${name}`).set(bytes);
    into("__wasm", wasm);
    into("__zkey", zkey);
    run(js.toString("utf8"));
    return async (input) => {
      randomFillSync(run("__pos = 0; __pool"));
      return JSON.parse(await run(`snarkjs.groth16.fullProve(JSON.parse(${JSON.stringify(JSON.stringify(input))}), { type: "mem", data: __wasm }, { type: "mem", data: __zkey }).then((r) => JSON.stringify(r))`));
    };
  })());
}

// ---- the secret and its question counter, kept only in ~/.paranoid/connector.json

function load() {
  if (!existsSync(STATE)) return null;
  const j = JSON.parse(readFileSync(STATE, "utf8"));
  const p = j.pending;
  return { secret: BigInt(j.secret), next: Number(j.next), pending: p ? { start: Number(p.start), cost: Number(p.cost), x: BigInt(p.x) } : null };
}
function save(s) {
  mkdirSync(HOME, { recursive: true, mode: 0o700 });
  const pending = s.pending ? { start: s.pending.start, cost: s.pending.cost, x: s.pending.x.toString() } : undefined;
  writeFileSync(STATE, JSON.stringify({ secret: s.secret.toString(), next: s.next, pending }), { mode: 0o600 });
  chmodSync(STATE, 0o600);
}
function parseCode(text) {
  const [a, b] = String(text).trim().split(".");
  const secret = /^\d+$/.test(a ?? "") ? BigInt(a) : 0n;
  const next = b === undefined ? NaN : Number(b);
  if (secret <= 0n || !Number.isInteger(next) || next < 0) throw new Error("That is not a connector code. Copy it from the Keys tab on the site: it looks like <digits>.<digits>.");
  return { secret, next };
}

// ---- buying questions with x402, for an agent with nothing but a Solana wallet (web/lib/paranoid/x402.ts)

const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
function fromB58(s) {
  let n = 0n;
  for (const c of s) {
    const i = B58.indexOf(c);
    if (i < 0) throw new Error(`Not a Solana address: ${s}`);
    n = n * 58n + BigInt(i);
  }
  const hex = n === 0n ? "" : n.toString(16);
  return Uint8Array.from([...Array(s.match(/^1*/)[0].length).fill(0), ...Buffer.from(hex.padStart(hex.length + (hex.length & 1), "0"), "hex")]);
}
function toB58(b) {
  let n = bytesToField(b), s = "";
  while (n > 0n) { s = B58[Number(n % 58n)] + s; n /= 58n; }
  for (const x of b) { if (x) break; s = "1" + s; }
  return s;
}

// A program address must not be a point on ed25519: it is one when (y^2 - 1) / (d y^2 + 1) is a square mod p.
const EP = 2n ** 255n - 19n;
const modpow = (b, e) => { let r = 1n; b %= EP; for (; e > 0n; e >>= 1n, b = (b * b) % EP) if (e & 1n) r = (r * b) % EP; return r; };
const ED = (EP - ((121665n * modpow(121666n, EP - 2n)) % EP)) % EP;
function onCurve(b) {
  const y = bytesToField(Uint8Array.from(b).reverse()) & ((1n << 255n) - 1n);
  if (y >= EP) return false;
  const y2 = (y * y) % EP;
  const x2 = (((y2 - 1n + EP) % EP) * modpow((ED * y2 + 1n) % EP, EP - 2n)) % EP;
  return x2 === 0n || modpow(x2, (EP - 1n) / 2n) === 1n;
}
function programAddress(seeds, program) {
  for (let bump = 255; bump >= 0; bump--) {
    const h = createHash("sha256").update(Buffer.concat([...seeds, Buffer.of(bump), program, Buffer.from("ProgramDerivedAddress")])).digest();
    if (!onCurve(h)) return new Uint8Array(h);
  }
  throw new Error("no program address");
}
const TOKEN = fromB58("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
const ataOf = (owner, mint) => programAddress([owner, TOKEN, mint], fromB58("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL"));

/** A Solana keypair file (the 64-number JSON the Solana CLI writes) as a public key and a signer. */
function wallet(path) {
  const k = Uint8Array.from(JSON.parse(readFileSync(path, "utf8")));
  const key = createPrivateKey({ key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), k.subarray(0, 32)]), format: "der", type: "pkcs8" });
  return { pub: k.subarray(32, 64), sign: (m) => new Uint8Array(sign(null, m, key)) };
}

const shortvec = (n) => { const o = []; do { let b = n & 0x7f; n >>= 7; if (n) b |= 0x80; o.push(b); } while (n); return o; };
const u32le = (v) => { const b = Buffer.alloc(4); b.writeUInt32LE(v); return [...b]; };
const u64le = (v) => { const b = Buffer.alloc(8); b.writeBigUInt64LE(BigInt(v)); return [...b]; };

/** The x402 `exact` payment: compute budget, one USDC TransferChecked to the gateway, the memo it asked for.
 *  Signed by the wallet only; the gateway adds its fee payer signature when it settles. */
function paymentTx(req, payer, blockhash) {
  const mint = fromB58(req.asset);
  // Signers first (fee payer writable, wallet read-only), then the writable token accounts, then the read-only rest.
  const keys = [fromB58(req.extra.feePayer), payer.pub, ataOf(payer.pub, mint), ataOf(fromB58(req.payTo), mint), mint, TOKEN,
    fromB58("ComputeBudget111111111111111111111111111111"), fromB58("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr")];
  const ix = (program, accounts, data) => [program, ...shortvec(accounts.length), ...accounts, ...shortvec(data.length), ...data];
  const ixs = [ix(6, [], [2, ...u32le(40_000)]), ix(6, [], [3, ...u64le(1)]), ix(5, [2, 4, 3, 1], [12, ...u64le(req.amount), 6]), ix(7, [], [...Buffer.from(req.extra.memo, "utf8")])];
  const message = Uint8Array.from([0x80, 2, 1, 4, ...shortvec(keys.length), ...keys.flatMap((k) => [...k]), ...blockhash, ...shortvec(ixs.length), ...ixs.flat(), 0]);
  return Buffer.from([...shortvec(2), ...new Uint8Array(64), ...payer.sign(message), ...message]).toString("base64");
}

/** Makes a new secret here, pays for `questions` with the wallet in PARANOID_PAYER, and keeps the secret for the connector. */
async function buy(questions) {
  if (!process.env.PARANOID_PAYER) throw new Error("Set PARANOID_PAYER to a Solana keypair file: the wallet that pays the USDC.");
  if (!Number.isInteger(questions)) throw new Error("Say how many questions to buy: node connect.mjs buy 500");
  const payer = wallet(process.env.PARANOID_PAYER);
  const secret = randomField();
  const url = `${SITE}/api/x402/join?questions=${questions}&commitment=${commitmentOf(secret).toString(16)}`;
  const first = await fetch(url, { method: "POST" });
  if (first.status !== 402) throw new Error(`Could not get a price (${first.status}): ${(await first.json().catch(() => ({}))).error ?? ""}`);
  const required = JSON.parse(Buffer.from(first.headers.get("payment-required"), "base64").toString("utf8"));
  const req = required.accepts.find((a) => a.scheme === "exact" && a.network.startsWith("solana:"));
  // The wallet signs only what this computer expects: USDC, to the gateway it knows, at no more than the price
  // the program on chain sets plus the published setup fee. A gateway that asked for more gets nothing.
  const { cfg } = await chain(true);
  const most = BigInt(questions) * cfg.rate + SETUP_USDC;
  if (!req || req.asset !== USDC || req.payTo !== GATEWAY || req.extra?.feePayer !== GATEWAY)
    throw new Error(`The gateway asked for a payment this connector does not recognise (to ${req?.payTo}, in ${req?.asset}). Nothing was signed.`);
  if (BigInt(req.amount) > most) throw new Error(`The gateway asked ${Number(req.amount) / 1e6} USDC for ${questions} questions, more than the ${Number(most) / 1e6} USDC the program sets. Nothing was signed.`);
  const usdc = (await rpc("getTokenAccountBalance", [toB58(ataOf(payer.pub, fromB58(req.asset))), { commitment: "confirmed" }]).catch(() => null))?.value.amount ?? "0";
  if (BigInt(usdc) < BigInt(req.amount)) throw new Error(`${questions} questions cost ${Number(req.amount) / 1e6} USDC and wallet ${toB58(payer.pub)} has ${Number(usdc) / 1e6}.`);
  // The secret is written before paying, so a crash after the payment cannot lose what it buys. A membership
  // that was here is kept beside it.
  const kept = existsSync(STATE) ? `${STATE}.${Date.now()}` : null;
  if (kept) renameSync(STATE, kept);
  save({ secret, next: 0 });
  const blockhash = req.extra.recentBlockhash ?? (await rpc("getLatestBlockhash", [{ commitment: "confirmed" }])).value.blockhash;
  const payload = { x402Version: 2, resource: required.resource, accepted: req, payload: { transaction: paymentTx(req, payer, fromB58(blockhash)) } };
  console.log(`Paying ${Number(req.amount) / 1e6} USDC for ${questions} questions from ${toB58(payer.pub)}...`);
  const paid = await fetch(url, { method: "POST", headers: { "payment-signature": Buffer.from(JSON.stringify(payload)).toString("base64") } });
  const body = await paid.json().catch(() => ({}));
  if (!paid.ok) {
    // Refused before any money moved (a 500 means it moved, so the new secret must stay): put the old membership back.
    if (paid.status < 500 && kept) renameSync(kept, STATE);
    throw new Error(`The payment did not go through (${paid.status}): ${body.error ?? "no reason given"}`);
  }
  console.log(`Bought ${body.questions} questions. Payment ${body.payment}`);
  state = { secret, next: 0 };
  cache = null;
  if (kept) {
    // The membership that was here stays on disk only while it still has questions.
    const old = JSON.parse(readFileSync(kept, "utf8"));
    const me = (await chain(true)).members.find((m) => m.commitment === commitmentOf(BigInt(old.secret)));
    const left = me && me.status === "active" ? me.questions - (await seenNext(BigInt(old.secret), me.questions, Number(old.next))) : 0;
    if (left > 0) console.log(`The membership that was here still has ${left} questions. Its code is kept in ${kept}.`);
    else unlinkSync(kept);
  }
  return body;
}

// ---- one fresh key per request

let models = null;
async function costOf(model) {
  if (!models || Date.now() - models.at > 300_000) {
    const j = await (await fetch(`${SITE}/api/v1/models`)).json();
    models = { at: Date.now(), list: j.data.map((m) => ({ id: m.id, cost: m.cost ?? 1 })) };
  }
  // The gateway sends an unknown model name to the default model, which is listed first.
  return (models.list.find((m) => m.id === model) ?? models.list[0])?.cost ?? 1;
}

let state, warned = false;
const sending = new Set(); // starts of keys on their way to the gateway right now
/** A key for `cost` questions. With `again` (a refused key's numbers and x) it proves the same numbers with the
 *  same x: y = secret + a1 * x does not depend on the member list, so resending gives the gateway the very same
 *  points and nothing new, and a refusal never costs questions. */
async function freshKey(cost, fresh = false, again = null) {
  const { cfg, members } = await chain(fresh);
  const me = members.find((m) => m.commitment === commitmentOf(state.secret));
  if (!me) throw new Error("No membership on chain matches this code.");
  if (me.status !== "active") throw new Error("This membership is not active (it was slashed).");
  const epoch = epochAt(cfg, await chainNow());
  if (epoch > me.endEpoch) throw new Error("This membership's questions have expired. Top up on the site.");
  // A key the gateway never answered (a network error or a 5xx) still holds its numbers: prove them again with
  // the same x, which shows the gateway nothing it has not seen, instead of letting them go to waste.
  if (!again && state.pending && !sending.has(state.pending.start)) {
    if (state.pending.cost === cost) again = state.pending;
    else { state.pending = null; save(state); }
  }
  let start, x;
  if (again) ({ start, x } = again);
  else {
    // Another device spent questions past our counter: never offer those again.
    const seen = await seenNext(state.secret, me.questions, state.next);
    if (seen > state.next) {
      if (!warned) console.warn(`warning: another device spent questions ${state.next} to ${seen - 1} of this membership. Use one place at a time.`);
      warned = true;
      state.next = seen;
    }
    if (state.next + cost > me.questions) throw new Error(`Only ${me.questions - state.next} questions are left. Buy more on the site, or with x402: node connect.mjs buy <questions>.`);
    // Reserve and write the counter before any proof exists: a question is never offered twice.
    start = state.next;
    state.next += cost;
    x = randomField();
    state.pending = { start, cost, x };
    save(state);
  }
  const spends = [];
  try {
    const prove = await prover();
    const tree = treeOf(members);
    for (let done = 0; done < cost; done += W) {
      spends.push(await proveSpend({ secret: state.secret, endEpoch: me.endEpoch, questions: me.questions, leafIndex: me.leafIndex, tree, epoch, limit: cfg.limit, start: start + done, weight: Math.min(W, cost - done), x }, prove));
    }
  } catch (e) {
    // Nothing left this computer, so the numbers are still unspent: give them back.
    if (!again && state.next === start + cost) { state.next = start; state.pending = null; save(state); }
    throw e;
  }
  if (process.env.PARANOID_DEBUG) console.log(`key x=${x.toString(16).slice(0, 10)} questions ${start}..${start + cost - 1}`);
  return { key: packKey(spends), start, x, reused: !!again };
}

// ---- the local endpoint

async function readBody(req) {
  const chunks = [];
  for await (const c of req) chunks.push(c);
  return Buffer.concat(chunks);
}
function fail(res, status, message) {
  res.writeHead(status, { "content-type": "application/json" });
  res.end(JSON.stringify({ error: { message, type: "paranoid_connector" } }));
}
async function relay(res, upstream) {
  res.writeHead(upstream.status, { "content-type": upstream.headers.get("content-type") ?? "application/json" });
  if (upstream.body) for await (const c of upstream.body) res.write(c);
  res.end();
}

/** Sends one chat request to the gateway with a fresh key for the model's price. */
async function forward(body, model) {
  const cost = await costOf(model);
  const send = async (k) => {
    sending.add(k.start);
    try { return await fetch(`${SITE}/api/v1/chat/completions`, { method: "POST", body, headers: { "content-type": "application/json", authorization: `Bearer ${k.key}` } }); }
    finally { sending.delete(k.start); }
  };
  const t = Date.now();
  let k = await freshKey(cost);
  let up = await send(k);
  if (up.status === 401 && (await up.clone().text()).includes("stale_member_list")) {
    // Someone joined or left since our read. Those questions were refused before use: prove the same ones again.
    up = await send(await freshKey(cost, true, k));
  }
  if (k.reused && up.status === 402) {
    // The key that looked unanswered had been answered after all: its numbers are spent, so take new ones.
    state.pending = null;
    save(state);
    k = await freshKey(cost);
    up = await send(k);
  }
  // Answered, or refused for good: the numbers are settled. Only a 5xx keeps them for the next request.
  if (up.status < 500 && state.pending?.start === k.start) { state.pending = null; save(state); }
  console.log(`${new Date().toISOString().slice(11, 19)} ${String(model ?? "default")}: ${cost} question${cost === 1 ? "" : "s"}, ${up.status} in ${Date.now() - t} ms`);
  return up;
}

/** True when a Host header (127.0.0.1:4141) or an Origin (http://localhost:3000) names this computer. */
function onThisComputer(value, isOrigin) {
  try { return ["127.0.0.1", "localhost", "[::1]"].includes(new URL(isOrigin ? value : `http://${value}`).hostname); }
  catch { return false; }
}

const server = http.createServer(async (req, res) => {
  const path = (req.url ?? "/").split("?")[0].replace(/\/$/, "");
  // Any web page open in a browser can send requests to this port. Browsers mark those with an Origin header,
  // and a page that rebinds its own domain to 127.0.0.1 still sends its own name as Host. Neither may spend questions.
  if (!onThisComputer(req.headers.host, false) || (req.headers.origin !== undefined && !onThisComputer(req.headers.origin, true)))
    return fail(res, 403, "The connector answers programs on this computer, not web pages.");
  try {
    if (req.method === "GET" && path === "/v1/models") return await relay(res, await fetch(`${SITE}/api/v1/models`));
    if (req.method !== "POST" || path !== "/v1/chat/completions") return fail(res, 404, "The connector serves GET /v1/models and POST /v1/chat/completions.");
    const body = await readBody(req);
    let model;
    try { model = JSON.parse(body.toString("utf8") || "{}").model; } catch { return fail(res, 400, "The request body is not JSON."); }
    await relay(res, await forward(body, model));
  } catch (e) {
    if (!res.headersSent) fail(res, 502, e.message);
    else res.end();
  }
});

// ---- MCP: the same questions as tools for Claude Code, Cursor and any MCP client (stdio, JSON-RPC 2.0, one message a line)

const TOOLS = [
  {
    name: "ask",
    description: "Ask one of PARANOID's AI models a question in private. The question goes with a fresh zero-knowledge key made on this computer, so the gateway cannot tell who asked or tie it to any other question. Spends the model's price in questions (see the models tool).",
    inputSchema: {
      type: "object",
      properties: {
        question: { type: "string", description: "The question, as you would type it into a chat." },
        model: { type: "string", description: "A model id from the models tool. Leave it out for the default model." },
        system: { type: "string", description: "Optional instructions for the model." },
      },
      required: ["question"],
    },
  },
  { name: "models", description: "List PARANOID's models and how many questions one message to each costs.", inputSchema: { type: "object", properties: {} } },
  { name: "balance", description: "How many questions this membership has left and the last day they can be used.", inputSchema: { type: "object", properties: {} } },
  {
    name: "buy",
    description: "Buy a new membership with an x402 payment in USDC on Solana from the wallet in PARANOID_PAYER: 0.002 USDC a question plus a 0.30 USDC setup fee, 250 questions at least. A membership already here that still has questions is kept in a file beside the new one.",
    inputSchema: { type: "object", properties: { questions: { type: "integer", minimum: 250, description: "How many questions to buy." } }, required: ["questions"] },
  },
];

const noMembership = "No membership here yet. Buy one with the buy tool (needs PARANOID_PAYER), or run node connect.mjs once and paste the connector code from the Keys tab on paranoid.red.";

async function balance() {
  if (!state) return noMembership;
  const { cfg, members } = await chain(true);
  const me = members.find((m) => m.commitment === commitmentOf(state.secret));
  if (!me) return "The membership here is not on chain (yet). If a purchase just went through, try again in a moment.";
  const next = Math.max(state.next, await seenNext(state.secret, me.questions, state.next));
  const day = new Date((cfg.genesis + (me.endEpoch + 1) * cfg.epochSeconds) * 1000).toISOString().slice(0, 10);
  return `${me.questions - next} of ${me.questions} questions left, usable until ${day}.`;
}

async function callTool(name, a = {}) {
  if (name === "models") {
    const j = await (await fetch(`${SITE}/api/v1/models`)).json();
    return j.data.filter((m) => m.available !== false).map((m, i) => `${m.id}: ${m.label ?? m.id}, ${m.cost ?? 1} question${(m.cost ?? 1) === 1 ? "" : "s"} a message${i === 0 ? " (default)" : ""}`).join("\n");
  }
  if (name === "balance") return balance();
  if (name === "buy") {
    const b = await buy(Number(a.questions));
    return `Bought ${b.questions} questions. Payment ${b.payment}`;
  }
  if (name === "ask") {
    if (!state) throw new Error(noMembership);
    if (typeof a.question !== "string" || !a.question.trim()) throw new Error("Give the question to ask.");
    const messages = [...(a.system ? [{ role: "system", content: String(a.system) }] : []), { role: "user", content: a.question }];
    const up = await forward(Buffer.from(JSON.stringify({ model: a.model, messages, stream: false })), a.model);
    const j = await up.json().catch(() => ({}));
    if (!up.ok) throw new Error(j.error?.message ?? `The gateway answered ${up.status}.`);
    return j.choices?.[0]?.message?.content ?? "";
  }
  throw new Error(`No tool named ${name}.`);
}

function serveMcp() {
  console.log = console.error; // stdout carries protocol messages only
  const send = (m) => process.stdout.write(JSON.stringify(m) + "\n");
  createInterface({ input: process.stdin }).on("line", async (line) => {
    if (!line.trim()) return;
    let msg;
    try { msg = JSON.parse(line); } catch { return send({ jsonrpc: "2.0", id: null, error: { code: -32700, message: "Parse error" } }); }
    if (msg.id === undefined || msg.id === null) return; // a notification
    const reply = (result) => send({ jsonrpc: "2.0", id: msg.id, result });
    if (msg.method === "initialize") return reply({ protocolVersion: msg.params?.protocolVersion ?? "2025-06-18", capabilities: { tools: {} }, serverInfo: { name: "paranoid", version: "1.1.0" } });
    if (msg.method === "ping") return reply({});
    if (msg.method === "tools/list") return reply({ tools: TOOLS });
    if (msg.method !== "tools/call") return send({ jsonrpc: "2.0", id: msg.id, error: { code: -32601, message: `Method not found: ${msg.method}` } });
    try { reply({ content: [{ type: "text", text: await callTool(msg.params?.name, msg.params?.arguments) }] }); }
    catch (e) { reply({ content: [{ type: "text", text: e.message }], isError: true }); }
  });
}

let arg = process.argv[2];
if (arg === "mcp") {
  state = load();
  serveMcp();
} else {
  try {
    if (arg === "buy") {
      await buy(Number(process.argv[3]));
      arg = undefined;
    }
    const had = load();
    if (!arg && !had && process.stdin.isTTY) {
      // Asked for, not passed on the command line, so the code never lands in the shell history.
      const rl = createInterface({ input: process.stdin, output: process.stdout });
      arg = await rl.question("Paste the connector code from the Keys tab: ");
      rl.close();
    }
    if (arg) {
      const code = parseCode(arg);
      // A different membership that was here is kept beside the new one, never overwritten.
      if (had && had.secret !== code.secret) renameSync(STATE, `${STATE}.${Date.now()}`);
      state = had && had.secret === code.secret ? { secret: code.secret, next: Math.max(had.next, code.next) } : code;
      save(state);
    } else if (had) state = had;
    else throw new Error("First run: node connect.mjs, then paste the connector code from the Keys tab on the site. Or buy with x402: PARANOID_PAYER=wallet.json node connect.mjs buy 500");
  } catch (e) {
    console.error(e.message);
    process.exit(1);
  }
  server.on("error", (e) => { console.error(e.code === "EADDRINUSE" ? `Port ${PORT} is in use. Set PARANOID_PORT to another port.` : e.message); process.exit(1); });
  server.listen(PORT, "127.0.0.1", () => {
    console.log(`PARANOID connector on http://127.0.0.1:${PORT}/v1`);
    console.log("Use any API key. Every request gets its own fresh key, made here.");
  });
}
