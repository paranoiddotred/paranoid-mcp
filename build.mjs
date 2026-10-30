// Builds connect.mjs from src/connect.src.mjs: embeds the Poseidon constants and pins the SHA-256 of the prover
// and circuit files in the folder given (zk/ by default), which scripts/fetch-zk.sh fills from their public
// sources: snarkjs 0.7.6 from npm, request.wasm and request.zkey from paranoiddotred/paranoid.
//   bash scripts/fetch-zk.sh && node build.mjs && git diff --exit-code connect.mjs
// A clean diff shows the published connect.mjs is exactly this source with those files.
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
const zk = process.argv[2] ?? "zk";
const at = (p) => new URL(p, import.meta.url);
const sha = (p) => createHash("sha256").update(readFileSync(at(`${zk}/${p}`))).digest("hex");
const out = readFileSync(at("src/connect.src.mjs"), "utf8")
  .replace("__POSEIDON_CONSTANTS__", JSON.stringify(JSON.parse(readFileSync(at("src/poseidon-constants.json"), "utf8"))))
  .replace("__SHA_SNARKJS__", sha("snarkjs.min.js"))
  .replace("__SHA_WASM__", sha("request.wasm"))
  .replace("__SHA_ZKEY__", sha("request.zkey"));
if (/__[A-Z_]+__/.test(out)) throw new Error("a placeholder was left in connect.mjs");
writeFileSync(at("connect.mjs"), out);
console.log(`connect.mjs ${out.length} bytes, sha256 ${createHash("sha256").update(out).digest("hex")}`);
