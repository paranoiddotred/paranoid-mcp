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
const VERSION = "1.2.2";
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
  "snarkjs.min.js": "3f61bbd9ac0a10173902eaef65b510fa4e9a2c057f759c7f18a6d0446b20fd06",
  "request.wasm": "63ddec9cd39bb2eb06c8c6fa51eb72e4333863fb8757c68770ab4ab1abe06478",
  "request.zkey": "d909d787fd228867708c361fef699676bc49a5c0adfe140a6d50a539779e69cd",
};

// ---- Poseidon over BN254 with circomlib's parameters (inputs 1, 2 and 3), vendored from poseidon-lite 0.3.0 (MIT)

const K = {"t2":{"C":["CcRunsaOm9T+H6q6KUy6OKcaoXdTTN0bbH3A29Cr16c=","DANWUwiW7sQql+2TfzE1z8UUKzrkBbg0PB2D/6YEy4E=","Hiih2TVpitEULlEYK7VM9KAOpaq9Ymi9MX6pd8wVSjA=","J68tgxqdJ0gICWXbMOKY5A5XV8PgCNuWTPnisSuRJR8=","Hm8RzmD8j1E6ajz+Fq4XWkEpFGLyFM0Iear0NUW3TgM=","Kmc4TTu9XkOFQYGctoHwvgRGLtFMNhPY9xkgYmjRQtM=","C2b981YJOmEWCfjhL7/s8LmF44HwJRiJNkCPXVyfRdA=","AS7j7B541HCDDGEJPCreNwsmyDzFzr7t2qaFLb2wniE=","AlK6X2dgv739iPZ/gXXj/WzRxDGwmba7LRCOe0Rbsbk=","F5R0zOyl/2dsa+w871QpY1Q5Gok1/3HW71rqrXypMvE=","LCQmE3mlG/qSKP9KUD/U7Zwfl0omSWmzfholibvtK5E=","HMHXtiaS5j6sLyiL0GlbQ8L2P1AB/A/FU+ZsBVGAGwU=","JVBZMBqtqYuy7VX4UpeelgB4Tb8X+6zQXZ7/X9nJG1Y=","KEN746wcsuR54fXA7M0ys66iQjSXCoGTsRwpzn5Z79k=","KCFqRC8uH3EcpPprU3ZusRhUjaj7T3jUM4diw39fIEM=","LB9HzRf6Wt8fOfTnBW3QP+7h784DCUWBEx8jdzI0gsk=","B6utArel68SGMrzJNWzrfdna/KJ2Y4pjZGuFZqYhr8k=","AjAmRgH/3yknWzP/qrUd/pQp+QiAppzRN9oMTRX5bDw=","G8lzBU5R2QWg8WhlZJfKQKhkQUVX7iiecX5dZomaoKk=","Lhwi+WRDUAggbDFX6GNB7dJJr/XC2EIfKmsiKI8KZ/w=","EiTzjfZ8U3gSHB1fRhu8UJ6OoVmORsn3pwRSvCu6hrg=","AuTmnYulnlGSgLS9ntAGj9e/6M2d/toZadKYkYbN4g4=","Hx7Mw0qroBN/XfgfwE/z7k8Z7jZOZT8HbUfpc12YAY4=","FnKtPXCaNTl0JmwwOamnMRQkRIAyzRgZ6suKTUKE9YI=","KD4/3CxuQgxW9Er1GStK6c2mlh8oTSSZHS7WAt+Mj8c=","HCo9EgxVDs/Q2wlXFw+gE2g3Ufj9/1nWYU+9af85S8w=","IW+Eh3qsYXL3iXpzI0Vu/hQ6mkN3PqbylstrgXdlP70=","LA0nK+zyp1dkun6OPijRK86qR+phylmkEaH1FVL5R4g=","FuNCmYZcDihITuenTEVOnxcKVICr4FCPy0psPYlUb0M=","F1zrpZnpb1s3WiMqb7nMcXcgR3ZYAikPSM2Tl1VIj8U=","DHWURA3EjBb+rZ4XWLAoBmqkEL+8NU9U2MX/u0Sh7jI=","GjwpvDnyG7XEZtt9frb9j3YOIAE8z5EskkeYgtkZ/Y0=","DM/dkG80JuXAmG6gSbJTQAhV00kHT1pmlcjuq80i5o8=","FPa8gdnxhvYr20dc5slBGGanqKP9Bls84OaZtn3Z55Y=","CWK4J4n7PRKXAspwsvbFqswJmBDJxJXIiO3rc4a5cFI=","GogK9wdNGLO/IMed4lEnvBMoSrAe8CV1r+8Mj2oxqG0=","EMuhhBmmozLNXnfwIRwVSyCvKST8IP8/TDASu3rpMRs=","BX5iqaj4mz69x2umOp6sqPontzGcrjQGdWooSfMC8Q0=","KHyXHekdwKvUSt9ThLSYjLlhMDu/Zc/1r6BBO0QoDO4=","Id8ziK8Wh7uzvKnaDMqQjx5WK8RtSrpOb395YOMGiR0=","G+XIh9JbznA+JcyXTQk0zXid+PcLSY/YPv+LVg4WgrM=","Jo2jb3blaPtoEXF1zqLNDdLLXUL9pazqSNWcJwag1cE=","DherCR9urlDGCb6vVRDs7MXYu3QTXr0FvQZGDMJqXtY=","BNcn5yj/oKZ67lNasHSkMJHvYtjPg9JwBA9cqh9ir0A=","DdvXv5wpNBWBtUl2K8Ai7TNwKsEPG/2GKxVBfX45ym4=","J5DrM1FiF1J2gWLoKYnGwjT1sNHTr5tYiinEnIeJZUs=","HkV8YBpjtz5EcZUBk9ilcDlfPZq4sv0JhLdkIGFC+ek=","Ia5kMB3KliVjjWqyu+cTX/qQ7NDEP/kfxMaG/EbgkbA=","A3n2PIzjRo1NopMWb0lJKIVL6eNDLglVWFhTTu2NNQs=","AC1WQgNZ0CZqdEoICAngVMoOSSGkZoasjJ9YoyTDUEk=","EjFY5ZZbXZsdaLPNMuELvtqNYkWeIfQJD8LFr5Y1FaY=","C+KfxAhHqUFmHRS79svgQg+7K29Sg21OYMgOtJytnsE=","Gslpkd7CuwVXcWFCAVpFPDbbnYWcrV+aIzgC8k/fTBo=","FZZEP3Y9vMJfSWT8YdI7Pl4SyfqX8YqSUcozVbywYn4=","EuC802VL36drKGHU7Drq4PGFfZ8X5xWu1tBJ6uO6MhI=","D8krTxu+qCuepz1K+a8qUM6rrH83FUsZBObHbHz5ZLo=","H5wLFhBEZELW8uWSqAE/QLFPfHciI29PnH6WUjOHJ2I=","Dr10JErnJnX4zeBhV6eC9AUNkU2ji0wFjRWfZD279NM=","LLfw7Tnhbp9pqfr9SrlRwDsGcelzRu45eoOYOdzPxtE=","Gp1uLs/wIsxWBUQ+5BurIM52HQUUzlJmkMcrynNS2b8=","KhFUOWB/M1peqDw7xEqTMdDBMyapp7owh9oYLWSOxy8=","I/m2UptdBA0VuPp67j40EOc4tWMFzUTylTXBFcWkwGA=","BYcsFtsPcqIkmsa6SEu5w6POl8FtWLaLJg65OfDm6Kc=","EwC97gi7eCTKIPuAEYB19AIZthUdVbXFK2JKfN7d9qc=","Gbm2PS8QjhfmOBeGOo9sKI160pkW2YyxBy5Oe31Ss3Y=","AVvuE1fjwBW1vaI3ZoUi9hPRyIcmtexCJKIBKEgbT38=","KVNzbpS7a58blwek8WFeTv4eHOS6shjL6pLHhbEo/9E=","CwaTU7oJFhiGL4BhgMA4X4UbmNNytF9UTOcmbtZgjfw=","ME901GHMwTEV5OC8+5OBflWut+uTBrZOT1iKyX2B9Ck=","FbvxRs6bygnooz9ed9/k9arSoWSkYXpMuO5UFc3pE/w=","CrTf4MJ0LN5EkBAxSHlk7ZuPS4UEBcEMqf8jhZVyyMY=","DjLbMgoETjGX9F92SaGWde9e7f6lRt6pJR3jn5Y5d5o=","ChdWqh83jKSydjWni2iI5meXczqCd0iWoweO+lFtoBY=","BExKM7EPaTRH/RcXf5Uu+JXmHTKPhe+pQlTWoqJdk+8=","LtNhG3JbinC+ZVtTf2b3AP4IedeaSWiR03sHtUZsS4s=","H5uk6Lq3zkLI7MPXIqouDq3965z900e12DOepxIIWKo=","GyMwQwUujCiPfukHqE5RiqOOgqxFAgZtt0BW+GXF09o=","JDHhzBZLuNB0Axq3K9VbTJAgU7/A8U2wyi+XsCCHWVQ=","CC+TTJH1qsMwzWlToKfbRaE+MiCXWDMZp5Hyc5ZYAf0=","K5oKIj51OLCjS+B0MVVCo8dyReKufL6Zmta7kwxImXw=","DhzZHt0s+izOuFSDuIepvoFkFj51qKAOsLWJzHAhTn0=","Lh6sDyv9/WPJUfYUd+NpiZl3TxmFTQD1iNMkYBzr4vk=","DL+pXzf7dAYMdhWOdp1tFXNFeE2O/bM8I9dIEVtQC4M=","CPBbO+kj7UTWWtSdimHppnbZkeOndRPZmAwjLfpKT4Q=","InGeKgcLzQhSv44hmE0EQ+coSSXcB1ijJaLdUQwEfvY=","BB9Zap7hyyvAYPf8w6GrTHvb8DYRmYLA9B9isvJoMMA=","Iz/TXeG+UgqHYo6wb2sdTAIb4cLQ3EZKGfzdCYaxD4k=","BSS0bRqoel5DJeCkI+vIENMeB4qhtHB+78tFPGHJwmc=","LDT0JMgeVxbOR/ysiUuFgkInu5VLDzGZzESGI3xRUhE=","C18qS2M4eBkgfv/CtVQfty3SAltUV8yX8zAQMn3kkV4=","IiB4VggszFTFty/kOdLP1sF0NdL1evbOrvrEH+BcZZ8=","JNV6i/XaY/5OJBWbf4lQtc37IQGUyvefJ4VASM4sgXE=","Cvqxgf3V4Fg7Nx11vWk/mDdK1wl7sBqFc5Gbsjt5OW4=","LbqbEI8gh3KZilLvrHy9VnbABXGUwWwL8WKQ1isRKO4=","JjSbZu24sW9W+IHHiPU/g8u4PeC9WSslWv8T5rzkILM=","Ja984OXhA1doXpX5Izl1OtgaVtKOzBk7I1KIo+bxN9s=","JbTOe9IpQ5DAlNalXt1ouXDu16roiyv/H3wBh/41AR8=","IsVD8Q9siew4flPxkIqI5d6c7yjr3zCxjLnVTB4CtjE=","Ajb5PneJxHJPx5CKnxkeHkJekGqRnXo032aOdIgvh6k=","KTULQBFmygEOfSfjfQXamWUr2uEU6wFlnLSXr5gMS1I=","Du14fWWCDT9r0xu6tUf3WmXtt12ETruJ7hJgkWZSNj8=","B8wRcPE7RvIDanU/Ugsykf3NDpm9lCl9GQb2VvTeb60=","Irk5IzsdcgX0m89hOj0wsZCHhtf59dEMIFlDVonorOo=","AUUXYqCquByKrR3IvDPocHQPCDpaqFQ4rdZQrOYK5aY=","I1BrtdhyfURh+r8QJdRtH+MuqmHex9pX5wT+wIkvzok=","LkhMROg4rqC6wGrj9xvdCSo3CVMeHv6pf4vWiQc1VSI=","D0vH0H66/WQ3nnjFC9LkK69KWUVFztwlRUGNomg1tUw=","H008j2WD6eX6dmN4Yvqu6FFYI4hyXfRg5iCZbVDY504=","CTUU4McHEfgmYNB74OSpiPrgKrx7aB2RU+uby0j+c4k=","GtqwyOKzutNGaZorXzvANkPug+zkcijySljgo0fhU9g=","FnKxcmBX2Z3RRwnrtHRkGjeMG5S4ByusGiLb756A2tI=","Hf1T1Fdq8uOPRPU/3KtGjMXY4vrgrMTuMNR7I5tHnBQ=","DGiIoQt1sPOnCjYmOjfhf+bXfWQPb8PevH8gd1MgXGA=","Gt25M6Zb53CSs0p+d9Ev6GEaYeAO5oSLhQkezKnR5Qg=","ANdUDc0mioRcEK4Y0d6TPPY4/1Ql8K//eTVijimdF5E=","FAwOQmh+nq0BsoJ6VmTKnCb+3eSs2Z2x0xaTnSC4LA4=","Lww6EV1DF9GRuom40T0YBsIKD5sk+MXtwJHirlZWWYQ=","DE7neP98FFUwBu0iDPnIEAigz/ZwsiuC2MU4odyVjGE=","FwTydm1G+Cw2k/AEQMzDYJQk7SbArMZiJ8PXSF3nTGk=","Ly0ZzD6l146noCwbUdJEq/B2nJ+FROQCObZv6QCcPPo=","GuA4U7dfyrpQU/ES4qjo3N1+5suc/tnH1sdmqAb8Zik=","CXGqv3lSQd9R0THQ+mGqXzVWkhstbwFOTkGobdrwVtU=","FAjDFuYBThqR1M9rbg3nPtpiT4OA3xyHX1wp97/i9kY=","Fmfz/i7b6FAkir5CtUMJO2yJ8fdz7yhTQWkfOYIu9b0=","E798XQ0sQ3akiwoDVXzfkVuBcYQJ5cEzQkxpV2UA/jc=","B2IKbfsLbOwwFq3z01M8JAJLlTR4VreXGbwLp0OmLCw=","FXTH7wxDVF82qMoIvb3YsHXSlZ4vMitzFnXePhmCtNA=","Jp5LW3oushr9VnlwpxfO7FvUGEVxwlT9wG4Dp/+DePA="],"M":[["Bm9vhdb2ioXsEDRTUaI6Oq8H84r4yVKnvOynC9KvetU=","K51LQRDJrpl3guFQmx0P2yCnwCu9i+pzBUYrn4Elseg="],["DMV827CFB9Yr9npEk8wmL7bAnVVwE//x9XP0MSIfj/k=","EnTmSaMu01WjGm7WlyThra3oV+hutcOhIbzRR5QyA8g="]]},"t3":{"C":["DumlkrqalRjQWYbWVvQMIRTEmTwRuymTjSHUcwTNjm4=","APFEUjXyFIxZhlhxafwbzYh7CNTQCGjfVpb/9AlW6GQ=","CN/zSH6KyZ4fKaBY0PqAuTDHKHMLerNs6HnziQ7Pc/U=","Lye+aQ/a7kbDzij3UysTyFbDU0LIS9puIJZjEPrcAdA=","KyrhrPaLe40kFr6/PU9iNLdj/gS4BD7ki4MnvryhbPI=","AxnQYgcr737MperAb5fU1VlSwXWrawPq5ktEx9vxHPo=","KIE9yuuuqoKKN234evSmO8i3vyetScYpjvezh78oUm0=","JydnOyzLyQPxgb844cHUDSAzhlIAw1K8FQkord35y3g=","I07EXKJ3J8LnSr0rKhSUzW771D40BYfWuPueMeZcxjI=","FbUlNAMa4Y9/hiyyz3z3YKsQqBUKM3sczZn/boeX1Cg=","Dcj61tnks19e2aPRhrec444Oio0bWLEy1wHU7s9o0fY=","G82V/8IR+8pgD3BfrT+1Z+pOs3j2Lh/sl4BVGKR+TZw=","EFILCrchyt/p7/gbAW/DTcdto2wleJN4F8uXjQad5Vk=","H21IFJuOf32bJX2O1fu69CkySYB1/tCs6IqeuB9WJ/Y=","HZZV9lIwkBTSngDvNaIIm//43ByBbw3JyjS9tUYMhwU=","BN9aVv+VvK+wUfexzUOpm6cx/2fkcDIFj+PUGFaXzH0=","BnLZlfj/9kAVGz0pDO2vFIaQoQqMhCSn9uwoK25L6Cg=","CZlStBSIRFSyEgDX/6/dXwyancwG8nCOn8HYIJtcdbk=","BSy6IlXf0Ax8SDFDuo1GlEjkNYaptM2Rg/0OhDprn6Y=","C4ut7mkK246wvXRxK3mZr4LeVXByUa13Fgd8uTxGTdw=","EZsVkPEzB69aHuZRAgwHx0nBXWBoOoBQuWPQqOSyvdE=","AxULfNbV0XslKdNr4PZ7gyxKz8iE707lzhW+C/tKjQk=","LMYYLF4UVG488ZUfFzkSNVN077g9gImKvmnLMXyepWU=","AFAyVR5jeMRQz+EppASzdkIYyt7awU4rktLNcxEb8Pk=","IzI34yibqjS7FH6XLry5UWRpw5n8wGn7iPnaLMKCdrU=","Bcj09OvUpuPJgNMWdL++YyMDfyGzSuWk6AwtTCTWAoA=","CnsdsTBC05a6BdgYoxnyUlK8817zru2R7h8JslkPxls=","KnO3H5shDPWxQpZXLJ0y2/FW4rCG/0fcXfVCNlpATsA=","GsmwQXq8yaGTUQfp/8kdw+wY8sTb5/Ipdqdgu1xQxGA=","EsAzmuCDdII/q7B2cH70eSafPk1ssQQ0kBXuBG3JP8A=","C3R1sQKhZa1/WxjbTh5wT1KQCqMlO6rGgkZoLlbpoo4=","A3woSeGRyj7bHF5J9ui4kXyEPjeTZvLqMqs6qI1/hEg=","BaaBH4VW8BTpJnRmHiF+m9UgbFyToH3BRf2xdqcWNG8=","KaeV59mAKJRulHt11U6fBEB26Hp7KIO0e2de9fOL1m4=","IEOaDISzIutFo4V6/Bj1gm6Mc4LIoVhcUHvhmZgf0i8=","Lguo2U2ez0qU7CBQxzcf8btQ8neZqEttSipvKgmCyIc=","FD/RFc4I+yfKOOt8zoIrRReCLNIQkEjS5tDdzKF9ccg=","DGTL7LHHNLhXlo273PgTzfhhFlkyPby/yEMjYjvpyvE=","AoowWEfGg/ZG/KklwWP/WudPNI1iwrZw8UJs75QD2lM=","Lk71EP8Lb9pfqUCrTEOA8mpry2TYlCe4JNZ1W1254ww=","AIHJW8QzhOZj15JwyVbOO4kltPbQM7B4uWOE9QV5QA4=","LtXwyRy9l0kYfi+t5ofgXuJJGzScA5oLuoqfQCOguzg=","MFCZkfiNo1BLvzdO1ari8DRIoix2I0yMmQ8B8zpzUgY=","HD8g/VVAmlMiG3xNSaNWufChEZ+yBntBp1KQlEJOxq0=","ELTn86td8AMElRRFm24Y7sRrsiE+jhMeFwiHtH3cuWw=","KhmCl5w/9/Q93VQ9iRwqvd2A+ATAd9d1A5qjUC5Dre8=","HHTuZPFeHbb+3b6tVtbVXbpDHrw5bJr5XK0PExW9XJE=","B1M+yFC6f5jquTA8rOAbS55PLouCcIz6nC/kWgrhRqA=","IVdrQ45QBEmhUeTurxexVChcaPQtQsGAihGr83ZMB1A=","LxfAVZuP55YIrVyhk9YvELzoOEyBXwkGdD1pMINtSp4=","LUd+OGLQdwinnoqulGFwvJd1pCATGEdK5mWwsbficw4=","Fi9SQ5ZwZMOQ4JVXeYTyka+6ImbDj1q82Jvg9bJ0fqs=","K0yyM+3pukgmTs0siuUNGteoWWqH8p+Kd3enAJI5MxE=","LI+8st2Fc9wduvj0YihUd22y7s5thcTPQlTnw14DsHo=","HW80dyXkgWry/0U/DNVrGZ4bYen2Aemt5eiNuHCUnak=","IEsMOX9OvnHrwtiz31uRPfnmrAK2jTEyTNSa9cRWVSk=","DEy53DxP2BdPEUmzxjw8L57LgnzX3CVTT/j7dbx5xQI=","F0rWGhRIyJmiVBZHT0kwMB5cSUdSeeBjmmFt3EW8e1Q=","GpYXe89NjYn3Wd9OwvPN4uqqKMF3zA+hOpgW1Jo40u8=","Bm0EskMx1xzQ74BUvGDE/wUgLBJqIzwagkKs42C4owo=","KkxPxuwLDPUhlXgoccbdOzgcxl9y4CrVJwN6Yqob2AQ=","E6stE2zPN9RH6fLhSnztyV5yf4RG9tnX5Vr8ASGf1kk=","ESFVL8omBhYZ0k2EPcgnacGwT87Cb1UZTC4+hprMapo=","AO9lMyKxPWyIm8gXFcN9d6bNJn1ZXEqJCaVUbHyXz/E=","DiVIPkWmZSCLJh2Lp0BR5kAMd21lJZXZhFrKNdijl9M=","KfU23LnddoIkUmRlnhXYjjlaw9Td6S2MRkSNuXnuuok=","KlbvnyxT/rrf2jNXXb29iFoSTieAu+oXDkVrqs4Ppb4=","HINhx461z13s+3otF7XECfKuKZmkZ2Lo7kFiQKjLmvE=","FRr/XziyCg/ARzCJqvAga4Po5op2RQe/09CrS+dDGcU=","BMYYfkHtiB3BsjnIj3+dQ6n1L8jIts3R525HYVtR8QA=","E7N72A9NJ/sQ2EMx9vttU0uBxh7RV3ZEnoAbfdycKWc=","AaXFNic8LZ31eL+9MsF7eizjZkwqUgMskyHOscToqOQ=","KrNWGDTKc4Na0F9desuVC0qaLGZrlybagyI5Blt8OwI=","HU2OwpHnINsgD+bWhsDWE6yvavTpXTv2n37VFqWXtkY=","BBKU0sxITSKPV4T+eRn9K7klNRJAoEtxFRTJyAtlrx0=","FUrJjgFwjGEcT6cVmR8ASJj1eTnRJuOSBClx3ZDoH8Y=","CzOdisyn1Pg+7dhAk671EFCzaEyI+LCwRSRWO8bqTaQ=","CVXknmYQyUJUpPhM+6s0RZjw5x6v9Kfdge2VtQg5yC4=","BnRqYVbrpUQmueIiBvFavKmm9B5vU1xvNSVAHqBlRiY=","Dxj1oOzRQjxJbzggxUnCeDjleQ4r0KGWrJF8f/Mgd/s=","BPbuyhdR9zCKxZ7/W+smHku1Y1g+3nvJKnOCI9b3bhM=","K1aXM2TExPXBo+xNo83OA4gR6xFvs+RbwXaNJvwLN1g=","Ejdp3UnVsFTc12uJgEsby44TkrOFcWpdg/62XUN/Ke8=","IUe0JPxIyAqI7lK5EWmqzqmJ9kRkcRUJlCV7L7AcY+k=","D9wfWFSLhXAabFUF6jMqKWR+bzStQkPC6lStiXzr5U0=","Ejc6glH+oATfaKvPD3eG1Lzv8oxdu+DDlE9oXMCgsfI=","IeT06l81+FutfqUv90LJ6KZCdWtq9EID3YofNcGpADU=","FiQ5FtadLKPftHIiJNTEYrVzZkkvRekNioGTTxvDsUc=","HvvkbdeleLT2b5rbyItDeKvCFWbhoEU8oTpBWcrASsI=","B+pehTfPXdCIhgIOI6fzh9Ro1VJb5m+FO2csyWqIlpo=","BajE+ZaLiqO3tHijD5pbY2UPGadefOEcqf4WwLdsALw=","IPBXcSzCFlT7/lm9NF6NrD94GMcBuceILZ1Xtyoy6D8=","BKEu3tqd/WiWcvjGf+4xY23NjojQHUkBm9kLM+sz22k=","J+iNjBXzfc7kTx5UJaUd7L0TbOUJGmdn5J7JVEzNEBo=","L+7Re4QoXtm4pcjF6VpB9m4JZhmncDIjF2xB7kM95NE=","HtfMdu30XHxAQkFCD3Kc85TllCkRMSoNaXK4vVOv8rg=","FXQumbm/oyMVf/jFhvVmDqxng0dhRM3K3yh0vkVGaxo=","GqwoU4f2XoLIlfxoh930BXcQdFTG7AMXKE8DPyfQx4U=","JYUcPIRdR5D53a29tgVzV4MuLnpJd19x7HWpZVTWfHc=","FaWCFWXMLsLOeEV9sZft81O367osVSM3DdzMPZ8Uamc=","JBHVekgTuZgO+n4xodtZZtz2TzYEQndQLxVIXyjHFyc=","AC5vjWUgzUcT4zW4wLbS5kfpqY4S9M0lWIKLXvbLTJs=","L/e8j0OAzemX2gC2FrD80a+PDpHi/h7XOYg0YJ4DFdI=","ALmDG5SFJVle4CckRxvNGC6VIfa3u2jx6Tvk/rsNPL4=","Ci9TdouOv2qGkTsOV8BOARykCGSKR0OofXetvwycNRI=","ACSBVhQv0Dc6R5+R/yOelg9Zn/fpS+abfyopAwXhGY0=","Fx1WILh7+xMoz4wCqz8MmjlxlqpqVCwjUOtRKisrzak=","FwpPVVNvfclwCHx8ENb612DJUhct1U3ZnRBF5Ow0qAg=","KaujP3mf5mwu8xNK6gQzbsw344wc0hG6SC7KF+Lb+uE=","HpvBeaT911j90bsZRQiNR+cNEUoD9qDotbplA2nmSXM=","HdJpeZtmD61Y9/SJLfsLWv6q2GmpxLRPnJ4cQ72vjwk=","Is28i3ARetFAEYHQLhVFnnzNQm/oacfJXR3Syw8krzg=","DvBC5FR3HFM6n1elXFA/zv0xUPUu2Up81bqTucfazv0=","EWCeBq1sj+Lyh/MDYDfohRMY6LCKA1mgOzBP/KYugoQ=","EWbZ5VRhbbqedT7qQnwXt/7NWMB23+QnCLCPW3g6qa8=","LeUpiUMahZWTQTAmNUQT2xd/v0zSrAtW+FWoiDV+5GY=","MAbrT/x6hYGabaSS86isHfUa7lsXuOiddL8Bz19x6a0=","KvQfu2G6ioD9z2//nj9vQimT/o8KRjn5YjRMgiUUUIY=","EZ5oTeR2FV/lprQajryF24cYqyeInoXngbIUus5IJ8M=","GDW3huLokl4Yi+pZrjY1N7USSMI4KPBHz/eEuXs/2AA=","KCAaNMWU36NNeUmWxkM6INFSusKnkFySbEDihasy7rY=","CD79eifRdRCU6A/vr3iwAIZMgutXEYdySnYfiMIsxOc=","C2+Io1dxmVJhWOYc7qJ76BHBbfd3TdhRngeVZPYf0Ts=","Dsho5tFeUdlkT2bh1kcalFiVEcoA0p4QFDkObuQlT1s=","KvM+P4ZncScawMmz7S4RQuzT50uTnNQNANk3q4TJhZE=","C1ICEfkEtefQm12WHGrOdzRWjFR91oWLNkzl5HlR8Xg=","Cy1yLQkZoarY21jxAGKpLqDFasQnDoIsyiKGIBiKHUA=","H3kNTX+M8JTZgM6zfCRT6Ve1SpmRyji74AYdHtblYtQ=","AXHrld+/fR6uqXzThfeAFQiFwWI1oqao2pLOsB5QQjM=","DC0OO1/VdUkym/aIXaZrm3kLQN79LIZQdiMFOBsWiHM=","EWL7KGicJxVOWoIotOcrN3y8r6WJ4oPDXTgDBUQHoY0=","LxRZtl3uRBtkrThqkegxDygsWpKonhmSFiPvgklxG8A=","Hm/zIWtojD2ZbXQ2fVzUwbxInUZ1TrcSwkP3DRtTz7s=","AcqL5zgyuNBoFIfSfRV4AtdBpvNs3CoFdogfkyZHiHU=","H3c1cG/+n8WG+XbVvfIj3GgChggLEM6gC5td4xX5ZQ4=","JSK2D06jMHZAoMLc4EH7qSGsEKPV8JbvR0XKg4KF8Bk=","I/C+4AGxAp1SVQdd3JV/gzQYytT1K2w/jOFsI1VyV1s=","K8Gui43buB/KrC1EVV7VaF0UJjPp35BfZtlAEJMILVk=","D5QGuCllZKNzBFB7jbo+0WI3EnOgex/JgBH81q1yIF8=","I2Co6wzH3vpntymY3pBxThfnWxdKUu5KyxJsjNmV8Kg=","FYcaXN3q2XaATIA8uu8lXrSBWl6W34sAbcu8J2f4iUg=","GTpWdmmY7p4KhlLdLzsdoDYvT1T3I3lUT5V8ze77Qg8=","KjlKQ5NPhpgvm+Vv9PqxcDsuY8itM0g05DCYBed3rg8=","GFmVTP64aV8+i2NdyzRRkoks0RIjRDuntBZuiHbA0UI=","BOEYF2MFDlgBNETby5nxkCsRvCXZC73KQI04GfT+0ys=","D9slPe6Dhp1AwzXqZN6MW7EOuC2wi16LH15VUr/QXyM=","BYy+ippQJ72qTvtiOt6tYnXwhobxwImEqdfFuum08cA=","E4Ltzplx4YZJfq2xrrH1KyO0uDvvAjqw0VIotMzspZo=","A0ZJkPBFxu4IGcpR/RGwvn9huOuZ8Ut34eZjRgHZ6LU=","I/e/yHINwpb/8ztB+Y/4PG/KtGBdsutaqlvBN663Clg=","ClmhWOPuwhF+bpTn8OnezxjD/9XhUxqSGWNhWLuvYvI=","BuxUyAOBwFK1i/I7MS/9POLE66BlQgr49MI+0Adf0Hs=","EYhy3IMuDrVHa1ZkjoZ+yLCTQPenvLG0li8P+e0fnQE=","E9afoSfYNBZa1cfLp61Z7VLgsPDkLX/qleGQa1IJIbE=","FpoXf2PqaBJwscaHenPSG94UOUL7cdxV/YpJ8Z8Qx3s=","BO9RWRxurZfvQvKHrc5A2Tq+sDK5IvZv+36aWnRQVE0=","JW4XWh3AeTkOzXynA/suOxnsYYBdTwPO1fRe5t0Paew=","MBAtKGNqvV/l8q9BL/YAT3XMNg0yBd0toAKBPT4s7rI=","EJmOQt/NO78cBxS8c+sb9ARDo/qZvvSjH9Mb4YL8x5I=","GT7djp/PPXYl+n0ktZih2J8zYur01YLv7K12+HnjaGA=","GBaK/TTy2RXQNozoC3szR9HHpWHOYRQl8mZNeqUfC10=","KTg8AevTtqsMAXZW6+ZYtqMo7He8M2JuKeLpWzPqYRE=","EGRtLyYD3jmh9K5ed3GmSnAttuhvt2q2AL9XP5AQxxE=","C+teB9GycUX1dfE5WlW/Ey+QwltA2ns4ZNAkLcsRF/s=","FtaFJSB4wTPcDT7K1itciDD5W7LlS1mr3/vwGNlvozY=","Cmq9HYM5OPM8dBVOBAS0tApVW7vsId36/Wct1iBH8Bo=","GmefXTbre1yOoSpMLe3I/rEt/+7EUDFycKbxmzTPGGA=","CYD7IzvUVsI5dNUODr/eRyakI+raTo9v+8dZLj8bk9Y=","FhtCIy5huEy/GBCvk6OPwM7OPVYoySggA+ustcMSxys=","CtoQqQx/BSCVD31Hpg1eakk/CXh/FWTl0JID20feGgs=","GnMNNyMQuoIyA0WimsQjjtPweoorThIbtQ3bmvQH9FE=","LIEg8mjvBU+BcGTDad2n6pCDd/6rpcTf+9oQ71joxVY=","HHyIJPdYdT+lfAB4nGhCF7kw6VMTvLc+bnuGSaSWj3A=","LNntMfX4aRyOOeQHenT6oPQArYtJHrP3tHsn+j/Rz3c=","I/9PnUaBNFfPYNkvV2GDmaXgIqwyHKVQhUriORiiLuo=","CZRaXRR6T2bO7OZAXd3Z0K9aLFEDUpQH3/HqWPGAQm0=","GI2cUoAl1MK2dmDGt3G5D3x9puqinT8mim3SI+xvxjA=","MFDjeZZZa3+B9oMRQx2HNNun2SbTYzWV4MDY3fTw9H8=","Fa8RaTloMKkWAMqBAsNcQmzq5UYeP5XYnYKVGNMK/Xg=","HabQmIVDLqmgbZ83+HPZhdrpM+NRRmspBChNozINisw=","J5bqkNJpryn1+KzzOSESTk5PrT2+ZYlF5UbuQR3aqcs=","IC190doPa0sDJcizMHdC8B4VYS7I6TBKfLAxngHTLWA=","CW1nkNBbt1kVapUromPWcqLX+ceI9Mgxop2s5MD4vl8=","BU76H2Ww/OKDgIllJ12He0ONojzlsT4ZY3mMsUR9JaQ=","GxYvg9kX6T7bMwjCmALeudiqaQETsuFIZMz24Y5BZfE=","IeUkHhJWTdb9nxzdKg3jnu3+/BRmzFaOxc63RaBQbtw=","HPtWYujPWskiaoDuF7Nqvstzq1+H4WGSe0NJ4Q5L3wg=","DyEXfjAqdxu65tjR7LNztiyZrzRiIKwBKcU/Zm6yQQA=","FnFSI3RgaZKv+w3X9xsSvsQjau3mKQVGvO9+H1FcIyA=","D6PsW5SIJZwutM8kUBv62b4uyeQsXMjM1BnSppLK2HA=","GTwOBOC9KYNXyyZsFQYIDtNu3OhcZIzAhejFexq1S7o=","ECrfjvdHNaJ+kSgwbcvDyZ9vcpHNQGV4zhTqKtq6aPg=","D+CveFjkmFnipU1vGtlFsTFqokv73SOuQKbQy3DD6rE=","IW9nF7vH3tsIU2oiIIQ/Ti2l8dqp69796KXqc0R5jSI=","HaVcyQDw0h9KPmlDkZGKGzwjsqx3PGs++I4uQigyUWE="],"M":[["EJt/QRug5MmytwyvXDansZS+fBGtJDeL/ttoWSuoEYs=","Fu1B4Tu5wMZq4RlCT928vJMU3J/b3upV1sZFQ9xJA+A=","K5C7oA/KBYn2F+fcv+guDfcGq2QM6yR7eRqTt042c20="],["KWnyfu0xpIC5w2x2Q3nbyizI/dFBXD3e1ilAvN4L13E=","LiQZ+ewC7DlMmHHIMpY9wbiddDyMe5ZAKbIxFoex/iM=","EBBx8AMjebaXMVh2aQ8FPRSNThCfX7BlyKrMVaD4m/o="],["FDAh7GhqPzMNX55lRjgGXObNeeKMWzdTMmJE7mWhsac=","F2zAKWla0CWCpw7/CKb9mdBX4S5Y59e2sWzfq8juKRE=","GaP8ClZwK/QXun/uOAJZP6ZERwMHBD93cyec1x0l1eA="]]},"t4":{"C":["GbhJ9pRQsGhI2h05vV5KQwK7hnRO3CYjiwh44mntI+U=","Jl3f4SfdUb1yOTR7dY8KEyDrLMdFCswdrUf4DI3PNNY=","GZdQ7EcvGAng9mpUXh5RYkEIrIRQFcKqPfw2urSX2Ko=","FX/z/mWscggRDwal90MCsU10PqJQZ/D/0DL3h8fxzfg=","LknEPEVp3Zxf01rEX8oz8QsVxZBpL4vu/hj0iWrJSQI=","DjX7iZgYkFINSu8rbWUGw8svC2lzwk+oJzE0X/otHx4=","JRrUfLFcTxEF8QmuXpRPG6nZ54BtZn/+xv5yMALguZY=","E9oH3GTUKDaYc+lxYCNGQfi+tW/dBeXzVj+jnZwi304=","DACbhOZQ5tI9wAx9zO90g6VTk5aJ01DNRue4kFX9Rzg=","AR8WscY6hU8BmS45VvQtiwTrZQxtU16wID3sdL79ygY=","DtaeXjg6aI8gnZpWHap5YS8/eNBGetRUhd8HCT82dUk=","BNupSnsM6eIhrK1BRytrvjrsUH9es9M/RjZyJkyfeJs=","Cj8mN9hA86FusJQnHJ0je2A2dX1LtQv3znMv8dT6KOg=","JZpmbxKe6hmPihxQL9s4+jmx8HVWlWS25UpIXRGCMj8=","KL90Wcmy9MbY59BqTuOkf3dF1CcQOOUVejL99+3g1qE=","ChypQfBXA3Um6iAPSJvo1MN8hbvM5qKu7JG9aUFDJEc=","DG+PlYvg6TBT1/1PxUUShVU17RU58FHctDom/ZJjYc8=","EjEGqTzRdXjUJugSisnZCqnooAcI4pbghN1X5pyq+BE=","JuG6Uq2Shdl906tS+OhACF6PqD/x6PGHewdIZ80t7nU=","HLVcrXvRM94YpkxcR7nJfL5Ni3v54JWGRHFTfmpK4sU=","Hc1z5GrNj44OLHzgS95/bSpTBD1QYKQccUPwjm6QVdA=","ARAD4y9tnGb1hS8FR0pN7wzaKUoOtOm5sSubtFEuVXQ=","Kx6AmsHRCrKa1fINA6V9/rrf5ZA/WLr+18UI3SKHrow=","JTneF4W3NZmftNrDXuF+0O+ZXQWrL8X66qaa6HvOwKU=","DCRsWi747gEmSX8iKz4KDvThw9QchtRuQ5gssR13lR0=","GSCJxJdPaOlUCBSPfAYy7bsJ5qatGhwvPwMF9dA7Uns=","Hq4K2KtosvBqDuNu6w0MBYUpCX2RCWt1bY/cL7WmDYU=","F5GQ5dDiIXnkb4KChyq8iNtuL9wN7pnml2i9mMXQa/s=","KbueLJB2cyV26agcesS4MhRSj32wDzG/bK/nlKmzzRw=","Il05TkIgdZlAPv0MJGSpDVJlJkWIKqw1sQ5ZDm5pHgg=","BkdgYjwlyM91PSOAVbREUyvhNVdFHAh94J79RUsj/Vk=","ELo6DgHfkuh/MBxLcW2KOU1n9L9Cp1wQkikQp49rW4c=","DgcL9T+EUbJPnG6WsMKoActRG8DCQuudNht3aT8hRxw=","G5TNYbBRsE3Tl1X/k4Iac8zWyxHSSR2Kp/khAU3iUvs=","HXyzm6+4x0ThSHh6LnAjD51OkX1XE7sFBIe1qn10Bws=","Lskxib0atPaRF9D+mAyA/4eFwpYYKfcBu3SsHzA7F9s=","LbNmv9020nemkruCW4YnW+rEBKGa4HqQgupGvYNReSY=","BiEA60hdsGJpZVzxhqaFMphSdUKEUDWa3JnOxpYHEbg=","B2HTPGZhSqpXDn8egkTKESAkP5L6WeT5AMVnv0H1pZs=","IPxBGhFNE5ksJwWqA04/MV14YIoPfeTM96cuSUhVrQ0=","JbXABKS9/LWt2exOmrIZuhAsZ+iz7/tfw6MPMXJQvFo=","I7GCLSeO1jKklOWPbfb17QOLGG2EdBVa2H59/2Kzf0s=","InNLTFw/lJNgbEupASSZvw8U0Tv8/MyqFhAqKcwvaeA=","JsDI/gnrMLfienTcM0kjR+W9/0Cao2ECVEE9P615XOU=","Bw3QzLa9e7rojqwD+h+7Jhlr4wg6gJgpu9Ym3zSMytk=","ErZZW9sym2+wQ7p4uyjDvsLApt5G2MWtYGfE6/1CUNo=","JI2X1/dig9Y77DDnpYdsEcBvypsnXGccXjPZW7fo1yk=","GjBtQ51GOwgW/G/WTMk5MYtF63Wd3eSqEG0V2b2bqqo=","KKj4Ny48ONrO18AEIctGIfTxtU3cJ4IbDWLT1ux8Vs8=","lJdXF/moqLs1FS8k1DKUBxzjIMgp84i8hSGD4eLOfg==","BNXuTDqnj32A/eYNcWSA01k/dNT2U66D9BAyRtsujWU=","Kmz16aoD1DNjSa1vuO0iace+9UuIIsx20ISVwS794Yc=","IwTTHqq5YLqSdNpD4Z3et/eSGAgI/W5Duq5I1+/Lo/M=","A/2ayGWksqbV5wCXhYFySb/win4HJvy04cEdOdGZ8LA=","tyWN7VK72iJIQE1V7lBEeYr8OiCRkwc/eVTU1jsLZA==","FZ+BraB3F5nsOPyi1L9l67E9OnTzKY2zYnLFymXpLZo=","HvkOZ0N/vIVQI3p1vCjju5AAEw6iXwxUceFEz0JkQx8=","HmX4OFFeX/AZa0mqQaLSVo33ObwXawjslaee2Cky4w0=","KxsEXe86FmzsbOdo0Hm6dLGMhE5XDh+CZXXBBoyUwz8=","CDLldTzrD/ZAJUOxEJIpwWXcLXO+9xXj8cbgfBaLsXM=","AvYU6c7fs9xrdirgo31BurG4QcLotkUbxajjw5C2rRY=","DiQn04vUamDdZAuONiytlnNw67d3vt/0D2oL4n5+1wU=","BJNjC3xnC23rfITUFOfOeQSfDsCYw8fFB2i74pIUpTo=","IurRAOjkgmdN7NqxcGbFomuxUVNV1UYaPcBsyFMnzqk=","JbPlbmVbQs2q4mJu0lVNSFg/GuNWJtBN5QhOC20qbxY=","HjJ1KtqINu9YN6bN6P8T27WZwzY0nkxYS0/cCgz2+dA=","L6KoccFaOHzFD2j288NFWyPACZXwUHj2cqmGQHTUEuU=","L1abippEJMknjh23MR6In1TMvxBmG6t/zRjnx6fYNQU=","BEy0VREKj91TGt5TAjTFGKffk/czL/0hRBZTdLJGtD0=","IngI3pOQbV1CAkYVfy5CsZH+jJCt/hGBeN3HI6UxkCU=","AvzKKTTgRrxiOt6thzV5hl0DeBrgkK1KhXnS56aAA1U=","DvkV8KwSC4dqvMzrNEodNrrT88Wrkajdy+wuBg2L76w=","F5cTD0t6Phd363V7xvKH9qsPuF9r5jsJ87Fu8rFAXTg=","CnYiXcBBcK4zBshaurWeYIx/SXwgFW1NNsZoVV3sxuU=","H/+57BmS1muh53p7kyCa9vj6dtSKy2ZHlhdLUyajGlw=","JXIcT8FaPyhTtXwzj6U42F+Pu6bGucYJBhGIm3l7nF8=","DIF/1C1fekEhXj0HuhlyFq20w3kHBdqV62O5gr/K91o=","E6vj9SOZFdOffhPCwklwtt+M+GzgCiIAK8FYZuUrWpY=","IQb+6lRiJOoS7385mHpGyFwbw9wpvb16ks1grLTTkc4=","IcqFlGinRraqp5R0o32rSfHKWijHSLxxV+GzNFuw+Vk=","BczWJVwebwxc8fDfk0GUxikR0U0DIWYqjxpImZ40GFs=","Dw40pktwpibkZNhGZ0xMiBbE+yZ/5E/m6ihnjLCUkKQ=","BVhTGk4lRwxhV3lMo20Olkfb/P41DWSDj1saii3g1L8=","CdPcqRc+0vrO6hJRV2g9GJJMra0/ZVpgty9YZJYfFFU=","AyjL1U6MCRNJP4Zu0D0hi/I/ktaKrsSGF9THIuW9QzU=","K/ByFuKv8KIjpIexpwlOB+eee8yXmMZI7jNH3VMp00s=","Ha80WlgAa3NkmcWDy3bDFtb3jtam3/yCER4Rpj/kEt8=","F2VjRyRWqqdGtpTGDhgjYR7zkDmy7cf/OR5vIpPSxAQ=","LvHg+tnwjoeju15H1+M1OMqWTSt9EIPU+wIlA1vT+Ns=","ImybGvlbq88XsrH1fHMQF5wYA97Fro8KF3ntNsgXrio=","FLzjVJzD23QoEmtMOhWuD/gUjInxP7NdNXNOtdStDe8=","Lev/FW4na7V0LDNz8mNbSLjpI9MB83L45VDP1ANCEsc=","LUCDz1qH9bb8I5WyLjVrZEGv4baynEet19BDLR1HYMc=","DCJbe80Ev5w0uREmL9ycG5G/eaEMAYTYnDF8U9cWHCk=","AxUhadTz0G7DOnm/rJGgLJmqAgDbZtWqe4NSZfnJyPM=","C2GBGpIQvniwWXRYdIbVi93I9Rv9/ru4ev6LeqfTGZw=","ID4ADK0pjar366alxZIYeLiuSKz3BI8WBG1jelM7b3g=","GkS/CTfHItE3ZnK2n2yWVbp+44b9oREsB1cUPRv6kUY=","A3a0+uCMsD01AK/sGh9WrLjg/edaIQbXAC9ZxWEdTao=","eAryyhytZGWiFxJQ/fwy1vwkHTIUF389VT7zYxghhQ==","EHdNmrgMJb3rgIvt/XKo2bddvhjVIhyH6dhXB5vcMdU=","ENxunABuo4sEseA7S9lJDA0D+Ykpyh1/tWgh/RnTtug=","VEuDOHkVGLLHZFpQOSeYsh91u2DjWWFwBn0AFBysFg==","IiwBF1cYOG8uLoLrEieJ41LhBaO4+oUmE7xTRDPuQow=","KEDQRem8IrJZz7iBGx4PRbd/e9t/fitGFRoUMPYI48U=","BidS+G7r4RoAnJN+RowzWwRVRXTCmQGWUI4B+lhgGGs=","BgQb2sSCBayHrbh8IKR4pxyZUMEqgLwKVajoPqrwR0Y=","BKUz8jbEItH/kAo2iUmwAix6KuCS8wjYKx3Lv1H1AA0=","E+MdemcjL9gR1qlVs9TyXf4GbR59wz3wS95QorLQWyo=","ARwmg66R6037wT1jV+hZmpJ50WSP8sldL3mQW7E5IPE=","Cw0hk0a4V0UlsaJw4LTLpdVsko4+LCvQoeyu0BWq9q4=","FKveyNucbclwKR7mOGkCCbZQgHge+f0T2Ex6cmtfE2Q=","GgtwtLJv3Cj80yqj0mZHiAHrEiAu9HztmI0DdmEL4QY=","J4VDch+W0TB7aUP5gE5/5WQB3rLvmcTRJwSILnJ4tgc=","FutZSUqXds9XhmIU29FHPz8HOKMlY42Lo2U14BHVglk=","JWemWKgf+0RPJACI+lUkxpqeU+6ra3+MQcNHnc+MZEo=","KaodfBUemtCnqznxq9nPd6t44CFaVxWmuIKt6EC7E9g=","FcCRIz5g7+DUu/zis2QVAGpPAX+ahTiM4ga5H5nyyYQ=","Fr19Iv+Fjl4IgsLJmVWNd+dnOtXxkV+f62eagRXwFM8=","AttQSAoHvg6ywuE+1u9AdMAYLZtmi44I/+Z2klAEICU=","BeSiIOajvJ97aAbsnWzboYYzDvK/ettME7qGY0O3MRk=","HdoF68MBcLyYy/Kl7jtQ6LX3C8Qk05+kEE038cvPekI=","AYS+9yGIgYf2Rbb+42Z/PJHaIUQU2JulzTAfIrDeiZA=","FJijB+aJAAZfXoJ29irvHDdBS4RJThV3rRptZDQbeOw=","JfQPgrMdrMT0k5gAudLD6s73N7j6sfhk/jNUitRr1J0=","CdMXzGcCUZQ/b1hiow0uqegwVs5JB7+7yx/zHOW7llA=","L3fXd4bZebI7pM5KTBs70KQRMs1GeoarKbkTts8xSdA=","D1Pa/VNan0Rz3CZrb8zGhBu9M2lj8lTBUvieeF9ym78=","JcH9cuIjBFJlw6CZ4XUm+g5pduHAC68W3pbehd7vL6I=","KpAsiYDBf6rjaNOF1S0WvkGvlchOrqPPiT5l1s5Kj2I=","HOFYCjRS7PMCh4yJdrgr6WZ23RFNHcjSVSdAV2L4NSk=","JKYHP5Gt3DOkmh+jBt8AiAHF7FaWCQNNL8UPfw9NAFY=","JeUtvWEkUw2fwn/jBtcdRYPgfKVUtdFXfyVsaLC+K3Q=","I9/648Qj+nqTRo28z7AphVl0vk0KeymUZ5blts1w8V0=","BjQto3DMDYxJt3WU9rAnxIBhXVC+NiQ6mVkbyZJO1vU=","J1QRQoEoZUa3XwnxFfx1G0d4MD0EBcG0zH3w2On2OSU=","FcGehTTFwaiGLCvB0Rnt3qvyFBU4M9e9tZ7hl/gYfPU=","Jl/gYnZtCPq0x40NnvPKvjZvO+CoIQYWebSz0td9Xz4=","E8z2idZ6PsnyLLfNCsOjJ9N3rFzQFG8Ejev9CY0+x74=","F2YvdFZ4lzn4HNOXSCeoh9kqXgW98/5rn7zMpFJKrr0=","IbKcdjKbMcjvGGMeUV9/L4LKalzKcM7k6An9YkvnrV0=","GBN0eDgqrbpEHrl/4nkBmJwGc4FlIVMZk56xewH6l1w=","K8B+or+taOjcck9f7ys3wtNPdhk1/9O3Oc7sRmjzfog=","LdsuN29U1kpWOEBIDfmT/rQXMgPCvZStDmAgd675oD4=","J361DyuqcGEGtByyTGAmCeiiD41y9hNwitslNzWWw/c=","DU3kfhq6NCadDGIJBPAaVrM/xLRQwNtQu3+Hc0yaH+U=","C4RCv+nkobRChnO2vT7qb59EVpcFjxNKrpCNAnminww=","Ef5bGPu+oahuBpMMuJ99SibhhqZZRelldCR/3bcg+PU=","IkAm9t+vceJNJdj22fkAId9bd03K1NiDFw5K2JwzoNY=","CyymqZn+aIfgcE2tWNA0ZalryeN9EJH2G8n5xiu+uCQ=","Ihtj1m8LRfnUDFQFOiigax0KTOQdNkeXoafgyWUp9CE=","MBhcSLey8dU9QSCAGwR9CHSTvOZNTSSu3OL0g2u4StQ=","I/XTcqPw48upieIjBWIn01MzVvD6pI8n+CZzGGMqYfA=","JxZoOzLHVf0b+CNeoWKx84jh4AkNBhYujm375DKPPjs=","CXdUWDaGb6IEyh2FPsCQnj0UB3DICsZ9yTDGl0jV1Lw=","FETo9ZK9v9gCXZGrSYLdQl9RaC0xRysF6BxDwPlDSzE=","JuBLZenKgnC+t0ocXLj+6L4/+/5YP3ASoA+HTncY++M=","IqXC+oYNEf407kelzZ+GmAD0j0/r4prW32mBb7GpFNI=","F0tU2ZB9j1xq/Wcqc49Cc37DOPOglkxin3R03UTFyNc=","HbHbiqRSg/MRaPpmaUzygI0hibh8jIFD1WyHGQezm4c=","FTC/D0ZSfoiQMLjHt9/eEm9l+vjM4KtmOHNB2BPRv9E=","C3P2E5kyKfWfAcHOyHYOmTbq2e3I8oFIiTMKLyut5Fc=","KcJaIv4hZGBFUqrqN39EjVh6uXf8gid4e9LcDza89B4=","KzDVPtF1m/uFA9pmySz0B3q+gnldwnKzd99X13yHVSY=","EvbXA7VwKqt7e35pNZ1TonVsCMhe3nInz18KKRZ4fNI=","JSDhgwCv2j9hpAoLiDcpOlWtAQcQKNSEH/qaxwY2QRM=","Hsna6oYJcezdqO1PNG+pZ6ybxZJ4J3OTxo8J+gO4uV8=","Cpmz4XjbLi5DL1zVvvj+RIO/XL9w7UB8CKriS4MK1yU=","B82p5j22458Ia4m2AcK75AfuCrrDyBehMXq618V3hJI=","CMnGWk+VXolS1XGxkbsK20m9gpCWMgOzXUiqs4+Pw6M=","Jzf4zh1aZ7NJWQ3b+9cJ7Zr1Sio/JxnTOAHJwXvdnJ4=","EEmmxl/wGfDSh3AHJ5jot5CUMr0MEpgTqfF5umJ/fWo=","GLT+locyxGLA6lqb6yfOy96IaJRP32TuYKUSI2Ha7ds=","L/K2/SLfSdJECy6u7vqMAqb0eM/PEfGypPdHNIOIXRk=","LsXy8ZKP6TLlbHibj2u8s+i+QFfL2NvRihs1L1zvQv8=","JlpezNi5KXXjOtn3W/NCbUJKTGp3lO4/CMHRADeOVF4=","JAXqpMC94RKdYkK7WtoOaHeOZWz8s2a/IFF9od/UJ5w=","CUyX2MGUxC6IAYAEy78rxf21GVXYstZrdt2Yotv2BBc=","LDDV8zuzLFwiuZeaYFv2TVCLcFIh5qaGMwyWJcKv4Lg=","AadWZvYkH2gl0BzG3LFiLUiG6lg+hymeaqL8cW/bbPU=","CjKQ6DmBE+pNEqwJHoe+fG01mrmmaXn89Hvy6H04L8s=","FUrenKNuJo3+s4RhQluw2MMSGdj6Dfx17NIb9pqgzHQ=","J6qNPiU4DAsbFy15xvIu7pkjHvXcadjcE6S1CV0Ch3I=","LPQFHmyrSDAaiy47ymCZ11a730ha+h9UnTlbvL2AZGE=","MB5w9ynzyUsdP1F93/nyAVEx/quK+l7rsIQ9f4SyPnE=","KYvrZPgS0l2LTZYgNHqwIzLcTO8ROuYNF6jXpMkfg7w=","GzYucqX4R/hNA/0pHDxHHtHBShWyIWgKzxGj8C5GqpU=","DciiFGEQwLN1QykCmZIj1aoe9ueOHl68vB2bpB3Bxzc=","CkhmOzTOXhwF3JMJLLaXeMshcppy3cA6CK+h65Iv8nk=","Coc5H7HNjN9glrZKgvnpXw/kbxQ7cC10VFuzFIgQmO4=","G1spRvfCiXXwUS/45so2L4gm7dfqnCnzgrqKKgiS/V0=","AQAc9RKsJB1H6+Ijkhm8ahc6i7y4pbmHtOrB9TMxW2s=","L9l3xw9kXbT3BPp9dpPacnrAk9P7X1/rxyvrF9g1ijI=","I8ADmj+rStPC18xogWTznnYdU1XAVETZm+djqXeTqcQ=","GdQ+4MYIHAUsnA32Fh6qwa7DVs9DWIjnnyfyL/A/ol0=","LZsQwvLnrBr93M/9lKVjAovym2RtAggwkZ+dXKHO/lk=","JFfKbC8qow7Efkr/Wmb1zieZKD4Wb8gc2uLyufg+Qmc=","Crw5L+he2oVYIFkkRQlAIoEe6Gdu1vDDBE37VKfBCzU=","GdLMXKVJ0dQM68038+pU8xFhrDmTrPMQHSwrww6sHrA=","D5euMDP/oBYIqvsmrhPNOT7g5OwEG6ZEo9OrVG6Yycg=","FtvHj9KLf7gmDkBM8dQnp/oVU36k4WjoihZkluiM/so=","JA+vKPEUmbkW8IX3O8TyLu+DROV2+K09GCeCA2bV4Hs=","Chuwdao3/wz+bIUx5V4XcOq6gIyP222/RvjKtY2e8a8=","LkfhXqSkf/GmqFOq86ZEyjjVsIWsEEL9xKcFp84In00=","Fm5b8HM3g0iGDKSpwJ054Wc6sFmTX03zX7FFKDdXcrY=","GLQtf/3S6k+vI1kC8FeidAyszNAnIzAB7RD5ZTjwkW8=","CJyxsDIjj15JFHiOPjx+rU/DaAILPtOCId6rEFHDdwI=","JCrNPrOi9yuvfHB23RZa34n5M5x7lxkh2ecIY0Ud2NE=","F0+7EEpO4wK/R/K9gvzolurJoGgoPzJkdK+GBFckXDs=","FzQOcdlvRm1h8wWM4JLGfSiR+yuzGGE/eAwnX+ERbGs=","Ho5ArIU7fULwDy44OYLQJPCYufj9RVlTov04DE339rI=","BSmJjcBkmQfh1NXihLjRB1GYxVytZuipv0D5KTji6WE=","IWJ1TbC6oDC/feW7eXNk3OjHeqAX7h179l8hxNTl348=","EsdVNpjEv2886yUK4AxYwqn5KR773kyEIb70R0F1LsY=","KSZD47ogJq/8uMUnkxO9UaczyTNT6dnHnLcjE2UmUI4=","zPE+DLb52B1SlRvqmQvVtsB8XZjmb/cdtudNW4fRWA==","GF0eIOI7CRfdZUEozy86qrZyOHPLMPwisPhsFatkW0s=","FMYcg21V0990K98Rxg76GGd4494PAkwPE/5T+Nh2Th8=","DzVoQbP1Vvzl2+RoBFdpHCkZ4q9TAIGE0D7hGV1yRJ4=","G4/Z/zlxTgdd8ST4h79As4MUM3T9IIC6DAprbo+ls+g=","DoaowgCcFAyj+HOSTiqqFPw8iuBOnfCz6RA0GHlvYCQ=","LmxeiY9VR3cOVGKtky/N0jc/xDggyisWsIYUIeeRVcg=","BdeX8as2RyN8FPnR3wMryf+f4aDs03eXLOX9WgwBRgQ=","KaMRBGOlqudsPRUodZgdDB2vLc1lUZ71yokphR2owAg=","KXTae8B0MiJzw6S5HAU1TNxxZAqLvR+GS3MvgWOIMxQ=","HtD7BmmbokmyowYhwF6xLKKcuRqggsi/zOnFIoibR9w=","HHk+8NzFESNlT/JtjYY/7q4p6MVy7KkS2AyK425A/ps=","HmqsHG090xV5ViV9PSNO8YyR6CWJp4Fp+7Sodwl33C8=","GiCtp1diNO7mJz3W+piyXtA3dICApH2Uj82jMlb7a/U=","GRAz1thc6qb8epojpv2ZlmQtdyBF7OUTNdSTBnKK+Ww=","bll52n5+9TqCWqb93Dq/x28gCzdAuLIy70gfXQYpew==","Cw1+acZRkQu+8+aNQX6foPvVf1lsjymDHv+MAXTNsG0=","Jcr1sMG5O8UWQ17AhOLs1ErEbbuwM8URLEsgolyc350=","EsHqiSzDHg2a+LeW2WRYcvf3dELWL9TICFsvFQ9yRyo=","Fq8paVFXq6m4u+Ov6yRf7uWpKdn5KLm4Heba3HjDKq4=","ATbfRXyAWI3Wh/svO+GGkXBbh+xaTP3BaNMQhCVrZ9w=","FjmijFtMgRZq6phPum5xR54Hse+8dENNuVooUGDnsIk=","A9Yvv4L9HUMT+OZQ9YfsBoFsKLcAvcUPfiMr2bXKm3Y=","Ea7rUn3IzkS00Uqt3KPP4vd6HkD8bal8JJgw3h7f3lQ=","E/m5pBJ0EpR5xeYTjGyO42pnDmvGjHpJZCtkWAe/yCQ=","Dkdy+j11F53ISEzSbHwfY13e7tepOUQMUGyui3680Vs=","GzmgDLyB5CfeS97Fj+vo2LWXF1IGemErOfxGpoxdTbQ=","K+22bhrVodVx4W4pU/SHMfZkY8LrVKJFRE0cCjolcH4=","LPCgmlXKk6+KvQaPBqcof7CLGTtghYKic3nONdqRXew=","LRvXj6kOd6qIgwyr/vL40n0aUSBQun2wdTyPuGPvs4c=","BlYQxvT5JJH0I9MHHrg1OffA1JwThwYuYw1/0oPcM5Q=","LZM/8ZIXpVRQE7Eoc0Ur68xfmWkDPxXsZC+0ZL1gc2g=","GqnT/kxkSRD3a5Kz4Tsw1QDa5TVOeVCMPEnIqpngJYs=","An7wSGnkgrHHSGOMWREcaycJX6dz4aygeM6h8chFC90=","K31STFFyy7sV204AZoqMRJ9nomBdnsA4AuP6E2rQuPs=","DHw4JEPGqnh8hxjYZ0fH90aTriWx5V3xP3w8Hdc12w8=","tFZxhrw/fGKntWrPT3Ygeh9DwtMND+SmJ9zdm9eQeA==","HkH8KbglRU/m1hc3/gi0f7B/5znkweYdAzdJCIPbT9U=","ElB81Va3u8xy7m2vxhZYRCHhr4ctjA6JACro07oGU7Y=","E9Q3CDVTAGvO8xLl5vUqXZfrNmF+82/k130+l/cctds=","Fj7HMlH4VENociJIfdqaZUZ9kLIvCzhmRoYHfGpEhtU="],"M":[["I20TOT74XMSKNR3Xht16HeXjmUIpYSf9h5RyI65RCK0=","J3aGSU92RLvEqbGU4Qck65Z/HcWHGOWePO3IIbKnrhk=","Aj22h4Tj8MwLhWGIJqmzUFEpwWR5lzsKhKRSnmawnGI=","HTWdJF8obBLVDWY7rnM/l4rwjNvWMBfFezp1ZG/zgsE="],["KnWhcVY7gH21Jb4llpmrKP6bx/sfcJQ/8Em8lw6EGgw=","CDq/9eEAUfB44oJ9CS4a6Ai03T4VzMNwbzjOQVe2dw4=","GlrXG7vs2Kl9xJz9uuMDrSTVxHQeq4t1aKn/glOh628=","DXRf0A3RZ/uGdyEzZA8CzpRQBKe8LFnoeQ9yXF2E8K8="],["IHBnnnmHgu9ZKlLKnO+CDUl60u7Lqn5C82az5SHE7UI=","LhjIVw0gv134AHOaU9p12Qbs4xjNIkq2s6K+l54tfqs=","D6hvDyfk091/M2fOhvaE8fLkOG0+W584+ig8aqcjtgg=","A/Pm+reR8WYoFo5LFNuutlcDXuPaayyoPwwkkeC0A+s="],["L1ReV4ICyXMkiFQOQfeDto/wYT/Xk3X4uos9MJWOdnc=","I4EL+Ch3/Bm/9+7+rj+vS7gQTDK6TNcBWWoVYj0BR24=","AU/NXrC+bVvur8SUQDTPMhwGjvkw8QviIH7VjSo0zdY=","wV/DodVzPdg16uCCPjd/i6SotidifMK7Zhwl0g+1Kg=="]]}};
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

// Every request goes out on a connection of its own (Connection: close), so the gateway cannot tie two requests
// together by the socket they share.
const net = (url, init = {}) => fetch(url, { ...init, headers: { ...init.headers, connection: "close" } });

async function rpc(method, params, url = RPC) {
  const res = await net(url, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }) });
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
  const res = await net(`${SITE}/api/v1/used`, { cache: "no-store" });
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
    const res = await net(`${SITE}/zk/${name}`);
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
  return { secret: BigInt(j.secret), next: Number(j.next), pending: (j.pending ?? []).map((p) => ({ start: Number(p.start), cost: Number(p.cost), x: BigInt(p.x) })) };
}
function save(s) {
  mkdirSync(HOME, { recursive: true, mode: 0o700 });
  const pending = (s.pending ?? []).map((p) => ({ start: p.start, cost: p.cost, x: p.x.toString() }));
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

// The price `buy` agrees to is read from Solana through PARANOID_RPC if you set one, and otherwise through a
// public node, never through paranoid.red's relay: the gateway that sends the bill does not also say the price.
const PRICE_RPC = process.env.PARANOID_RPC ?? "https://api.mainnet-beta.solana.com";
async function priceOnChain() {
  const acc = await rpc("getAccountInfo", [CONFIG, { encoding: "base64", commitment: "confirmed" }], PRICE_RPC).catch((e) => { throw new Error(`Could not read the price from Solana (${e.message}). Set PARANOID_RPC to a Solana RPC you trust.`); });
  if (acc?.value?.owner !== PROGRAM) throw new Error("The PARANOID config read from Solana is not owned by the program. Nothing was signed.");
  const c = b64(acc.value.data[0]);
  return new DataView(c.buffer, c.byteOffset, c.byteLength).getBigUint64(53, true);
}

/** Makes a new secret here, pays for `questions` with the wallet in PARANOID_PAYER, and keeps the secret for the connector. */
async function buy(questions) {
  if (!process.env.PARANOID_PAYER) throw new Error("Set PARANOID_PAYER to a Solana keypair file: the wallet that pays the USDC.");
  if (!Number.isInteger(questions)) throw new Error("Say how many questions to buy: node connect.mjs buy 500");
  const payer = wallet(process.env.PARANOID_PAYER);
  const secret = randomField();
  const url = `${SITE}/api/x402/join?questions=${questions}&commitment=${commitmentOf(secret).toString(16)}`;
  const first = await net(url, { method: "POST" });
  if (first.status !== 402) throw new Error(`Could not get a price (${first.status}): ${(await first.json().catch(() => ({}))).error ?? ""}`);
  let req, resource;
  try {
    const required = JSON.parse(Buffer.from(first.headers.get("payment-required") ?? "", "base64").toString("utf8"));
    req = required.accepts.find((a) => a.scheme === "exact" && String(a.network).startsWith("solana:"));
    resource = required.resource;
  } catch { req = null; }
  if (!req || !/^\d+$/.test(String(req.amount)) || typeof req.extra?.memo !== "string") throw new Error("The gateway's price could not be read. Nothing was signed.");
  // The wallet signs only what this computer expects: USDC, to the gateway it knows, at no more than the price
  // the program on chain sets plus the published setup fee. A gateway that asked for more gets nothing.
  const most = BigInt(questions) * (await priceOnChain()) + SETUP_USDC;
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
  const payload = { x402Version: 2, resource, accepted: req, payload: { transaction: paymentTx(req, payer, fromB58(blockhash)) } };
  console.log(`Paying ${Number(req.amount) / 1e6} USDC for ${questions} questions from ${toB58(payer.pub)}...`);
  const paid = await net(url, { method: "POST", headers: { "payment-signature": Buffer.from(JSON.stringify(payload)).toString("base64") } });
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
    const j = await (await net(`${SITE}/api/v1/models`)).json();
    models = { at: Date.now(), list: j.data.map((m) => ({ id: m.id, cost: m.cost ?? 1 })) };
  }
  // The gateway sends an unknown model name to the default model, which is listed first.
  return (models.list.find((m) => m.id === model) ?? models.list[0])?.cost ?? 1;
}

let state, warned = false;
const sending = new Set(); // starts of keys on their way to the gateway right now
/** Forgets a key's numbers once the gateway has answered it or refused it for good. */
const settled = (start) => { state.pending = (state.pending ?? []).filter((p) => p.start !== start); save(state); };
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
  if (!again) again = (state.pending ?? []).find((p) => p.cost === cost && !sending.has(p.start)) ?? null;
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
    state.pending = [...(state.pending ?? []), { start, cost, x }];
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
    if (!again && state.next === start + cost) { state.next = start; settled(start); }
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
    try { return await net(`${SITE}/api/v1/chat/completions`, { method: "POST", body, headers: { "content-type": "application/json", authorization: `Bearer ${k.key}` } }); }
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
    settled(k.start);
    k = await freshKey(cost);
    up = await send(k);
  }
  // Answered, or refused for good: the numbers are settled. Only a 5xx keeps them for the next request.
  if (up.status < 500) settled(k.start);
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
    if (req.method === "GET" && path === "/v1/models") return await relay(res, await net(`${SITE}/api/v1/models`));
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
    const j = await (await net(`${SITE}/api/v1/models`)).json();
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
    if (msg.method === "initialize") return reply({ protocolVersion: msg.params?.protocolVersion ?? "2025-06-18", capabilities: { tools: {} }, serverInfo: { name: "paranoid", version: VERSION } });
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
