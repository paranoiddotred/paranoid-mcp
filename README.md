# PARANOID MCP

Ask AI models in private from Claude Code, Cursor or any MCP client. Every question carries a fresh zero-knowledge proof made on your own computer, so the PARANOID gateway can check that it was paid for without learning which member asked or tying it to any other question. To keep your network address apart as well, see [What stays visible](SECURITY.md#what-stays-visible).

[PARANOID](https://paranoid.red) runs open models such as DeepSeek, Kimi, Qwen and GLM, including uncensored ones. Questions are bought once with USDC on Solana, and agents can buy them on their own with [x402](https://github.com/coinbase/x402). The Solana program and the circuit behind every proof are open at [paranoiddotred/paranoid](https://github.com/paranoiddotred/paranoid), and that source builds to the exact bytes deployed on mainnet.

## Install

It is one file with no packages to install and needs Node.js 20.18, 22.8 or newer. Download it and check it
against the current [release](https://github.com/paranoiddotred/paranoid-mcp/releases) in one go:

```bash
mkdir -p ~/paranoid && curl -o ~/paranoid/connect.mjs https://paranoid.red/connect.mjs \
  && echo "8f90ee28b74883a46dcf928efaecfcd452591753851283210edf2788cbdd73c1  $HOME/paranoid/connect.mjs" | shasum -a 256 -c
```

The file paranoid.red serves is byte for byte the `connect.mjs` in this repository, and every release lists its
SHA-256, so a copy that was changed anywhere on the way fails that check before it ever runs.

You can also build it yourself from `src/` and the prover and circuit files where they are published (snarkjs
0.7.6 on npm, the circuit in [paranoiddotred/paranoid](https://github.com/paranoiddotred/paranoid)). CI does the
same on every push and fails if a single byte differs.

```bash
bash scripts/fetch-zk.sh && node build.mjs && git diff --exit-code connect.mjs
```

**Claude Code**

```bash
claude mcp add paranoid -e PARANOID_PAYER=$HOME/agent-wallet.json -- node $HOME/paranoid/connect.mjs mcp
```

**Cursor** (`~/.cursor/mcp.json`)

```json
{
  "mcpServers": {
    "paranoid": {
      "command": "node",
      "args": ["/Users/you/paranoid/connect.mjs", "mcp"],
      "env": { "PARANOID_PAYER": "/Users/you/agent-wallet.json" }
    }
  }
}
```

`PARANOID_PAYER` points at a Solana keypair file (the JSON the Solana CLI writes) whose wallet holds USDC. It is needed only to buy questions. If you already have questions on [paranoid.red](https://paranoid.red/app), run `node connect.mjs` once and paste the connector code from the Keys tab instead.

## Tools

| Tool | What it does |
| --- | --- |
| `ask` | Asks a model a question with a fresh key and returns the answer. Takes `question`, and `model` and `system` if you want them. |
| `models` | Lists the models and how many questions one message to each costs. |
| `balance` | Says how many questions are left and the last day they can be used. |
| `buy` | Buys a new membership with x402 from the wallet in `PARANOID_PAYER`. |

Questions cost 0.002 USDC each, 250 at least, plus a 0.30 USDC setup fee when an agent buys with x402. The gateway pays the Solana network fees.

## How it stays private

When you buy questions, your computer makes a secret and sends only a commitment to it, which goes into a member list on Solana. For each question, the connector proves in zero knowledge that it holds the secret of some member with questions left, and marks one numbered question as spent with a nullifier that names no member. The gateway verifies the proof and forwards the question to the model, but it never learns which member asked, two questions cannot be tied together through their proofs, and each request travels on a connection of its own. Your network address is a separate layer: [SECURITY.md](SECURITY.md#what-stays-visible) shows how to route the connector through Tor or a VPN.

Spending the same numbered question twice reveals the secret. Anyone can then slash the membership and recompute every question it ever asked, so keep each membership in one place. The connector writes each number to disk before it is used and reads the public list of spent questions before every key, so this cannot happen by accident.

The design follows [zkAPI](https://github.com/vbuterin/zkapi) by Vitalik Buterin and Davide Crapis, from the Ethereum Foundation and the Open Anonymity Project. PARANOID brings it to Solana.

## Use a PARANOID key in any OpenAI app

The Keys tab on [paranoid.red](https://paranoid.red/app) gives a key that starts with `sk-paranoid-`. It works like an OpenAI API key, so any app or SDK that lets you set the OpenAI base URL can run on PARANOID with two settings.

```text
Base URL  https://paranoid.red/api/v1
API key   sk-paranoid-...
```

With the OpenAI SDK for Node.js:

```js
import OpenAI from "openai";

const client = new OpenAI({ baseURL: "https://paranoid.red/api/v1", apiKey: process.env.PARANOID_KEY });
const res = await client.chat.completions.create({
  model: "default",
  messages: [{ role: "user", content: "Explain zero-knowledge proofs in two lines." }],
});
console.log(res.choices[0].message.content);
```

With the OpenAI SDK for Python:

```python
import os
from openai import OpenAI

client = OpenAI(base_url="https://paranoid.red/api/v1", api_key=os.environ["PARANOID_KEY"])
res = client.chat.completions.create(model="default", messages=[{"role": "user", "content": "Hello"}])
print(res.choices[0].message.content)
```

With curl:

```bash
curl https://paranoid.red/api/v1/chat/completions \
  -H "Authorization: Bearer $PARANOID_KEY" \
  -H "Content-Type: application/json" \
  -d '{"model":"default","messages":[{"role":"user","content":"Hello"}]}'
```

`GET https://paranoid.red/api/v1/models` lists the models and what one message to each costs. A model name the gateway does not know goes to the default model, so apps that insist on a name of their own still work.

The key is a bundle of proofs made on your device and stops working when the day ends. For an app or agent that stays on, run the connector instead: it makes a fresh key for every request, so nothing ever expires.

## Other ways to run it

The same file serves the OpenAI API on your computer for any app that speaks it.

```bash
node connect.mjs                 # serves http://127.0.0.1:4141/v1, any API key works
PARANOID_PAYER=wallet.json node connect.mjs buy 500
```

Full documentation is at [paranoid.red/docs/agents](https://paranoid.red/docs/agents) and [paranoid.red/docs/connector](https://paranoid.red/docs/connector).

## Files it downloads

On its first question the connector downloads the prover and the circuit from paranoid.red and keeps them in `~/.paranoid/zk`. The prover is snarkjs 0.7.6 exactly as published on npm, and the circuit files are the ones published in [paranoiddotred/paranoid](https://github.com/paranoiddotred/paranoid), so anyone can compare them. Their SHA-256 hashes are written inside `connect.mjs`, it refuses to run anything that does not match, and the prover runs in a separate JavaScript realm with no network, files or process to reach, so the proof is the only thing that leaves it. [SECURITY.md](SECURITY.md) has the details.

## License

MIT
