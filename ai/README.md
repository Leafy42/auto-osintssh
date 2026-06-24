# Open Models → OSINT Workers

Research + a working harness for turning **open-weight LLMs** into OSINT
reconnaissance workers that drive this repo's recon runner
(`bridge/pipe-server.js`), reason over tool output, extract entities, and write
an intel brief straight onto the Holotable.

This folder ships three deliverables (all requested, all here):

| File | What it is |
|------|-----------|
| [`PROMPTS.md`](PROMPTS.md) | Model-agnostic **prompt pack** — system prompt, tool-selection rubric, function schemas, report template, few-shot/fine-tuning seeds. |
| [`osint_agent.py`](osint_agent.py) | **Python** reference harness — zero-dependency (stdlib WebSocket client + urllib). |
| [`go/osint-agent.go`](go/osint-agent.go) | **Go** reference harness — single static binary, stdlib only. Built for the air-gapped box. |
| [`prep_dataset.py`](prep_dataset.py) | **Dataset prep** — filter/dedup/augment/split recorded trajectories into train/val JSONL. |

Both harnesses were smoke-tested end-to-end against the real runner in simulate
mode (handshake → tool loop → entity extraction → `board.json` + `report.md`).

> ⚠️ **Authorized use only.** This drives active reconnaissance. Operate inside
> a written scope. The design keeps three independent safety gates (below).

---

## 0. TL;DR recommendation

For *this* project — a workstation-class OSINT worker you can run today and
fine-tune later — the realistic build is:

- **Run now (no training):** an Apache/MIT open model that's strong at
  tool-calling, served locally with an OpenAI-compatible API, driven by the
  harness here. On a single 24 GB GPU that means **Qwen3-32B** or the
  **Qwen3-30B-A3B** MoE (or a **GLM-4.5-Air-class** model) at 4-bit. These are
  the best agentic tool-callers that actually fit one card. *(web-sourced for
  2026 versions; verify the model card)*
- **Specialize later (cheap):** **QLoRA-fine-tune a 7B–14B** model on a few
  thousand distilled tool-call trajectories. ~a few GPU-hours, **under ~$20** on
  one rented A100/H100. Bakes in tool-selection discipline + your report style.
- **Don't fine-tune the facts.** Tool output is the live intel — keep it in the
  loop (what the harness already does) or in RAG. Fine-tune *behavior*, not
  *knowledge*.
- **Escalation order:** prompt → few-shot → (RAG) → fine-tune. Prove a prompted
  baseline with the harness first; only train what prompting can't fix.

---

## 1. Which open models (mid-2026)

> Confidence note: assistant training cutoff is Jan 2026. Families and licenses
> below are solid; **2026 version numbers are web-sourced — confirm on the
> official model card before committing.** Sourcing in §8.

### Pick by what fits your hardware

| Your hardware | Realistic models | Why |
|---|---|---|
| **1× 24 GB** (RTX 3090/4090) | Qwen3-32B (Q4/AWQ), **Qwen3-30B-A3B** MoE, GLM-4.5-Air-class, Mistral-Small-24B, Phi-4 | Best agentic tool-callers that fit one card. MoE (3B active) is fast. |
| **48 GB** (A6000 / 2×24) | Llama-3.3-70B (Q4), larger Qwen/GLM MoE | 70B-class dense reasoning; note Llama's custom license. |
| **80 GB** (A100/H100) | 70B at Q5/Q6/AWQ/FP8, mid MoEs | Higher-fidelity quant, more headroom. |
| **Multi-GPU rack** | DeepSeek V3.2/V4 (MIT), Kimi K2.x (Modified MIT), GLM-5.x | Frontier long-horizon tool use; giant MoEs need the **total** params resident. |

### License cheat-sheet (matters for internal/commercial security work)

- **Cleanest (Apache-2.0 / MIT, no MAU caps, no field restrictions):** Qwen3
  (Apache-2.0), DeepSeek V3.x/V4 (MIT), Phi-4 (MIT), Mistral *Small* (Apache-2.0),
  GLM-5.x (reported MIT).
- **Permissive with a catch:** Kimi K2 ("Modified MIT" — read the modification);
  Mistral *Large* (more restrictive terms).
- **Custom / restrictive — review carefully:** Llama 3.x/4 (Llama Community
  License: 700M-MAU cap, EU multimodal carve-outs); Gemma 3 (Google Gemma
  license, use-policy restrictions, requires acceptance).

### Best at the thing that matters here (agentic tool use)

Tool-calling + multi-step + structured output is the whole job. The
consistently-named open leaders in mid-2026: **Qwen3 / Qwen3.x**, **GLM-4.5-Air
& GLM-5.x**, **Kimi K2.x**, **DeepSeek V3.2/V4**. Benchmarks to check yourself:
**BFCL** (call-level accuracy; v4 adds agentic/abstention) and **τ-bench /
τ²-bench** (task-level completion over a tool-call chain). The harness's tool
schemas are standard OpenAI-style, so any of these works without code changes.

---

## 2. How to serve a model locally

The harness speaks the **OpenAI-compatible `/v1/chat/completions`** API with
tool calling. Three good servers:

| Server | Best for | Tool calling / structured output |
|---|---|---|
| **Ollama** | Easiest single box / offline | OpenAI-compatible `/v1`; tool calling + JSON `format`. `ollama run qwen3:32b` and point `--api http://127.0.0.1:11434/v1`. |
| **llama.cpp `llama-server`** | Air-gapped / CPU+GPU / Apple Silicon | OpenAI-compatible; **start with `--jinja`** to enable tool calling; JSON-Schema → GBNF grammar gives valid tool-call JSON. Single C++ binary + GGUF. |
| **vLLM** | Throughput / multi-GPU server | Most complete API; **guided decoding** (`guided_json` via xgrammar/outlines) is the biggest reliability win for tool args. |

**Reliability tip that matters most for small local models:** turn on
**constrained/guided decoding** (GBNF in llama.cpp, `guided_json`/xgrammar in
vLLM). It masks invalid tokens during generation so tool-call arguments are
*guaranteed* to match the JSON schema — this eliminates the parse-failure/retry
churn that wrecks agent loops on ≤7B models.

Quant guide: **GGUF Q4_K_M** = best size/quality balance (CPU+GPU, llama.cpp);
**Q5_K_M/Q6_K** near-lossless; **AWQ** = better accuracy same bit-width (vLLM,
GPU-only); **FP8** = native on H100/H200. Rough VRAM: ~0.5 GB/B at 4-bit + ~15–20%
for KV cache; MoE still needs the **total** params resident.

---

## 3. Run the harness

```bash
# Terminal 1 — the recon runner. SIMULATE by default (runs nothing real).
node bridge/pipe-server.js --fast

# Terminal 2 — a local model
ollama run qwen3:32b            # or: llama-server --jinja ... / vllm serve ...

# Terminal 3 — the worker (Python)
python3 ai/osint_agent.py \
    --target example.com \
    --objective "map the external attack surface" \
    --model qwen3:32b \
    --api http://127.0.0.1:11434/v1

# …or the Go binary (build once, copy anywhere)
go build -o osint-agent ./ai/go
./osint-agent -target example.com -model qwen3:32b -api http://127.0.0.1:11434/v1
```

Outputs land in `loot/`:
- `example.com.board.json` → **Import (⤒)** in the page to drop the AI's
  extracted entities onto the canvas (schema matches the board exactly).
- `example.com.report.md` → the intel brief.

Because the runner **broadcasts to every connected client**, the Holotable page
(if also connected via dock ▸ LIVE PIPE) shows the raw tool output filling in
live *while* the worker reasons over it — the "pipe into a VNC", now AI-driven.

### Real, authorized engagement

```bash
# Runner: real execution, locked to an allowlist
node bridge/pipe-server.js --exec --scope samples/scope.txt --timeout 120 --out ./loot

# Worker: enable active tools, enforce the SAME allowlist client-side
python3 ai/osint_agent.py --target acme-corp.com \
    --scope samples/scope.txt --allow-active \
    --model qwen3:32b --api http://127.0.0.1:11434/v1
```

### Key flags (both harnesses)

| flag | effect |
|---|---|
| `--target` | apex domain / subdomain / IP / CIDR (validated) |
| `--scope FILE` | allowlist; **deny-by-default once set** (mirrors the runner) |
| `--allow-active` | permit active tools (`nmap`, `httpx`); off by default |
| `--yes` | auto-authorize scope prompts (non-interactive runs) |
| `--max-steps` | orchestrator-enforced step budget (default 16) |
| `--max-obs-chars` | truncate each tool observation (head+tail) before it re-enters context |
| `--out DIR` | where `board.json` + `report.md` go |
| `--record FILE` | append the run as an SFT trajectory (JSONL) — see §5.4 |

---

## 4. Architecture & the agent loop

```
 LLM (Ollama / llama.cpp --jinja / vLLM)  ──OpenAI /v1 + tools──┐
                                                                │  ReAct loop
 osint_agent (.py / .go)  ◀─────────────────────────────────────┘
   │  tools the model can call:
   │    run_recon(target, tools[])      → drives the runner
   │    add_findings(events[])          → records entities
   │    request_scope_decision(...)     → human gate for ambiguous scope
   │    write_report(markdown)          → ends the run
   │
   └─WebSocket──▶ bridge/pipe-server.js ──▶ subfinder/amass/nmap/whois/…
                       broadcasts {log, result, run-done}
   outputs: board.json (import ⤒)  +  report.md
```

**Pattern:** ReAct (Think → Act → Observe), with reliability rails the research
flagged as load-bearing for production tool-agents:

- **Structured tool calls**, not text parsing (native function-calling + schema).
- **Orchestrator-enforced step budget** (`--max-steps`) — the loop is bounded by
  code, not by asking the model "are you done?".
- **De-dup guard** — one result per `(tool, target)`; repeats are refused.
- **Observation truncation** (`--max-obs-chars`, head+tail) so a noisy nmap dump
  doesn't blow the context window. (Upgrade path: LLM-summarize or
  observation-masking for very long runs.)
- **Tool-selection rubric** injected as context so target *type* → right tool.

For longer engagements, the research-backed upgrade is a **hybrid**:
Plan-and-Execute for an inspectable overall recon plan + ReAct adaptivity within
a step + a **Reflexion** self-critique gate ("did the evidence actually answer
the objective?") before `write_report`. Hooks are obvious in `Agent.run()`.

---

## 5. Fine-tuning roadmap (the "what it'd take to train them")

You said you'll rent GPUs to train — here's the realistic plan. **Fine-tune
behavior (tool-selection discipline, parsing, report style), not facts.**

### 5.1 Method & framework

- **QLoRA + SFT** is the default: 4-bit base, train small LoRA adapters. Add a
  **DPO/ORPO** pass afterward to polish report quality from preference pairs.
- **Frameworks:** **Unsloth** (fastest, lowest-VRAM, single-GPU) or
  **LLaMA-Factory** (web UI, easy DPO); **Axolotl** for reproducible
  config-driven runs at scale; **TRL/PEFT** as the underlying primitives.

### 5.2 Compute & cost (well-corroborated ballparks)

| Model | QLoRA VRAM | Fits on | Rough train cost |
|---|---|---|---|
| 7B | ~12 GB | 16–24 GB card | a few $ / ~couple hrs |
| 14B | ~22 GB | 24 GB card | a few $ |
| 32B | ~44 GB | 48 GB card | low tens of $ |
| 70B | ~88 GB (≈46 GB optimized) | 80 GB A100/H100 | ~$6–16 (8–20 hrs, 1 GPU) |

Cloud rates mid-2026: **H100 ≈ $2.50–3/hr** (spot lower), **A100-80 ≈
$1.5–3.4/hr**. **A 7B–14B OSINT worker is realistically tunable for under ~$20**
on one rented GPU.

### 5.3 Training data — the real work

Multi-turn **tool-call trajectories**, not single-shot pairs. Each example =
*objective → run_recon → (tool output) → add_findings → … → write_report*.

1. **Distill from a strong teacher.** Have a big model (the harness's own
   `--max-steps` runs against the **simulator** produce perfect, safe,
   deterministic trajectories — no live targets needed) generate thousands of
   trajectories over varied targets. The `samples/` exports are ready-made
   realistic tool outputs to build from. An 8B tuned on ~25k synthetic examples
   has beaten its 70B teacher on the target task.
2. **Format on proven function-calling sets:** Salesforce **xLAM**
   (xlam-function-calling-60k), **ToolACE**, NousResearch **Hermes
   function-calling**, **Glaive**. Mirror their `tool_call` schema so the model
   generalizes across tool signatures.
3. **Vary the schemas.** Randomize tool names/params across examples so the model
   learns *tool-selection*, not memorized signatures (the xLAM/ToolACE trick
   against schema overfitting).
4. **Size:** quality > quantity. ~1k examples/tool is a common target; ~5k–25k
   total gives strong gains. Build a held-out trajectory eval set.

### 5.4 The dataset generator you already have (`--record`)

The simulator in `pipe-server.js` emits realistic, deterministic output for
every tool. Point a **teacher model** at the harness in simulate mode and pass
`--record trajectories.jsonl` — each run is appended as one JSONL line of your
SFT corpus, with **zero real scanning and zero PII**:

```bash
node bridge/pipe-server.js --fast          # simulate; deterministic output
for d in acme-corp.com globex.io 198.51.100.0/24 staff@initech.com; do
  python3 ai/osint_agent.py --target "$d" --model qwen3:32b \
      --api http://127.0.0.1:11434/v1 --record data/trajectories.jsonl --yes
done
```

Each line is the OpenAI **conversational-with-tools** format that
LLaMA-Factory / Axolotl / TRL consume directly:

```json
{"messages":[{"role":"system",...},{"role":"user",...},
             {"role":"assistant","tool_calls":[{"function":{"name":"run_recon",...}}]},
             {"role":"tool","name":"run_recon","content":"### whois\n..."}, ...],
 "tools":[ ...the 4 function schemas... ],
 "meta":{"target":"acme-corp.com","mode":"simulate","findings":12,"completed":true}}
```

Tool-role observations are re-truncated (`--max-obs-chars`) so recorded context
stays training-sized. Both harnesses write the identical format and **append**,
so you can fan many runs (and both languages) into one file.

**Variance — two levers (use both):**

1. **At the source — `pipe-server.js --vary [SEED]`.** Simulate mode normally
   emits fixed fixtures (`203.0.113.42`, `www./mail./vpn.`), which would make the
   model overfit. `--vary` gives each target a **coherent random profile** —
   subfinder's subdomains resolve to dnsx's IPs, httpx/nmap hit the same hosts,
   whois/amass agree — so trajectories stay logically consistent but differ run
   to run. The model reasons over genuinely different data each time.
   ```bash
   node bridge/pipe-server.js --fast --vary 7
   ```
2. **In post — `prep_dataset.py`.** Cleans and multiplies the recorded corpus:
   ```bash
   python3 ai/prep_dataset.py loot/trajectories.jsonl --out-dir data \
       --augment 3 --val-frac 0.1 --seed 7
   ```
   It (a) keeps only `meta.completed` runs (`--keep-incomplete` to override),
   (b) dedups identical conversations, (c) optionally emits `--augment N` extra
   variants per run with the target domain and every IPv4 **consistently**
   substituted (subdomains/emails/tool-args move together), and (d) writes a
   deterministic `train.jsonl` / `val.jsonl` split.

This is the bridge from "prompted baseline" to "fine-tuned worker" — with
`--vary` + `--augment`, the corpus builds (and diversifies) itself.

### 5.5 Pitfalls

- **Catastrophic forgetting** → mix general instruction data into the tuning set.
- **Overfitting** (small data) → held-out set + early stopping.
- **Schema overfitting** → vary tool schemas (above).
- **Eval leakage** → strict train/test target separation.
- **When NOT to train:** if a prompted Qwen3/GLM baseline already hits your bar,
  stop — fine-tuning is the heaviest lever. Benchmark the harness first.

### 5.6 Evaluation

- **BFCL** (call-level: right tool, right args) + **τ-bench** (task-level
  completion) for general tool-use health.
- **Custom trajectory evals** (most relevant): score (1) final report, (2)
  single-step tool choice, (3) the whole tool-call path vs an expected
  trajectory — catches "right answer, wrong reasoning". LangChain `agentevals` /
  LangSmith trajectory evaluators do this off the shelf.

---

## 6. Safety model (three independent gates)

This is dual-use tooling. Controls, deny-by-default:

1. **The runner gate.** `pipe-server.js` simulates by default; real tools need
   `--exec`/`--ssh`. The page can only request tools from a fixed registry, and
   targets run via `spawn()` argv arrays — **no shell, no injection**.
2. **The harness gate.** `--scope` is **deny-by-default** once set (mirrors the
   runner's allowlist); active tools (`nmap`, `httpx`) stay behind
   `--allow-active`; targets are re-validated client-side.
3. **The model gate.** The system prompt hard-codes rules of engagement: passive
   first, never fabricate, and **`request_scope_decision`** (a human-in-the-loop
   stop) for any out-of-scope pivot — e.g., an email discovered for a *different*
   org. Keep this gate; don't let the model self-authorize.

Recommended additions if you productionize (from the research): a tamper-evident
**audit log** of every tool call + args, an **engagement-ID / written-scope**
artifact required before the active phase, and separate permission tiers for
passive-recon vs active-attack tools.

---

## 7. Prior art worth copying

- **OSINT_AI_Agent** (LangGraph supervisor + typed entity state) — closest
  pattern to the entity layer here.
- **HexStrike AI** / **FuzzingLabs mcp-security-hub** — MCP tool-wrapper layer
  if you want to expose the runner over MCP to Claude/Cursor/Copilot instead of
  (or alongside) this harness.
- **CAI (Cybersecurity AI)** — guardrail/agent-framework reference.
- **PentestGPT**, **Nebula**, **hackingBuddyGPT** — broader AI-pentest agents.
- **Neo4j + Relik/LlamaIndex** — entity-linking + relationship extraction into a
  graph, if you outgrow the flat board and want a real knowledge graph.

> **MCP path:** the runner's job interface (`{type:'run', target, tools}`) maps
> 1:1 to an MCP tool. Wrapping it as an MCP server is the natural next step to
> let an MCP-native client orchestrate it — same safety gates apply.

---

## 8. Sources & confidence

Compiled from a fan-out of web-research agents (Jun 2026); primary anchors
where they exist, flagged confidence elsewhere.

**Models / licenses / serving** *(families high-confidence; 2026 version numbers
web-sourced — verify on model cards)*
- Qwen3 — github.com/QwenLM/qwen3 · huggingface.co/Qwen
- DeepSeek V3.x — simonwillison.net/2025/Dec/1/deepseek-v32/
- Open-model license overview — huggingface.co/blog/daya-shankar/open-source-llms
- llama.cpp function calling (`--jinja`) — github.com/ggml-org/llama.cpp/blob/master/docs/function-calling.md
- vLLM structured outputs — docs.vllm.ai/en/v0.10.1/features/structured_outputs.html
- Ollama OpenAI compatibility — docs.ollama.com/api/openai-compatibility
- Quant formats — fungies.io/llm-quantization-gguf-awq-gptq-guide-2026/
- VRAM math — spheron.network/blog/gpu-memory-requirements-llm/

**Tool-use benchmarks**
- BFCL — proceedings.mlr.press/v267/patil25a.html (ICML 2025) · gorilla.cs.berkeley.edu/leaderboard.html
- τ-bench — arxiv.org/pdf/2406.12045 · github.com/sierra-research/tau2-bench

**Fine-tuning**
- SFT/LoRA/QLoRA/DPO — pub.towardsai.net/how-to-fine-tune-an-llm-sft-lora-qlora-and-dpo-explained-edcab1f45fd6
- Framework comparison — dev.to/ultraduneai/eval-003-fine-tuning-in-2026-axolotl-vs-unsloth-vs-trl-vs-llama-factory-2ohg
- VRAM/cost — llmhardware.io/guides/llm-fine-tuning-hardware-requirements · modal.com/blog/how-much-vram-need-fine-tuning · intuitionlabs.ai/articles/h100-rental-prices-cloud-comparison
- Distillation — aws.amazon.com/blogs/machine-learning/use-llama-3-1-405b-to-generate-synthetic-data-for-fine-tuning-tasks/
- Function-calling datasets — huggingface.co/datasets/Salesforce/xlam-function-calling-60k · arxiv.org/html/2511.15718v2 (ToolACE)

**Agent patterns / reliability**
- ReAct vs Plan-and-Execute — dev.to/jamesli/react-vs-plan-and-execute-a-practical-comparison-of-llm-agent-patterns-4gh9
- Reflexion — arxiv.org/abs/2303.11366
- Context/observation management — arxiv.org/html/2511.22729v1 · langchain.com/blog/context-management-for-deepagents
- Trajectory evals — docs.langchain.com/langsmith/trajectory-evals · github.com/langchain-ai/agentevals

**OSINT-AI prior art / safety**
- PentestGPT — github.com/GreyDGL/PentestGPT
- CAI — github.com/aliasrobotics/cai
- HexStrike — github.com/0x4m4/hexstrike-ai
- OSINT_AI_Agent — github.com/dazzyddos/OSINT_AI_Agent
- mcp-security-hub — github.com/FuzzingLabs/mcp-security-hub
- Entity linking — neo4j.com/blog/developer/entity-linking-relationship-extraction-relik-llamaindex/
- LLM guardrails — wiz.io/academy/ai-security/llm-guardrails

_Caveat: many 2026 figures are from secondary engineering blogs; load-bearing
claims recur across independent sources, but spot-check exact version numbers,
licenses, and benchmark scores on primary model cards before you commit money or
compute._
