# Fine-tuning quickstart — OSINT recon worker

Turnkey path from "prompted baseline" to a QLoRA-tuned open model that runs the
harness. Everything here is **offline and PII-free** — training data is
generated against the runner's simulator, not live targets.

```
gen_corpus.sh ──▶ data/train.jsonl (+val)         ← record teacher runs, prep
     │                     │
     │                     ├─▶ Unsloth  (reads JSONL directly)         → adapters
     │                     └─▶ convert_to_sharegpt.py → LLaMA-Factory  → adapters
     ▼
serve tuned model ──▶ point osint_agent.py --model <tuned> at it
```

> Authorized use only. A fine-tuned recon model is still bound by the three
> safety gates in [`../README.md`](../README.md#6-safety-model-three-independent-gates).

## Files
| File | Purpose |
|---|---|
| `gen_corpus.sh` | One command: runner `--vary` + teacher runs `--record` + `prep_dataset` + convert. |
| `convert_to_sharegpt.py` | OpenAI messages+tools JSONL → LLaMA-Factory ShareGPT-with-tools. |
| `dataset_info.json` | LLaMA-Factory dataset registration (point `--dataset_dir` here). |
| `qwen_qlora.yaml` | LLaMA-Factory QLoRA training config. |
| `unsloth_qlora.py` | Unsloth QLoRA script (consumes the JSONL directly). |

## 1. Generate the corpus
```bash
# a teacher model must be served (OpenAI-compatible); a strong one distills best
TEACHER=qwen3:32b API=http://127.0.0.1:11434/v1 AUGMENT=3 ./ai/finetune/gen_corpus.sh
```
Produces `data/train.jsonl`, `data/val.jsonl` (and ShareGPT copies under
`ai/finetune/data/`). Point `TARGETS_FILE=my_targets.txt` at your own list for
more schema/entity diversity; more targets + `--vary` + `--augment` = more variance.

## 2a. Train with Unsloth (single 24 GB GPU, simplest)
```bash
pip install "unsloth[colab-new]" trl datasets     # see unsloth.ai for exact extras
python3 ai/finetune/unsloth_qlora.py \
    --model unsloth/Qwen2.5-14B-Instruct-bnb-4bit \
    --train data/train.jsonl --val data/val.jsonl \
    --out ai/finetune/out/unsloth-osint
```
Reads the JSONL directly via the tokenizer's tool-aware chat template — no
conversion step. Uncomment `save_pretrained_gguf` in the script to export a Q4
GGUF for Ollama/llama.cpp.

## 2b. Train with LLaMA-Factory (web UI / DPO / multi-GPU)
```bash
# convert (gen_corpus.sh already did this if you ran it)
python3 ai/finetune/convert_to_sharegpt.py data/train.jsonl ai/finetune/data/train_sharegpt.json
python3 ai/finetune/convert_to_sharegpt.py data/val.jsonl   ai/finetune/data/val_sharegpt.json
# train
llamafactory-cli train ai/finetune/qwen_qlora.yaml
```
**Set `template:` to match the base model** (`qwen` / `llama3` / `mistral` /
`glm4` / …) — a mismatch silently corrupts tool tokens.

## 3. Serve the tuned model
- **Unsloth GGUF → Ollama:** `ollama create osint -f Modelfile` (FROM your GGUF),
  then `ollama run osint`.
- **LoRA adapters → vLLM:** `vllm serve <base> --enable-lora --lora-modules osint=ai/finetune/out/...`
- **Merge + llama.cpp:** merge adapters, `convert_hf_to_gguf.py`, `llama-server --jinja`.

## 4. Run the harness on it
```bash
node bridge/pipe-server.js --exec --scope samples/scope.txt          # real, in-scope
python3 ai/osint_agent.py --target acme-corp.com --scope samples/scope.txt \
    --allow-active --model osint --api http://127.0.0.1:11434/v1
```

## 5. Evaluate before/after
Hold out targets the model never trained on. Compare the tuned model vs the
prompted baseline on: right-tool-first-try, valid tool-call JSON rate, findings
recall, and report quality. See [`../README.md` §5.6](../README.md#56-evaluation)
for BFCL / τ-bench / trajectory-eval pointers.

## Reality checks
- **Prove the prompted baseline first.** If a stock Qwen3/GLM already clears your
  bar via the harness, you may not need to train (see `../README.md` §5.5).
- **Mix in general instruction data** (commented example in `qwen_qlora.yaml`) to
  avoid catastrophic forgetting.
- **Diversify** — the simulator caches one profile per target per seed; vary the
  target list, the `--vary` seed, and `--augment` so the model learns
  tool-selection, not fixtures.
- These configs are **references** — API keys/flags for Unsloth, TRL, and
  LLaMA-Factory move fast; check each project's current docs for your version.
