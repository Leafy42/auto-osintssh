#!/usr/bin/env bash
# gen_corpus.sh — build a fine-tuning corpus end to end, offline & PII-free.
#
# Runs the recon runner in SIMULATE + --vary mode, drives it with a TEACHER
# model over many targets recording each trajectory, then filters/augments/
# splits into train/val JSONL. No live scanning happens.
#
#   TEACHER=qwen3:32b API=http://127.0.0.1:11434/v1 ./ai/finetune/gen_corpus.sh
#
# Env knobs: TEACHER (model), API (OpenAI-compatible base), SEED, AUGMENT,
#            TARGETS_FILE (one domain per line), OUTDIR.
set -euo pipefail
cd "$(dirname "$0")/../.."          # repo root

TEACHER="${TEACHER:-qwen3:32b}"
API="${API:-http://127.0.0.1:11434/v1}"
SEED="${SEED:-7}"
AUGMENT="${AUGMENT:-3}"
OUTDIR="${OUTDIR:-data}"
RAW="$OUTDIR/trajectories.jsonl"
mkdir -p "$OUTDIR"
: > "$RAW"

# A pool of synthetic in-scope targets. Replace with TARGETS_FILE for your own.
if [[ -n "${TARGETS_FILE:-}" ]]; then
  mapfile -t TARGETS < "$TARGETS_FILE"
else
  TARGETS=(acme-corp.com globex.io initech.net umbrella-labs.org soylent.tech
           stark-industries.com wayne-ent.io cyberdyne.systems tyrell.co hooli.dev
           piedpiper.ai vandelay.com wonka.co oscorp.net massive-dynamic.io)
fi

echo "[gen] starting runner: simulate --vary $SEED"
node bridge/pipe-server.js --fast --vary "$SEED" >/tmp/osint-runner.log 2>&1 &
RUNNER=$!
trap 'kill $RUNNER 2>/dev/null || true' EXIT
sleep 1

echo "[gen] teacher=$TEACHER api=$API  targets=${#TARGETS[@]}"
for t in "${TARGETS[@]}"; do
  [[ -z "$t" ]] && continue
  echo "  · $t"
  python3 ai/osint_agent.py --target "$t" --objective "map external attack surface" \
      --model "$TEACHER" --api "$API" --record "$RAW" --yes \
      --out "$OUTDIR/boards" >/dev/null 2>&1 || echo "    (run failed for $t — skipped)"
done

echo "[gen] prep: filter + dedup + augment x$AUGMENT + split"
python3 ai/prep_dataset.py "$RAW" --out-dir "$OUTDIR" --augment "$AUGMENT" --val-frac 0.1 --seed "$SEED"

echo "[gen] convert to LLaMA-Factory ShareGPT (optional; Unsloth reads JSONL directly)"
python3 ai/finetune/convert_to_sharegpt.py "$OUTDIR/train.jsonl" ai/finetune/data/train_sharegpt.json
python3 ai/finetune/convert_to_sharegpt.py "$OUTDIR/val.jsonl"   ai/finetune/data/val_sharegpt.json

echo "[gen] done. train: $OUTDIR/train.jsonl  ·  sharegpt: ai/finetune/data/train_sharegpt.json"
