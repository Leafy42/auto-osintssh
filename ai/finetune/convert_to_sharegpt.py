#!/usr/bin/env python3
# Convert recorded OSINT trajectories (OpenAI messages+tools JSONL, from
# osint_agent --record / prep_dataset.py) into LLaMA-Factory's ShareGPT
# tool-calling format (Glaive-style): conversations with human/gpt/
# function_call/observation turns + a `tools` JSON string + a `system` field.
#
#   python3 ai/finetune/convert_to_sharegpt.py data/train.jsonl \
#       ai/finetune/data/train_sharegpt.json
#
# Note: assumes one observation follows each tool call (the harness's normal
# flow). Batched tool calls in a single turn are emitted as consecutive
# function_call turns; if your trainer version rejects that, run the harness
# with one tool per run_recon call, or split them here.
import json, os, sys


def convert(records):
    out = []
    for rec in records:
        system, convs = "", []
        for m in rec.get("messages", []):
            role = m.get("role")
            content = m.get("content") or ""
            if role == "system":
                system = content
            elif role == "user":
                convs.append({"from": "human", "value": content})
            elif role == "tool":
                convs.append({"from": "observation", "value": content})
            elif role == "assistant":
                if content.strip():
                    convs.append({"from": "gpt", "value": content})
                for tc in (m.get("tool_calls") or []):
                    fn = tc.get("function", {})
                    args = fn.get("arguments", "{}")
                    try:
                        args = json.loads(args) if isinstance(args, str) else args
                    except json.JSONDecodeError:
                        pass
                    convs.append({"from": "function_call",
                                  "value": json.dumps({"name": fn.get("name"), "arguments": args})})
        if not convs:
            continue
        out.append({"conversations": convs, "system": system,
                    "tools": json.dumps([t.get("function", t) for t in rec.get("tools", [])])})
    return out


def main():
    if len(sys.argv) < 3:
        sys.exit("usage: convert_to_sharegpt.py <in.jsonl> <out.json>")
    records = [json.loads(l) for l in open(sys.argv[1]) if l.strip()]
    converted = convert(records)
    os.makedirs(os.path.dirname(os.path.abspath(sys.argv[2])), exist_ok=True)
    with open(sys.argv[2], "w") as f:
        json.dump(converted, f, indent=2)
    print(f"✔ {len(converted)} examples → {sys.argv[2]}")


if __name__ == "__main__":
    main()
