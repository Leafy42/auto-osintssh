#!/usr/bin/env python3
# Unsloth QLoRA fine-tune for the OSINT recon worker.
#
# Consumes the recorded OpenAI messages+tools JSONL DIRECTLY (data/train.jsonl,
# data/val.jsonl from prep_dataset.py) via the tokenizer's chat template with
# tool schemas — no format conversion needed. Best for a single 24 GB GPU.
#
#   pip install "unsloth[colab-new]" trl datasets      # see unsloth.ai for exact extras
#   python3 ai/finetune/unsloth_qlora.py --model unsloth/Qwen2.5-14B-Instruct-bnb-4bit \
#       --train data/train.jsonl --val data/val.jsonl --out ai/finetune/out/unsloth-osint
#
# Requirements: a GPU + the unsloth/trl/datasets stack. The base model's chat
# template must support tools (Qwen/Llama-3.x/Mistral do). This script is a
# reference; verify API names against the versions you install.
import argparse


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="unsloth/Qwen2.5-14B-Instruct-bnb-4bit")
    ap.add_argument("--train", default="data/train.jsonl")
    ap.add_argument("--val", default="data/val.jsonl")
    ap.add_argument("--out", default="ai/finetune/out/unsloth-osint")
    ap.add_argument("--max-seq", type=int, default=8192)
    ap.add_argument("--epochs", type=float, default=3.0)
    ap.add_argument("--lr", type=float, default=1e-4)
    ap.add_argument("--rank", type=int, default=16)
    ap.add_argument("--batch", type=int, default=1)
    ap.add_argument("--accum", type=int, default=8)
    args = ap.parse_args()

    # Imported lazily so `python -c "import ast"` / syntax checks don't need the GPU stack.
    from unsloth import FastLanguageModel
    from datasets import load_dataset
    from trl import SFTTrainer, SFTConfig

    model, tokenizer = FastLanguageModel.from_pretrained(
        model_name=args.model, max_seq_length=args.max_seq, load_in_4bit=True)
    model = FastLanguageModel.get_peft_model(
        model, r=args.rank, lora_alpha=args.rank * 2, lora_dropout=0.05,
        target_modules=["q_proj", "k_proj", "v_proj", "o_proj",
                        "gate_proj", "up_proj", "down_proj"],
        use_gradient_checkpointing="unsloth")

    ds = load_dataset("json", data_files={"train": args.train, "validation": args.val})

    def to_text(ex):
        # Render the full tool-calling conversation with the model's own template.
        return {"text": tokenizer.apply_chat_template(
            ex["messages"], tools=ex.get("tools"), tokenize=False,
            add_generation_prompt=False)}

    ds = ds.map(to_text, remove_columns=[c for c in ds["train"].column_names if c != "text"])

    trainer = SFTTrainer(
        model=model, tokenizer=tokenizer,
        train_dataset=ds["train"], eval_dataset=ds["validation"],
        args=SFTConfig(
            dataset_text_field="text", max_seq_length=args.max_seq,
            per_device_train_batch_size=args.batch,
            gradient_accumulation_steps=args.accum,
            warmup_ratio=0.05, num_train_epochs=args.epochs,
            learning_rate=args.lr, bf16=True, logging_steps=5,
            eval_strategy="steps", eval_steps=100, save_steps=100,
            output_dir=args.out, lr_scheduler_type="cosine"),
    )
    trainer.train()
    model.save_pretrained(args.out)
    tokenizer.save_pretrained(args.out)
    # For local serving with Ollama/llama.cpp, also export merged GGUF:
    #   model.save_pretrained_gguf(args.out + "-gguf", tokenizer, quantization_method="q4_k_m")
    print(f"✔ adapters saved → {args.out}")


if __name__ == "__main__":
    main()
