#!/usr/bin/env python3
# ======================================================================
# prep_dataset.py — turn recorded OSINT trajectories into a training set.
#
# Reads JSONL produced by osint_agent's --record flag (one run per line:
# {"messages":[...], "tools":[...], "meta":{...}}) and emits clean
# train/val splits ready for LLaMA-Factory / Axolotl / TRL (the same
# conversational-with-tools format).
#
# Pipeline: filter (completed runs) -> dedup -> optional entity-substitution
# augmentation -> deterministic shuffle -> train/val split.
#
#   # basic clean + split
#   python3 ai/prep_dataset.py loot/trajectories.jsonl --out-dir data
#
#   # 3 augmented variants per run (fresh domain + remapped IPs each)
#   python3 ai/prep_dataset.py loot/trajectories.jsonl --out-dir data \
#       --augment 3 --val-frac 0.1 --seed 7
#
# Augmentation gives variance even from the deterministic simulator; combine
# with `pipe-server.js --vary` for variance at the source too.
# ======================================================================
import argparse, hashlib, json, random, re, sys

IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
WORDS = ["acme", "globex", "initech", "umbrella", "soylent", "stark", "wayne", "cyberdyne",
         "tyrell", "hooli", "piedpiper", "vandelay", "wonka", "oscorp", "massive", "dunder",
         "aperture", "blackmesa", "nakatomi", "weyland", "abstergo", "encom", "gekko", "lumen"]
TLDS = ["com", "io", "net", "co", "org", "tech", "ai", "dev", "cloud", "systems"]


def canon_hash(rec):
    """Stable hash of the conversation (ignores meta) for dedup."""
    return hashlib.sha1(json.dumps(rec.get("messages", []), sort_keys=True).encode()).hexdigest()


def rand_domain(rng):
    return f"{rng.choice(WORDS)}{rng.randint(2, 989)}.{rng.choice(TLDS)}"


def rand_ip(rng):
    return f"{rng.choice([192,198,203,45,104,159,185,13,72,91])}.{rng.randint(0,255)}.{rng.randint(0,255)}.{rng.randint(1,253)}"


def augment(rec, rng):
    """Return a variant with the target domain and all IPv4s consistently
    substituted. Operates on the serialized record so subdomains, emails, and
    tool-call arguments all move together."""
    old = (rec.get("meta") or {}).get("target")
    s = json.dumps(rec)
    if old:
        s = s.replace(old, rand_domain(rng))
    ipmap = {}
    s = IPV4.sub(lambda m: ipmap.setdefault(m.group(), rand_ip(rng)), s)
    out = json.loads(s)
    out.setdefault("meta", {})["augmented"] = True
    return out


def main():
    ap = argparse.ArgumentParser(description="Prepare recorded OSINT trajectories for fine-tuning.")
    ap.add_argument("input", help="JSONL from osint_agent --record")
    ap.add_argument("--out-dir", default="data", help="output directory")
    ap.add_argument("--val-frac", type=float, default=0.1, help="fraction held out for validation")
    ap.add_argument("--augment", type=int, default=0, help="extra substituted variants per run")
    ap.add_argument("--keep-incomplete", action="store_true",
                    help="keep runs that did not reach write_report (meta.completed=false)")
    ap.add_argument("--min-msgs", type=int, default=4, help="drop trajectories shorter than this")
    ap.add_argument("--seed", type=int, default=0)
    args = ap.parse_args()
    rng = random.Random(args.seed)

    raw, kept, seen = 0, [], set()
    with open(args.input) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            raw += 1
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                print(f"  ! skipping malformed line {raw}", file=sys.stderr)
                continue
            meta = rec.get("meta") or {}
            if not args.keep_incomplete and not meta.get("completed", False):
                continue
            if len(rec.get("messages", [])) < args.min_msgs:
                continue
            h = canon_hash(rec)
            if h in seen:
                continue
            seen.add(h)
            kept.append(rec)

    base = len(kept)
    augmented = []
    for rec in kept:
        for _ in range(args.augment):
            augmented.append(augment(rec, rng))
    dataset = kept + augmented
    rng.shuffle(dataset)

    n_val = int(len(dataset) * args.val_frac)
    val, train = dataset[:n_val], dataset[n_val:]

    import os
    os.makedirs(args.out_dir, exist_ok=True)
    for name, rows in (("train", train), ("val", val)):
        path = os.path.join(args.out_dir, f"{name}.jsonl")
        with open(path, "w") as f:
            for r in rows:
                f.write(json.dumps(r) + "\n")
        print(f"✔ {name}: {len(rows):>5} → {path}")

    print(f"\nread {raw} lines · kept {base} unique completed · "
          f"+{len(augmented)} augmented · total {len(dataset)} "
          f"(train {len(train)} / val {len(val)})", file=sys.stderr)


if __name__ == "__main__":
    main()
