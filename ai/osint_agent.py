#!/usr/bin/env python3
# ======================================================================
# OSINT Holotable — LLM recon worker (Python reference harness)
#
# Drives the Holotable runner (bridge/pipe-server.js) with a local,
# open-weight LLM. The model plans recon, picks tools, reads their output,
# extracts entities, and writes an intel brief + a Holotable-importable
# board.json. Zero third-party dependencies — stdlib only (a minimal
# RFC-6455 WebSocket client + urllib for the OpenAI-compatible LLM API).
#
#   LLM (Ollama / llama.cpp --jinja / vLLM, OpenAI-compatible /v1)
#        │  tool-calling ReAct loop
#        ▼
#   osint_agent.py  ──WebSocket──▶  pipe-server.js  ──▶  recon tools
#        │                                  (simulate by default)
#        ├─▶ intel-report.md
#        └─▶ board.json  (import in the page with ⤒)
#
# ── Authorized use only ───────────────────────────────────────────────
# This worker initiates active reconnaissance. Run it only against targets
# you are authorized to test. Two independent gates protect you:
#   1. The runner must be started with --exec/--ssh for ANY real tool to
#      run; without it everything is simulated.
#   2. This harness enforces a deny-by-default --scope allowlist and keeps
#      active tools (nmap, httpx) behind --allow-active.
#
# ── Usage ─────────────────────────────────────────────────────────────
#   # terminal 1: the runner (safe simulate mode)
#   node bridge/pipe-server.js
#   # terminal 2: a local model, e.g.  ollama run qwen3:30b-a3b
#   python3 ai/osint_agent.py --target example.com \
#       --objective "map external attack surface" \
#       --model qwen3:30b-a3b --api http://127.0.0.1:11434/v1
#
#   # real, authorized engagement:
#   node bridge/pipe-server.js --exec --scope samples/scope.txt
#   python3 ai/osint_agent.py --target acme-corp.com --scope samples/scope.txt \
#       --allow-active --model qwen3:32b --api http://127.0.0.1:8000/v1
# ======================================================================
import argparse, base64, hashlib, ipaddress, json, os, re, socket, struct
import sys, time, urllib.request, urllib.error

HERE = os.path.dirname(os.path.abspath(__file__))

# Tools the runner knows about, split into passive / active tiers. Active
# tools touch the target directly and stay behind --allow-active.
PASSIVE = ["whois", "subfinder", "theharvester", "amass", "dnsx", "dnsrecon", "host"]
ACTIVE  = ["httpx", "nmap"]
ALL_TOOLS = PASSIVE + ACTIVE

DEFAULT_SYSTEM = """\
You are an OSINT reconnaissance analyst operating an authorized engagement.
You drive a fixed set of recon tools against IN-SCOPE targets only, read their
output, extract entities and relationships, and produce a sourced intel brief.

RULES OF ENGAGEMENT (non-negotiable):
- Only act on targets the operator has placed in scope. If a target is not
  clearly in scope, call request_scope_decision and stop — never guess.
- You can ONLY call the provided tools (each runs a vetted recon binary). You
  cannot run shell commands.
- Prefer passive/low-noise tools first (whois, subfinder, dnsx, theharvester,
  amass). Escalate to active tools (nmap, httpx) only when justified.
- Never fabricate findings. Every entity in the report must trace to a tool
  observation you actually received.
- Respect the step budget; do not re-run a tool that already produced a result
  for the same target.

METHOD (ReAct): THINK briefly, PICK the most informative next tool using the
rubric, ACT with run_recon, OBSERVE the output, RECORD entities with
add_findings, REPEAT until done, then FINISH with write_report.

Entity types: domain, subdomain, ip, email, person, org, port, service, tech,
nameserver, mx, url, cve, secret, asn, netblock, note, link.
"""

RUBRIC = """\
TOOL SELECTION RUBRIC (target type -> tools, run passive first):
- apex domain (example.com): whois, subfinder, theharvester, amass -> dnsx ->
  (active) httpx -> nmap
- subdomain (api.example.com): dnsx -> httpx -> nmap
- IP / CIDR: nmap, httpx; whois for netblock/ASN
- email: theharvester; pivot the domain part as an apex
Noise ladder: whois > subfinder > theharvester > amass > dnsx > httpx > nmap
Resolve a domain to an IP with dnsx BEFORE nmap. Batch independent passive
tools in one run_recon call. One result per (tool,target) is enough.
"""

# OpenAI-compatible function schemas (see ai/PROMPTS.md §3).
def tool_schemas(allow_active):
    enum = ALL_TOOLS if allow_active else PASSIVE
    return [
        {"type": "function", "function": {
            "name": "run_recon",
            "description": "Run one or more recon tools against a single in-scope target and return their output.",
            "parameters": {"type": "object", "properties": {
                "target": {"type": "string", "description": "One domain, IPv4, IPv6, or CIDR. Must be in scope."},
                "tools": {"type": "array", "items": {"type": "string", "enum": enum},
                          "description": "Tools to run. Prefer passive first."}},
                "required": ["target", "tools"]}}},
        {"type": "function", "function": {
            "name": "add_findings",
            "description": "Record normalized entities/relationships extracted from tool output.",
            "parameters": {"type": "object", "properties": {
                "events": {"type": "array", "items": {"type": "object", "properties": {
                    "type": {"type": "string"}, "data": {"type": "string"},
                    "module": {"type": "string"}, "source": {"type": "string"},
                    "t": {"type": ["integer", "null"]}},
                    "required": ["type", "data", "source"]}}},
                "required": ["events"]}}},
        {"type": "function", "function": {
            "name": "request_scope_decision",
            "description": "Ask the operator whether a target is in scope. Stops autonomous scanning.",
            "parameters": {"type": "object", "properties": {
                "target": {"type": "string"}, "reason": {"type": "string"}},
                "required": ["target", "reason"]}}},
        {"type": "function", "function": {
            "name": "write_report",
            "description": "Finalize the engagement with a Markdown intel brief. Ends the run.",
            "parameters": {"type": "object", "properties": {"markdown": {"type": "string"}},
                "required": ["markdown"]}}},
    ]

# ----------------------------------------------------------------------
# Scope allowlist — mirrors bridge/pipe-server.js inScope(). Deny-by-default
# when a scope file is supplied; allow-all (with a warning) when none is.
# ----------------------------------------------------------------------
class Scope:
    def __init__(self, entries):
        self.entries = [e.strip().lower() for e in entries if e.strip() and not e.strip().startswith("#")]

    @classmethod
    def from_file(cls, path):
        if not path:
            return cls([])
        with open(path) as f:
            return cls(f.read().splitlines())

    def allows(self, target):
        if not self.entries:
            return True  # no scope file -> everything allowed (warned at startup)
        t = str(target).strip().lower()
        for e in self.entries:
            base = e[2:] if e.startswith("*.") else e
            if t == base or t.endswith("." + base):
                return True
            if "/" in e:
                try:
                    if ipaddress.ip_address(t) in ipaddress.ip_network(e, strict=False):
                        return True
                except ValueError:
                    pass
        return False


def valid_target(t):
    t = str(t).strip()
    if not t or len(t) > 253:
        return False
    if re.match(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$", t, re.I):
        return True
    try:
        ipaddress.ip_network(t, strict=False)  # ipv4/ipv6/cidr
        return True
    except ValueError:
        return False


# ----------------------------------------------------------------------
# Minimal RFC-6455 WebSocket client (text frames only; client->server masked).
# Enough to talk to bridge/pipe-server.js. No third-party deps.
# ----------------------------------------------------------------------
class WS:
    def __init__(self, url, timeout=10):
        m = re.match(r"ws://([^:/]+)(?::(\d+))?(/.*)?$", url)
        if not m:
            raise ValueError("only ws:// URLs supported: " + url)
        self.host, port, path = m.group(1), m.group(2), m.group(3) or "/"
        self.port = int(port or 80)
        self.sock = socket.create_connection((self.host, self.port), timeout=timeout)
        key = base64.b64encode(os.urandom(16)).decode()
        req = (f"GET {path} HTTP/1.1\r\nHost: {self.host}:{self.port}\r\n"
               "Upgrade: websocket\r\nConnection: Upgrade\r\n"
               f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n")
        self.sock.sendall(req.encode())
        resp = self._read_until(b"\r\n\r\n")
        if b"101" not in resp.split(b"\r\n")[0]:
            raise ConnectionError("WebSocket handshake failed: " + resp.decode("latin1", "replace")[:120])
        self.buf = b""

    def _read_until(self, sep):
        data = b""
        while sep not in data:
            chunk = self.sock.recv(4096)
            if not chunk:
                break
            data += chunk
        return data

    def send_json(self, obj):
        payload = json.dumps(obj).encode()
        header = bytearray([0x81])  # FIN + text
        n = len(payload)
        mask = os.urandom(4)
        if n < 126:
            header.append(0x80 | n)
        elif n < 65536:
            header.append(0x80 | 126); header += struct.pack(">H", n)
        else:
            header.append(0x80 | 127); header += struct.pack(">Q", n)
        header += mask
        masked = bytes(b ^ mask[i & 3] for i, b in enumerate(payload))
        self.sock.sendall(bytes(header) + masked)

    def _fill(self, n):
        while len(self.buf) < n:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise ConnectionError("socket closed")
            self.buf += chunk

    def recv_json(self, timeout=None):
        """Return the next decoded JSON message, or None on close/timeout."""
        if timeout is not None:
            self.sock.settimeout(timeout)
        try:
            while True:
                self._fill(2)
                b0, b1 = self.buf[0], self.buf[1]
                opcode = b0 & 0x0f
                length = b1 & 0x7f
                off = 2
                if length == 126:
                    self._fill(4); length = struct.unpack(">H", self.buf[2:4])[0]; off = 4
                elif length == 127:
                    self._fill(10); length = struct.unpack(">Q", self.buf[2:10])[0]; off = 10
                self._fill(off + length)
                payload = self.buf[off:off + length]
                self.buf = self.buf[off + length:]
                if opcode == 0x8:  # close
                    return None
                if opcode in (0x0, 0x1):
                    try:
                        return json.loads(payload.decode("utf-8", "replace"))
                    except json.JSONDecodeError:
                        continue
                # ping/pong ignored
        except (socket.timeout, ConnectionError):
            return None

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


# ----------------------------------------------------------------------
# Recon bridge — connect, learn the runner's capabilities, run a job, and
# collect the parsed `result` text per tool until run-done.
# ----------------------------------------------------------------------
class Bridge:
    def __init__(self, url, job_timeout=120):
        self.ws = WS(url)
        self.job_timeout = job_timeout
        hello = self.ws.recv_json(timeout=5) or {}
        self.tools = hello.get("tools", ALL_TOOLS)
        self.exec_mode = hello.get("exec", False)
        self.scoped = hello.get("scoped", False)

    def run(self, target, tools):
        """Send a job; return {tool_tag: combined_text}. Blocks until run-done."""
        self.ws.send_json({"type": "run", "target": target, "tools": tools})
        results, logs, deadline = {}, [], time.time() + self.job_timeout
        while time.time() < deadline:
            msg = self.ws.recv_json(timeout=max(1, deadline - time.time()))
            if msg is None:
                break
            mt = msg.get("type")
            if mt == "result":
                tag = msg.get("tool", "lines")
                results[tag] = (results.get(tag, "") + "\n" + msg.get("text", "")).strip()
            elif mt == "log":
                logs.append(f"[{msg.get('tool')}] {msg.get('line')}")
            elif mt == "run-done":
                break
        if not results and logs:
            results["log"] = "\n".join(logs[-40:])
        return results

    def close(self):
        self.ws.close()


# ----------------------------------------------------------------------
# OpenAI-compatible LLM client (chat/completions with tool calling).
# ----------------------------------------------------------------------
class LLM:
    def __init__(self, api, model, key=None, temperature=0.2):
        self.url = api.rstrip("/") + "/chat/completions"
        self.model, self.key, self.temperature = model, key, temperature

    def chat(self, messages, tools=None, tool_choice="auto"):
        body = {"model": self.model, "messages": messages, "temperature": self.temperature}
        if tools:
            body["tools"] = tools
            body["tool_choice"] = tool_choice
        data = json.dumps(body).encode()
        headers = {"Content-Type": "application/json"}
        if self.key:
            headers["Authorization"] = "Bearer " + self.key
        req = urllib.request.Request(self.url, data=data, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=300) as r:
                out = json.loads(r.read())
        except urllib.error.HTTPError as e:
            raise SystemExit(f"LLM HTTP {e.code}: {e.read().decode('utf-8','replace')[:300]}")
        except urllib.error.URLError as e:
            raise SystemExit(f"LLM unreachable at {self.url}: {e.reason}")
        return out["choices"][0]["message"]


# ----------------------------------------------------------------------
# Board builder — turn collected events into a Holotable-importable board.
# Schema mirrors app.js serialize() v3.
# ----------------------------------------------------------------------
_COLORS = ["#16e0ff", "#9d7bff", "#27e8a7", "#ff9f43", "#ff4d6d"]

def build_board(target, events):
    by_source = {}
    for e in events:
        by_source.setdefault(e.get("source", "ai"), []).append(e)
    timelines = []
    for i, (src, evs) in enumerate(sorted(by_source.items())):
        boxes = [{"id": f"bx{i}_{j}", "type": e.get("type", "data"), "module": e.get("module", ""),
                  "data": str(e.get("data", "")), "source": src, "t": e.get("t")}
                 for j, e in enumerate(evs)]
        point = {"id": f"pt{i}", "t": None, "expanded": True, "boxes": boxes}
        timelines.append({"id": f"tl{i}", "title": f"{src.upper()} · {target}",
                          "x": 140 + i * 520, "y": 160, "color": _COLORS[i % len(_COLORS)],
                          "points": [point]})
    return {"v": 3, "cam": {"x": 0, "y": 0, "zoom": 1}, "timelines": timelines,
            "notes": [], "links": [], "strokes": [], "hiddenSources": {}}


# ----------------------------------------------------------------------
# The agent loop.
# ----------------------------------------------------------------------
class Agent:
    def __init__(self, llm, bridge, scope, args):
        self.llm, self.bridge, self.scope, self.args = llm, bridge, scope, args
        self.events = []          # accumulated findings
        self.ran = set()          # (tool, target) already executed
        self.report = None
        self.messages = []        # full transcript (for --record SFT trajectories)
        self.tools = []           # tool schemas in play (recorded alongside)

    def _truncate(self, text):
        cap = self.args.max_obs_chars
        if len(text) <= cap:
            return text
        head, tail = text[: cap * 2 // 3], text[-cap // 3:]
        return f"{head}\n...[{len(text)-cap} chars truncated]...\n{tail}"

    def _do_run_recon(self, a):
        target = str(a.get("target", "")).strip()
        tools = [t for t in a.get("tools", []) if t in ALL_TOOLS]
        if not valid_target(target):
            return f"REJECTED: '{target}' is not a valid domain/IP/CIDR."
        if not self.scope.allows(target):
            return f"REJECTED: '{target}' is out of scope. Call request_scope_decision."
        blocked = [t for t in tools if t in ACTIVE and not self.args.allow_active]
        tools = [t for t in tools if t not in blocked]
        if blocked:
            note = f"(active tools {blocked} blocked — run with --allow-active to enable) "
        else:
            note = ""
        tools = [t for t in tools if (t, target) not in self.ran]
        if not tools:
            return f"{note}No new tools to run for {target} (already executed or none allowed)."
        for t in tools:
            self.ran.add((t, target))
        print(f"  ▸ run_recon {target} :: {', '.join(tools)}", file=sys.stderr)
        results = self.bridge.run(target, tools)
        if not results:
            return f"{note}No output returned for {target} :: {tools}."
        parts = [f"### {tag}\n{self._truncate(text)}" for tag, text in results.items()]
        return note + "\n\n".join(parts)

    def _do_add_findings(self, a):
        added = 0
        for e in a.get("events", []):
            if not isinstance(e, dict) or not e.get("data"):
                continue
            self.events.append({"type": e.get("type", "data"), "data": str(e.get("data")),
                                "module": e.get("module", ""), "source": e.get("source", "ai"),
                                "t": e.get("t")})
            added += 1
        return f"Recorded {added} finding(s). Total so far: {len(self.events)}."

    def _do_scope_decision(self, a):
        target, reason = a.get("target", "?"), a.get("reason", "")
        if self.args.yes:
            return f"Operator (--yes) AUTHORIZED scope for {target}. You may proceed."
        print(f"\n  ⚠ SCOPE DECISION for {target}: {reason}", file=sys.stderr)
        try:
            ans = input("    Authorize this target? [y/N] ").strip().lower()
        except EOFError:
            ans = "n"
        return ("Operator AUTHORIZED " if ans == "y" else "Operator DECLINED ") + \
               f"{target}. " + ("Proceed." if ans == "y" else "Do not scan it; continue with in-scope work.")

    def run(self):
        messages = [
            {"role": "system", "content": self.args.system + "\n\n" + RUBRIC},
            {"role": "user", "content":
                f"Target in scope: {self.args.target}\nObjective: {self.args.objective}\n"
                f"Runner mode: {'REAL EXEC' if self.bridge.exec_mode else 'SIMULATE'}; "
                f"active tools {'ENABLED' if self.args.allow_active else 'DISABLED'}.\n"
                f"Available tools: {', '.join(self.bridge.tools)}.\n"
                "Begin. Plan briefly, then call run_recon."},
        ]
        tools = tool_schemas(self.args.allow_active)
        self.messages, self.tools = messages, tools   # keep refs for --record
        handlers = {"run_recon": self._do_run_recon, "add_findings": self._do_add_findings,
                    "request_scope_decision": self._do_scope_decision}
        for step in range(1, self.args.max_steps + 1):
            print(f"[step {step}/{self.args.max_steps}]", file=sys.stderr)
            msg = self.llm.chat(messages, tools=tools)
            messages.append(msg)
            calls = msg.get("tool_calls") or []
            if not calls:
                # No tool call: nudge once, then treat trailing text as progress.
                content = (msg.get("content") or "").strip()
                if content:
                    print("  · model: " + content[:200], file=sys.stderr)
                messages.append({"role": "user", "content":
                    "Continue: call run_recon for the next step, or write_report if done."})
                continue
            for call in calls:
                fn = call["function"]["name"]
                try:
                    a = json.loads(call["function"].get("arguments") or "{}")
                except json.JSONDecodeError:
                    a = {}
                if fn == "write_report":
                    self.report = a.get("markdown", "").strip()
                    return self._finish()
                result = handlers.get(fn, lambda _a: f"Unknown tool {fn}.")(a)
                messages.append({"role": "tool", "tool_call_id": call.get("id", fn),
                                 "name": fn, "content": result})
        print("  · step budget exhausted — forcing report.", file=sys.stderr)
        messages.append({"role": "user", "content":
            "Step budget reached. Call write_report now with whatever you have."})
        msg = self.llm.chat(messages, tools=tools, tool_choice="auto")
        for call in (msg.get("tool_calls") or []):
            if call["function"]["name"] == "write_report":
                try:
                    self.report = json.loads(call["function"]["arguments"]).get("markdown", "")
                except json.JSONDecodeError:
                    pass
        return self._finish()

    def _finish(self):
        outdir = self.args.out
        os.makedirs(outdir, exist_ok=True)
        stamp = self.args.target.replace("/", "_")
        board_path = os.path.join(outdir, f"{stamp}.board.json")
        report_path = os.path.join(outdir, f"{stamp}.report.md")
        with open(board_path, "w") as f:
            json.dump(build_board(self.args.target, self.events), f, indent=2)
        report = self.report or self._fallback_report()
        with open(report_path, "w") as f:
            f.write(report)
        if self.args.record:
            self._record_trajectory()
        print(f"\n✔ {len(self.events)} findings", file=sys.stderr)
        print(f"✔ board  → {board_path}  (import in page with ⤒)", file=sys.stderr)
        print(f"✔ report → {report_path}", file=sys.stderr)
        return {"events": self.events, "board": board_path, "report": report_path}

    def _record_trajectory(self):
        """Append the run as one JSONL line for SFT: conversational format with
        tool schemas, consumable by LLaMA-Factory / Axolotl / TRL. Tool-role
        observations are re-truncated so recorded context stays training-sized.
        Against the runner's SIMULATE mode this yields clean, PII-free,
        deterministic tool-call trajectories with no live scanning."""
        clean = []
        for m in self.messages:
            m = dict(m) if isinstance(m, dict) else m
            if isinstance(m, dict) and m.get("role") == "tool" and isinstance(m.get("content"), str):
                m["content"] = self._truncate(m["content"])
            clean.append(m)
        rec = {"messages": clean, "tools": self.tools,
               "meta": {"target": self.args.target, "objective": self.args.objective,
                        "mode": "exec" if self.bridge.exec_mode else "simulate",
                        "findings": len(self.events), "completed": self.report is not None}}
        with open(self.args.record, "a") as f:
            f.write(json.dumps(rec, default=str) + "\n")
        print(f"✔ trajectory → {self.args.record} (append)", file=sys.stderr)

    def _fallback_report(self):
        lines = [f"# OSINT Brief — {self.args.target}", "",
                 f"_Objective: {self.args.objective}_", "",
                 "## Entities", ""]
        for e in self.events:
            lines.append(f"- **{e['type']}** `{e['data']}` — {e['module']} _(via {e['source']})_")
        if not self.events:
            lines.append("_No findings recorded._")
        return "\n".join(lines) + "\n"


def main():
    p = argparse.ArgumentParser(description="LLM-driven OSINT recon worker for the Holotable.")
    p.add_argument("--target", required=True, help="apex domain / subdomain / IP / CIDR")
    p.add_argument("--objective", default="Map the external attack surface.")
    p.add_argument("--model", required=True, help="model name as the API server knows it")
    p.add_argument("--api", default="http://127.0.0.1:11434/v1", help="OpenAI-compatible base URL")
    p.add_argument("--api-key", default=os.environ.get("OPENAI_API_KEY"))
    p.add_argument("--bridge", default="ws://127.0.0.1:7842", help="pipe-server.js WebSocket URL")
    p.add_argument("--scope", help="allowlist file (domains / *.domain / CIDR); deny-by-default when set")
    p.add_argument("--allow-active", action="store_true", help="permit active tools (nmap, httpx)")
    p.add_argument("--yes", action="store_true", help="auto-authorize scope prompts (non-interactive)")
    p.add_argument("--max-steps", type=int, default=16)
    p.add_argument("--max-obs-chars", type=int, default=4000, help="truncate each tool observation")
    p.add_argument("--job-timeout", type=int, default=120)
    p.add_argument("--temperature", type=float, default=0.2)
    p.add_argument("--out", default="loot", help="output directory for board.json + report.md")
    p.add_argument("--record", help="append this run as an SFT trajectory (JSONL) for fine-tuning")
    p.add_argument("--system-file", default=os.path.join(HERE, "SYSTEM_PROMPT.txt"),
                   help="optional system-prompt override file")
    args = p.parse_args()

    if os.path.exists(args.system_file):
        with open(args.system_file) as f:
            args.system = f.read()
    else:
        args.system = DEFAULT_SYSTEM

    if not valid_target(args.target):
        raise SystemExit(f"Invalid --target '{args.target}' (need domain/IP/CIDR).")
    scope = Scope.from_file(args.scope)
    if not scope.entries:
        print("⚠ no --scope file: ALL targets allowed. Supply one for real engagements.", file=sys.stderr)
    elif not scope.allows(args.target):
        raise SystemExit(f"--target {args.target} is not in --scope {args.scope}.")

    print(f"connecting to runner {args.bridge} ...", file=sys.stderr)
    bridge = Bridge(args.bridge, job_timeout=args.job_timeout)
    print(f"runner: mode={'exec' if bridge.exec_mode else 'simulate'} "
          f"tools={len(bridge.tools)} scoped={bridge.scoped}", file=sys.stderr)
    if args.allow_active and not bridge.exec_mode:
        print("note: --allow-active set but runner is in SIMULATE mode (no real scans).", file=sys.stderr)

    llm = LLM(args.api, args.model, key=args.api_key, temperature=args.temperature)
    try:
        Agent(llm, bridge, scope, args).run()
    finally:
        bridge.close()


if __name__ == "__main__":
    main()
