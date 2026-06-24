// ======================================================================
// OSINT Holotable — LLM recon worker (Go reference harness)
//
// A single static binary (stdlib only) that drives the Holotable runner
// (bridge/pipe-server.js) with a local open-weight LLM over an
// OpenAI-compatible API. Picks recon tools, reads their output, extracts
// entities, and writes an intel brief + a Holotable-importable board.json.
//
// Built for the air-gapped forensic box: `go build` it once, copy the
// binary, no runtime dependencies.
//
//   go build -o osint-agent ./ai/go
//   node bridge/pipe-server.js            # terminal 1 (simulate)
//   ollama run qwen3:32b                   # terminal 2 (a local model)
//   ./osint-agent -target example.com -model qwen3:32b \
//       -api http://127.0.0.1:11434/v1 -objective "map attack surface"
//
// Authorized use only. Active tools (nmap, httpx) stay behind -allow-active,
// and a -scope allowlist is deny-by-default once supplied. Real scans also
// require the runner itself to be started with --exec/--ssh.
// ======================================================================
package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

var (
	passive   = []string{"whois", "subfinder", "theharvester", "amass", "dnsx", "dnsrecon", "host"}
	active    = []string{"httpx", "nmap"}
	allTools  = append(append([]string{}, passive...), active...)
	colors    = []string{"#16e0ff", "#9d7bff", "#27e8a7", "#ff9f43", "#ff4d6d"}
	domainRe  = regexp.MustCompile(`^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$`)
	ipv4Re    = regexp.MustCompile(`^\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?$`)
	ipv6Re    = regexp.MustCompile(`^[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{0,4}){2,7}(?:/\d{1,3})?$`)
)

const defaultSystem = `You are an OSINT reconnaissance analyst operating an authorized engagement.
You drive a fixed set of recon tools against IN-SCOPE targets only, read their
output, extract entities and relationships, and produce a sourced intel brief.

RULES OF ENGAGEMENT (non-negotiable):
- Only act on in-scope targets. If a target is not clearly in scope, call
  request_scope_decision and stop — never guess.
- You can ONLY call the provided tools. You cannot run shell commands.
- Prefer passive tools first; escalate to active (nmap, httpx) only when justified.
- Never fabricate findings; every entity must trace to a tool observation.
- Respect the step budget; do not re-run a tool already run for the same target.

METHOD (ReAct): THINK briefly, PICK the next tool with the rubric, ACT with
run_recon, OBSERVE, RECORD with add_findings, REPEAT, then FINISH with write_report.

Entity types: domain, subdomain, ip, email, person, org, port, service, tech,
nameserver, mx, url, cve, secret, asn, netblock, note, link.`

const rubric = `TOOL SELECTION RUBRIC (run passive first):
- apex domain: whois, subfinder, theharvester, amass -> dnsx -> (active) httpx -> nmap
- subdomain: dnsx -> httpx -> nmap
- IP/CIDR: nmap, httpx; whois for netblock/ASN
- email: theharvester; pivot the domain part as an apex
Resolve a domain with dnsx BEFORE nmap. Batch independent passive tools in one
run_recon call. One result per (tool,target) is enough.`

// ---------- config ----------
type config struct {
	target, objective, model, api, apiKey, bridge, scopeFile, system, out string
	record                                                               string
	allowActive, yes                                                      bool
	maxSteps, maxObs, jobTimeout                                          int
	temperature                                                          float64
}

// ---------- target validation & scope ----------
func validTarget(t string) bool {
	t = strings.TrimSpace(t)
	if t == "" || len(t) > 253 {
		return false
	}
	return domainRe.MatchString(strings.ToLower(t)) || ipv4Re.MatchString(t) || ipv6Re.MatchString(t)
}

type scope struct{ entries []string }

func loadScope(path string) (*scope, error) {
	s := &scope{}
	if path == "" {
		return s, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	for _, ln := range strings.Split(string(b), "\n") {
		ln = strings.TrimSpace(strings.ToLower(ln))
		if ln != "" && !strings.HasPrefix(ln, "#") {
			s.entries = append(s.entries, ln)
		}
	}
	return s, nil
}

func (s *scope) allows(target string) bool {
	if len(s.entries) == 0 {
		return true
	}
	t := strings.ToLower(strings.TrimSpace(target))
	for _, e := range s.entries {
		base := e
		if strings.HasPrefix(e, "*.") {
			base = e[2:]
		}
		if t == base || strings.HasSuffix(t, "."+base) {
			return true
		}
		if strings.Contains(e, "/") {
			if _, ipnet, err := net.ParseCIDR(e); err == nil {
				if ip := net.ParseIP(t); ip != nil && ipnet.Contains(ip) {
					return true
				}
			}
		}
	}
	return false
}

// ---------- minimal RFC-6455 WebSocket client ----------
type ws struct {
	conn net.Conn
	r    *bufio.Reader
}

func dialWS(raw string) (*ws, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "ws" {
		return nil, fmt.Errorf("only ws:// URLs supported: %s", raw)
	}
	host := u.Host
	if !strings.Contains(host, ":") {
		host += ":80"
	}
	conn, err := net.DialTimeout("tcp", host, 10*time.Second)
	if err != nil {
		return nil, err
	}
	keyBytes := make([]byte, 16)
	rand.Read(keyBytes)
	key := b64(keyBytes)
	path := u.Path
	if path == "" {
		path = "/"
	}
	req := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"+
		"Sec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n", path, host, key)
	if _, err = conn.Write([]byte(req)); err != nil {
		return nil, err
	}
	r := bufio.NewReader(conn)
	status, err := r.ReadString('\n')
	if err != nil || !strings.Contains(status, "101") {
		return nil, fmt.Errorf("handshake failed: %q", strings.TrimSpace(status))
	}
	for { // drain remaining headers
		line, err := r.ReadString('\n')
		if err != nil || line == "\r\n" {
			break
		}
	}
	return &ws{conn: conn, r: r}, nil
}

func (w *ws) sendJSON(v any) error {
	payload, _ := json.Marshal(v)
	n := len(payload)
	var hdr bytes.Buffer
	hdr.WriteByte(0x81) // FIN + text
	mask := make([]byte, 4)
	rand.Read(mask)
	switch {
	case n < 126:
		hdr.WriteByte(byte(0x80 | n))
	case n < 65536:
		hdr.WriteByte(0x80 | 126)
		binary.Write(&hdr, binary.BigEndian, uint16(n))
	default:
		hdr.WriteByte(0x80 | 127)
		binary.Write(&hdr, binary.BigEndian, uint64(n))
	}
	hdr.Write(mask)
	masked := make([]byte, n)
	for i, b := range payload {
		masked[i] = b ^ mask[i&3]
	}
	_, err := w.conn.Write(append(hdr.Bytes(), masked...))
	return err
}

// recvJSON reads one server text frame (server->client is unmasked).
func (w *ws) recvJSON(timeout time.Duration) (map[string]any, error) {
	w.conn.SetReadDeadline(time.Now().Add(timeout))
	for {
		h := make([]byte, 2)
		if _, err := io.ReadFull(w.r, h); err != nil {
			return nil, err
		}
		opcode := h[0] & 0x0f
		length := int(h[1] & 0x7f)
		switch length {
		case 126:
			ext := make([]byte, 2)
			io.ReadFull(w.r, ext)
			length = int(binary.BigEndian.Uint16(ext))
		case 127:
			ext := make([]byte, 8)
			io.ReadFull(w.r, ext)
			length = int(binary.BigEndian.Uint64(ext))
		}
		payload := make([]byte, length)
		if _, err := io.ReadFull(w.r, payload); err != nil {
			return nil, err
		}
		if opcode == 0x8 {
			return nil, io.EOF
		}
		if opcode == 0x0 || opcode == 0x1 {
			var m map[string]any
			if json.Unmarshal(payload, &m) == nil {
				return m, nil
			}
		}
	}
}

func (w *ws) close() { w.conn.Close() }

// ---------- bridge ----------
type bridge struct {
	w          *ws
	tools      []string
	execMode   bool
	jobTimeout time.Duration
}

func newBridge(raw string, jobTimeout int) (*bridge, error) {
	w, err := dialWS(raw)
	if err != nil {
		return nil, err
	}
	b := &bridge{w: w, tools: allTools, jobTimeout: time.Duration(jobTimeout) * time.Second}
	if hello, err := w.recvJSON(5 * time.Second); err == nil {
		if ex, ok := hello["exec"].(bool); ok {
			b.execMode = ex
		}
		if ts, ok := hello["tools"].([]any); ok {
			b.tools = nil
			for _, t := range ts {
				b.tools = append(b.tools, fmt.Sprint(t))
			}
		}
	}
	return b, nil
}

func (b *bridge) run(target string, tools []string) map[string]string {
	b.w.sendJSON(map[string]any{"type": "run", "target": target, "tools": tools})
	results := map[string]string{}
	deadline := time.Now().Add(b.jobTimeout)
	for time.Now().Before(deadline) {
		msg, err := b.w.recvJSON(time.Until(deadline))
		if err != nil {
			break
		}
		switch msg["type"] {
		case "result":
			tag := fmt.Sprint(msg["tool"])
			results[tag] = strings.TrimSpace(results[tag] + "\n" + fmt.Sprint(msg["text"]))
		case "run-done":
			return results
		}
	}
	return results
}

// ---------- LLM ----------
type llm struct {
	url, model, key string
	temperature     float64
}

type message struct {
	Role       string     `json:"role"`
	Content    string     `json:"content,omitempty"`
	ToolCalls  []toolCall `json:"tool_calls,omitempty"`
	ToolCallID string     `json:"tool_call_id,omitempty"`
	Name       string     `json:"name,omitempty"`
}

type toolCall struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Function struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	} `json:"function"`
}

func (l *llm) chat(messages []message, tools []any) (message, error) {
	body := map[string]any{"model": l.model, "messages": messages, "temperature": l.temperature}
	if tools != nil {
		body["tools"] = tools
		body["tool_choice"] = "auto"
	}
	buf, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", l.url, bytes.NewReader(buf))
	req.Header.Set("Content-Type", "application/json")
	if l.key != "" {
		req.Header.Set("Authorization", "Bearer "+l.key)
	}
	client := &http.Client{Timeout: 300 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return message{}, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return message{}, fmt.Errorf("LLM HTTP %d: %s", resp.StatusCode, truncate(string(raw), 300))
	}
	var out struct {
		Choices []struct {
			Message message `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(raw, &out); err != nil || len(out.Choices) == 0 {
		return message{}, fmt.Errorf("bad LLM response: %s", truncate(string(raw), 200))
	}
	return out.Choices[0].Message, nil
}

// ---------- tool schemas ----------
func toolSchemas(allowActive bool) []any {
	enum := passive
	if allowActive {
		enum = allTools
	}
	fn := func(name, desc string, params map[string]any) any {
		return map[string]any{"type": "function", "function": map[string]any{
			"name": name, "description": desc, "parameters": params}}
	}
	return []any{
		fn("run_recon", "Run recon tools against one in-scope target and return their output.",
			map[string]any{"type": "object", "required": []string{"target", "tools"}, "properties": map[string]any{
				"target": map[string]any{"type": "string", "description": "domain/IPv4/IPv6/CIDR, in scope"},
				"tools":  map[string]any{"type": "array", "items": map[string]any{"type": "string", "enum": enum}}}}),
		fn("add_findings", "Record normalized entities extracted from tool output.",
			map[string]any{"type": "object", "required": []string{"events"}, "properties": map[string]any{
				"events": map[string]any{"type": "array", "items": map[string]any{"type": "object",
					"required": []string{"type", "data", "source"}, "properties": map[string]any{
						"type": map[string]any{"type": "string"}, "data": map[string]any{"type": "string"},
						"module": map[string]any{"type": "string"}, "source": map[string]any{"type": "string"},
						"t": map[string]any{"type": []string{"integer", "null"}}}}}}}),
		fn("request_scope_decision", "Ask the operator whether a target is in scope. Stops scanning.",
			map[string]any{"type": "object", "required": []string{"target", "reason"}, "properties": map[string]any{
				"target": map[string]any{"type": "string"}, "reason": map[string]any{"type": "string"}}}),
		fn("write_report", "Finalize with a Markdown intel brief. Ends the run.",
			map[string]any{"type": "object", "required": []string{"markdown"}, "properties": map[string]any{
				"markdown": map[string]any{"type": "string"}}}),
	}
}

// ---------- board / event ----------
type event struct {
	Type   string `json:"type"`
	Data   string `json:"data"`
	Module string `json:"module"`
	Source string `json:"source"`
	T      *int64 `json:"t"`
}

func buildBoard(target string, events []event) map[string]any {
	bySrc := map[string][]event{}
	order := []string{}
	for _, e := range events {
		if _, ok := bySrc[e.Source]; !ok {
			order = append(order, e.Source)
		}
		bySrc[e.Source] = append(bySrc[e.Source], e)
	}
	timelines := []any{}
	for i, src := range order {
		boxes := []any{}
		for j, e := range bySrc[src] {
			boxes = append(boxes, map[string]any{"id": fmt.Sprintf("bx%d_%d", i, j),
				"type": e.Type, "module": e.Module, "data": e.Data, "source": src, "t": e.T})
		}
		timelines = append(timelines, map[string]any{"id": fmt.Sprintf("tl%d", i),
			"title": strings.ToUpper(src) + " · " + target, "x": 140 + i*520, "y": 160,
			"color": colors[i%len(colors)],
			"points": []any{map[string]any{"id": fmt.Sprintf("pt%d", i), "t": nil,
				"expanded": true, "boxes": boxes}}})
	}
	return map[string]any{"v": 3, "cam": map[string]any{"x": 0, "y": 0, "zoom": 1},
		"timelines": timelines, "notes": []any{}, "links": []any{}, "strokes": []any{},
		"hiddenSources": map[string]any{}}
}

// ---------- agent ----------
type agent struct {
	l      *llm
	b      *bridge
	s      *scope
	cfg      config
	events   []event
	ran      map[string]bool
	report   string
	messages []message // full transcript (for -record SFT trajectories)
	tools    []any     // tool schemas in play
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func (ag *agent) truncate(text string) string {
	cap := ag.cfg.maxObs
	if len(text) <= cap {
		return text
	}
	head := text[:cap*2/3]
	tail := text[len(text)-cap/3:]
	return fmt.Sprintf("%s\n...[%d chars truncated]...\n%s", head, len(text)-cap, tail)
}

func (ag *agent) runRecon(a map[string]any) string {
	target := strings.TrimSpace(fmt.Sprint(a["target"]))
	var tools []string
	if arr, ok := a["tools"].([]any); ok {
		for _, t := range arr {
			if s := fmt.Sprint(t); contains(allTools, s) {
				tools = append(tools, s)
			}
		}
	}
	if !validTarget(target) {
		return fmt.Sprintf("REJECTED: '%s' is not a valid domain/IP/CIDR.", target)
	}
	if !ag.s.allows(target) {
		return fmt.Sprintf("REJECTED: '%s' is out of scope. Call request_scope_decision.", target)
	}
	note := ""
	var allowed []string
	var blocked []string
	for _, t := range tools {
		if contains(active, t) && !ag.cfg.allowActive {
			blocked = append(blocked, t)
			continue
		}
		if ag.ran[t+"|"+target] {
			continue
		}
		allowed = append(allowed, t)
	}
	if len(blocked) > 0 {
		note = fmt.Sprintf("(active tools %v blocked — use -allow-active) ", blocked)
	}
	if len(allowed) == 0 {
		return note + fmt.Sprintf("No new tools to run for %s.", target)
	}
	for _, t := range allowed {
		ag.ran[t+"|"+target] = true
	}
	fmt.Fprintf(os.Stderr, "  ▸ run_recon %s :: %s\n", target, strings.Join(allowed, ", "))
	results := ag.b.run(target, allowed)
	if len(results) == 0 {
		return note + fmt.Sprintf("No output returned for %s.", target)
	}
	var parts []string
	for tag, text := range results {
		parts = append(parts, fmt.Sprintf("### %s\n%s", tag, ag.truncate(text)))
	}
	return note + strings.Join(parts, "\n\n")
}

func (ag *agent) addFindings(a map[string]any) string {
	n := 0
	if arr, ok := a["events"].([]any); ok {
		for _, item := range arr {
			m, ok := item.(map[string]any)
			if !ok || m["data"] == nil {
				continue
			}
			ev := event{Type: str(m, "type", "data"), Data: fmt.Sprint(m["data"]),
				Module: str(m, "module", ""), Source: str(m, "source", "ai")}
			if tf, ok := m["t"].(float64); ok {
				ti := int64(tf)
				ev.T = &ti
			}
			ag.events = append(ag.events, ev)
			n++
		}
	}
	return fmt.Sprintf("Recorded %d finding(s). Total: %d.", n, len(ag.events))
}

func (ag *agent) scopeDecision(a map[string]any) string {
	target := fmt.Sprint(a["target"])
	if ag.cfg.yes {
		return "Operator (-yes) AUTHORIZED " + target + ". Proceed."
	}
	fmt.Fprintf(os.Stderr, "\n  ⚠ SCOPE DECISION for %s: %s\n    Authorize? [y/N] ", target, a["reason"])
	reader := bufio.NewReader(os.Stdin)
	ans, _ := reader.ReadString('\n')
	if strings.TrimSpace(strings.ToLower(ans)) == "y" {
		return "Operator AUTHORIZED " + target + ". Proceed."
	}
	return "Operator DECLINED " + target + ". Do not scan it; continue in-scope."
}

func (ag *agent) run() error {
	mode := "SIMULATE"
	if ag.b.execMode {
		mode = "REAL EXEC"
	}
	activeState := "DISABLED"
	if ag.cfg.allowActive {
		activeState = "ENABLED"
	}
	messages := []message{
		{Role: "system", Content: ag.cfg.system + "\n\n" + rubric},
		{Role: "user", Content: fmt.Sprintf(
			"Target in scope: %s\nObjective: %s\nRunner mode: %s; active tools %s.\n"+
				"Available tools: %s.\nBegin. Plan briefly, then call run_recon.",
			ag.cfg.target, ag.cfg.objective, mode, activeState, strings.Join(ag.b.tools, ", "))},
	}
	tools := toolSchemas(ag.cfg.allowActive)
	ag.tools = tools
	for step := 1; step <= ag.cfg.maxSteps; step++ {
		fmt.Fprintf(os.Stderr, "[step %d/%d]\n", step, ag.cfg.maxSteps)
		msg, err := ag.l.chat(messages, tools)
		if err != nil {
			return err
		}
		messages = append(messages, msg)
		if len(msg.ToolCalls) == 0 {
			if msg.Content != "" {
				fmt.Fprintln(os.Stderr, "  · model: "+truncate(msg.Content, 200))
			}
			messages = append(messages, message{Role: "user",
				Content: "Continue: call run_recon for the next step, or write_report if done."})
			continue
		}
		for _, call := range msg.ToolCalls {
			var a map[string]any
			json.Unmarshal([]byte(call.Function.Arguments), &a)
			name := call.Function.Name
			if name == "write_report" {
				ag.report = strings.TrimSpace(str(a, "markdown", ""))
				ag.messages = messages
				return ag.finish()
			}
			var result string
			switch name {
			case "run_recon":
				result = ag.runRecon(a)
			case "add_findings":
				result = ag.addFindings(a)
			case "request_scope_decision":
				result = ag.scopeDecision(a)
			default:
				result = "Unknown tool " + name
			}
			id := call.ID
			if id == "" {
				id = name
			}
			messages = append(messages, message{Role: "tool", ToolCallID: id, Name: name, Content: result})
		}
	}
	fmt.Fprintln(os.Stderr, "  · step budget exhausted — forcing report.")
	messages = append(messages, message{Role: "user",
		Content: "Step budget reached. Call write_report now with whatever you have."})
	if msg, err := ag.l.chat(messages, tools); err == nil {
		for _, call := range msg.ToolCalls {
			if call.Function.Name == "write_report" {
				var a map[string]any
				json.Unmarshal([]byte(call.Function.Arguments), &a)
				ag.report = str(a, "markdown", "")
			}
		}
		messages = append(messages, msg)
	}
	ag.messages = messages
	return ag.finish()
}

func (ag *agent) finish() error {
	os.MkdirAll(ag.cfg.out, 0o755)
	stamp := strings.ReplaceAll(ag.cfg.target, "/", "_")
	boardPath := filepath.Join(ag.cfg.out, stamp+".board.json")
	reportPath := filepath.Join(ag.cfg.out, stamp+".report.md")
	bj, _ := json.MarshalIndent(buildBoard(ag.cfg.target, ag.events), "", "  ")
	os.WriteFile(boardPath, bj, 0o644)
	report := ag.report
	if report == "" {
		report = ag.fallbackReport()
	}
	os.WriteFile(reportPath, []byte(report), 0o644)
	if ag.cfg.record != "" {
		ag.recordTrajectory()
	}
	fmt.Fprintf(os.Stderr, "\n✔ %d findings\n✔ board  → %s  (import with ⤒)\n✔ report → %s\n",
		len(ag.events), boardPath, reportPath)
	return nil
}

// recordTrajectory appends the run as one JSONL line for SFT: conversational
// format with tool schemas, consumable by LLaMA-Factory / Axolotl / TRL.
// Tool-role observations are re-truncated so recorded context stays
// training-sized. Against the runner's SIMULATE mode this yields clean,
// PII-free, deterministic tool-call trajectories with no live scanning.
func (ag *agent) recordTrajectory() {
	clean := make([]message, len(ag.messages))
	for i, m := range ag.messages {
		if m.Role == "tool" {
			m.Content = ag.truncate(m.Content)
		}
		clean[i] = m
	}
	mode := "simulate"
	if ag.b.execMode {
		mode = "exec"
	}
	rec := map[string]any{"messages": clean, "tools": ag.tools, "meta": map[string]any{
		"target": ag.cfg.target, "objective": ag.cfg.objective, "mode": mode,
		"findings": len(ag.events), "completed": ag.report != ""}}
	line, _ := json.Marshal(rec)
	f, err := os.OpenFile(ag.cfg.record, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "record: %v\n", err)
		return
	}
	defer f.Close()
	f.Write(append(line, '\n'))
	fmt.Fprintf(os.Stderr, "✔ trajectory → %s (append)\n", ag.cfg.record)
}

func (ag *agent) fallbackReport() string {
	var b strings.Builder
	fmt.Fprintf(&b, "# OSINT Brief — %s\n\n_Objective: %s_\n\n## Entities\n\n", ag.cfg.target, ag.cfg.objective)
	if len(ag.events) == 0 {
		b.WriteString("_No findings recorded._\n")
	}
	for _, e := range ag.events {
		fmt.Fprintf(&b, "- **%s** `%s` — %s _(via %s)_\n", e.Type, e.Data, e.Module, e.Source)
	}
	return b.String()
}

// ---------- helpers ----------
func str(m map[string]any, key, def string) string {
	if v, ok := m[key]; ok && v != nil {
		return fmt.Sprint(v)
	}
	return def
}
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
func b64(b []byte) string {
	const t = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	var out strings.Builder
	for i := 0; i < len(b); i += 3 {
		var n uint32
		rem := len(b) - i
		n = uint32(b[i]) << 16
		if rem > 1 {
			n |= uint32(b[i+1]) << 8
		}
		if rem > 2 {
			n |= uint32(b[i+2])
		}
		out.WriteByte(t[(n>>18)&63])
		out.WriteByte(t[(n>>12)&63])
		if rem > 1 {
			out.WriteByte(t[(n>>6)&63])
		} else {
			out.WriteByte('=')
		}
		if rem > 2 {
			out.WriteByte(t[n&63])
		} else {
			out.WriteByte('=')
		}
	}
	return out.String()
}

func main() {
	cfg := config{}
	flag.StringVar(&cfg.target, "target", "", "apex domain / subdomain / IP / CIDR (required)")
	flag.StringVar(&cfg.objective, "objective", "Map the external attack surface.", "engagement objective")
	flag.StringVar(&cfg.model, "model", "", "model name as the API server knows it (required)")
	flag.StringVar(&cfg.api, "api", "http://127.0.0.1:11434/v1", "OpenAI-compatible base URL")
	flag.StringVar(&cfg.apiKey, "api-key", os.Getenv("OPENAI_API_KEY"), "API key (optional)")
	flag.StringVar(&cfg.bridge, "bridge", "ws://127.0.0.1:7842", "pipe-server.js WebSocket URL")
	flag.StringVar(&cfg.scopeFile, "scope", "", "allowlist file (deny-by-default once set)")
	flag.BoolVar(&cfg.allowActive, "allow-active", false, "permit active tools (nmap, httpx)")
	flag.BoolVar(&cfg.yes, "yes", false, "auto-authorize scope prompts")
	flag.IntVar(&cfg.maxSteps, "max-steps", 16, "max agent steps")
	flag.IntVar(&cfg.maxObs, "max-obs-chars", 4000, "truncate each tool observation")
	flag.IntVar(&cfg.jobTimeout, "job-timeout", 120, "per-job seconds")
	flag.Float64Var(&cfg.temperature, "temperature", 0.2, "sampling temperature")
	flag.StringVar(&cfg.out, "out", "loot", "output dir for board.json + report.md")
	flag.StringVar(&cfg.record, "record", "", "append this run as an SFT trajectory (JSONL) for fine-tuning")
	flag.StringVar(&cfg.system, "system", "", "system prompt override (else built-in)")
	flag.Parse()

	if cfg.target == "" || cfg.model == "" {
		fmt.Fprintln(os.Stderr, "error: -target and -model are required")
		flag.Usage()
		os.Exit(2)
	}
	if cfg.system == "" {
		cfg.system = defaultSystem
	}
	if !validTarget(cfg.target) {
		fatal("invalid -target %q (need domain/IP/CIDR)", cfg.target)
	}
	sc, err := loadScope(cfg.scopeFile)
	if err != nil {
		fatal("scope: %v", err)
	}
	if len(sc.entries) == 0 {
		fmt.Fprintln(os.Stderr, "⚠ no -scope file: ALL targets allowed. Supply one for real engagements.")
	} else if !sc.allows(cfg.target) {
		fatal("-target %s not in -scope %s", cfg.target, cfg.scopeFile)
	}

	fmt.Fprintf(os.Stderr, "connecting to runner %s ...\n", cfg.bridge)
	b, err := newBridge(cfg.bridge, cfg.jobTimeout)
	if err != nil {
		fatal("bridge: %v", err)
	}
	defer b.w.close()
	mode := "simulate"
	if b.execMode {
		mode = "exec"
	}
	fmt.Fprintf(os.Stderr, "runner: mode=%s tools=%d\n", mode, len(b.tools))
	if cfg.allowActive && !b.execMode {
		fmt.Fprintln(os.Stderr, "note: -allow-active set but runner is SIMULATE (no real scans).")
	}

	l := &llm{url: strings.TrimRight(cfg.api, "/") + "/chat/completions", model: cfg.model,
		key: cfg.apiKey, temperature: cfg.temperature}
	ag := &agent{l: l, b: b, s: sc, cfg: cfg, ran: map[string]bool{}}
	if err := ag.run(); err != nil {
		fatal("%v", err)
	}
}

func fatal(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "error: "+format+"\n", a...)
	os.Exit(1)
}
