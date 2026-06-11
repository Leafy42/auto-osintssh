# OSINT Holotable

A free-floating, **MS-Paint-style intel table** for OSINT work. Lay out as many
timelines as you want across an infinite canvas; each point on a timeline holds a
**stack of overlapping, semi-transparent event boxes** that you can fan open with
a single command. Ingest output from **many tools — not just SpiderFoot** — and
pipe a live CLI scan straight onto the table as it runs.

It is one folder of static files. **No build, no server, no network calls.** Open
`index.html` from `file://` and it works on a disconnected forensic box.

![OSINT Holotable](docs/holotable.png)

---

## The idea

> *"…kinda like Iron Man in the Avengers, where he can plot in 3D in his living
> room and work through a complex scene. Multiple timelines, free-floating, almost
> like MS Paint where you can use your whole screen. Multiple OSINT tools, CLI
> based, so you can take the information from there — almost like a pipe into a VNC."*

That's the brief. Concretely:

- **The table is the whole screen.** Pan by dragging empty space, zoom with the
  wheel. A holographic grid gives you spatial reference. Drop timelines and notes
  anywhere.
- **Timelines stack events.** Every event sharing a time-bucket collapses into one
  receding, translucent stack with a count badge. Click a point — or hit **`E`** —
  to fan them all open into a readable column.
- **Everything is writeable.** Edit any event's type / data / module inline, edit a
  point's timestamp, rename timelines. Add and delete points, boxes, timelines.
- **Drag-and-drop works freely.** Grab an event by its `⠿` grip and drop it on any
  point — on the same timeline or a different one. While you drag, every point lights
  up a translucent drop-zone.
- **Pipe in any tool.** Parsers for SpiderFoot, Nmap, theHarvester, Amass, Shodan,
  Recon-ng, WHOIS, DNSRecon, plus generic CSV/JSON/raw-lines. Paste, drop a file, or
  stream a live scan over a local WebSocket bridge.

---

## Run it

```bash
git clone <this repo>
cd auto-osintssh
# just open the file — no server needed
xdg-open index.html        # Linux
open index.html            # macOS
```

Or double-click `index.html`. It runs entirely in the browser; nothing is uploaded.
Your board autosaves to the browser's local storage, and you can **Export** a
portable `.json` case file to move between machines or commit to a repo.

---

## Ingesting tool output

Click **Ingest** (or press **`I`**), pick the tool, paste its output (or drop the
file), choose a grouping granularity, and choose a target timeline (or a new one).
Sample exports for every parser live in [`samples/`](samples/).

| Tool | Accepts |
|------|---------|
| **SpiderFoot** | CSV export (`Updated, Type, Module, Source, Data` — tolerant of column order/names) |
| **theHarvester** | JSON or the plain-text `[*] … found:` report |
| **Nmap** | normal output, greppable (`-oG`), or XML — open ports → events, hostnames/IPs split out |
| **Amass** | host list or the `name --> record --> ip` relation format |
| **Shodan** | host/search JSON (→ `ip:port` services) or `shodan host` text |
| **Recon-ng** | CSV export |
| **WHOIS** | raw `key: value` text (registrar, creation/expiry dates timed automatically) |
| **DNSRecon** | JSON / CSV |
| **Generic CSV / JSON / Raw lines** | anything else — values are auto-classified (ip, email, domain, url, hash, CVE…) |

Header row count doesn't match what you expected? Paste your exact header row and the
column aliases can be widened — see `headerIndex()` in `app.js`.

Events are colour-coded by source. The **dock legend** lets you toggle any source's
visibility; **search** (top bar) dims everything that doesn't match.

---

## Live pipe — stream a scan onto the table

The optional bridge streams a CLI tool's **stdout** into the table over a local
WebSocket, so the board fills in as the scan runs. **Zero dependencies** (pure Node),
and the pipe is **one-way**: the page only *receives* lines, so opening the page can
never run anything on your machine. You choose the command, on the CLI, for tools you
are authorized to run.

```bash
# synthetic demo feed (no tools needed) — just to see it work
node bridge/pipe-server.js

# stream a real scan, tagging lines with the parser to use
node bridge/pipe-server.js --tool nmap  -- nmap -sV -T4 target.example.com
node bridge/pipe-server.js --tool amass -- amass enum -d target.example.com
node bridge/pipe-server.js --tool spiderfoot -- tail -f spiderfoot-scan.csv
```

Then in the page: **dock ▸ LIVE PIPE ▸ `ws://localhost:7842` ▸ connect**. Parsed
events land on a `LIVE FEED` timeline; raw lines scroll in the console.

> This is the "pipe into a VNC" seam. Today the upstream is a local command's stdout;
> the same WebSocket message shape (`{tool, line}` / `{tool, events:[…]}`) is exactly
> what an SSH-driven remote scanner would emit, which is the planned `auto-osintssh`
> back end.

---

## Controls

| | |
|---|---|
| **Pan** | drag empty space · hold **Space** · **`H`** mode |
| **Zoom** | mouse wheel (zooms to cursor) · **`F`** frames everything |
| **Select / edit** | **`V`** — click a box to select, click its text to edit |
| **Move event** | drag the `⠿` grip onto any point (any timeline) |
| **Expand / collapse** | click a point · per-timeline `⤢`/`⤡` · all: **`E`** / **`C`** |
| **Link events** | **`L`**, click two boxes (double-click a link to remove) |
| **Pen / Note** | **`P`** free-draw · **`N`** drop a sticky note |
| **New timeline** | **`T`** or the toolbar |
| **Undo / redo** | **⌘/Ctrl-Z** · **⌘/Ctrl-Shift-Z** |
| **Delete** | select + **Delete** · per-item `✕` |
| **Right-click** | context menu on events / timelines / canvas |

Saves live in the top-right: name a case, **Save**, then **Load**/**Delete** from the
dropdown. **Export ⤓** / **Import ⤒** move portable `.json` boards.

---

## Architecture

One folder, three core files, no framework:

```
index.html        # shell / DOM skeleton
styles.css        # the holographic OSINT theme
app.js            # engine: camera, render, interaction, parsers, pipe, saves
bridge/           # optional zero-dependency live-pipe WebSocket server
samples/          # one realistic export per supported tool
test/             # unit tests (pure) + headless browser smoke test
```

- The **camera** is a `{x, y, zoom}` transform on a `#world` div; the grid is drawn on
  a viewport-fixed canvas from the same camera, so they stay in lockstep.
- **Timelines and notes** are absolutely-positioned DOM (cheap inline editing); **links
  and pen strokes** render on an SVG layer in world space so they pan/zoom together.
- Parsers, time/bucketing and point-layout are **pure functions**, exported for Node
  tests. All ingested data is rendered via `textContent` (never `innerHTML`), so a
  malicious value in a target's data can't inject markup.
- `window.holotable` is a small scripting handle — `push()`, `ingestText()`, `setCam()`,
  `fit()` — for driving the table programmatically.

### Tests

```bash
npm test                                   # pure-helper unit tests (zero deps)
NODE_PATH=$(npm root -g) npm run test:smoke # headless-browser smoke test (needs playwright)
```

`npm test` covers the parsers (incl. CSV edge cases, header reordering, tool formats),
time round-trips, bucketing and anti-overlap layout. The smoke test loads the real page
and exercises boot, ingest, the free-drag, linking, notes, search, zoom, save and undo.

---

## Notes & roadmap

- **"Wrap-around" scroll** from an earlier iteration is superseded by free pan/zoom —
  the whole table is now the scroll surface, so timelines never run out of room.
- **Granularity is applied at ingest time** (per import), deliberately, so it never
  re-buckets and fights your manual point/timestamp edits afterward.
- Next seams: SSH-driven remote scan runner feeding the same pipe; per-timeline
  time-proportional spacing as a toggle; multi-select drag.

Authorized / defensive use only — for your own engagements, CTFs, and research.
