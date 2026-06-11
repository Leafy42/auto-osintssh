#!/usr/bin/env node
/* ====================================================================
   OSINT Holotable — runner & live-pipe bridge  (zero dependencies)

   Drives OSINT tools and streams their results onto the Holotable over a
   WebSocket — "a pipe into a VNC". The table can launch a job (a target +
   a set of tools); the runner executes each tool locally or over SSH and
   streams the parsed-friendly output back, live.

   ── Safety ─────────────────────────────────────────────────────────
   • SIMULATE BY DEFAULT. With no flags it runs nothing real — it emits
     realistic synthetic output so you can see the whole pipeline work.
   • Real execution requires an explicit opt-in: --exec (local) or
     --ssh user@host (remote). Authorized engagements only.
   • The web page can only ask to run tools from a fixed registry against
     a target; it can never send a shell command. Targets are validated
     (domain / IP / CIDR) and every tool runs via spawn() with an argv
     array — no shell — so a target cannot inject commands.
   • Binds to 127.0.0.1 by default.

   ── Usage ──────────────────────────────────────────────────────────
     node bridge/pipe-server.js                 # simulate (safe demo)
     node bridge/pipe-server.js --exec          # run real LOCAL tools
     node bridge/pipe-server.js --ssh user@recon-box   # run over SSH
     node bridge/pipe-server.js --demo          # passive synthetic feed
     node bridge/pipe-server.js --tool nmap -- nmap -sV target  # stream one cmd
   Then in the page: dock ▸ RECON ▸ target + tools ▸ Launch
                 (or dock ▸ LIVE PIPE ▸ connect to just watch a stream)
   ==================================================================== */
'use strict';
const http = require('http');
const crypto = require('crypto');
const { spawn } = require('child_process');

/* ============================ tool registry ============================ */
/* Each tool: the binary + an argv builder (no shell), a parser-tag the page
   uses, and a simulator that mimics real output for a target. */
const REGISTRY = {
  nmap:         { bin:'nmap',         tag:'nmap',         args:t=>['-sV','-T4','--open',t],            sim:simNmap },
  theharvester: { bin:'theHarvester', tag:'theharvester', args:t=>['-d',t,'-b','crtsh,bing','-f','-'], sim:simHarvester },
  amass:        { bin:'amass',        tag:'amass',        args:t=>['enum','-passive','-d',t],           sim:simAmass },
  whois:        { bin:'whois',        tag:'whois',        args:t=>[t],                                  sim:simWhois },
  dnsrecon:     { bin:'dnsrecon',     tag:'dnsrecon',     args:t=>['-d',t,'-j','-'],                    sim:simDnsrecon },
  host:         { bin:'host',         tag:'dnsrecon',     args:t=>['-a',t],                             sim:simHost },
};

/* target must be a clean hostname / IPv4 / CIDR / IPv6 — this is what makes
   the no-shell argv calls injection-proof. */
function validTarget(t){
  if (typeof t !== 'string') return false;
  t = t.trim();
  if (t.length > 253 || !t) return false;
  return /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/i.test(t)   // domain
      || /^\d{1,3}(?:\.\d{1,3}){3}(?:\/\d{1,2})?$/.test(t)                   // ipv4 / cidr
      || /^[0-9a-f]{1,4}(?::[0-9a-f]{0,4}){2,7}(?:\/\d{1,3})?$/i.test(t);    // ipv6
}
function buildArgv(toolKey, target, ssh){
  const tool = REGISTRY[toolKey];
  if (!tool) return null;
  const targs = tool.args(target);
  return ssh ? ['ssh','-o','BatchMode=yes','-o','ConnectTimeout=10', ssh, tool.bin, ...targs]
             : [tool.bin, ...targs];
}

/* ============================ simulators ============================ */
function simNmap(t){
  return [
    `Starting Nmap 7.94 ( https://nmap.org )`,
    `Nmap scan report for ${t} (203.0.113.42)`,
    `Host is up (0.018s latency).`,
    `PORT     STATE SERVICE   VERSION`,
    `22/tcp   open  ssh       OpenSSH 8.2p1 Ubuntu 4ubuntu0.5`,
    `80/tcp   open  http      nginx 1.18.0`,
    `443/tcp  open  ssl/https nginx 1.18.0`,
    `8080/tcp open  http-proxy Squid 4.10`,
    `Nmap done: 1 IP address (1 host up) scanned`,
  ];
}
function simHarvester(t){
  return [
    `[*] Target: ${t}`,
    `[*] Emails found:`,
    `-------------------`,
    `admin@${t}`, `j.doe@${t}`, `security@${t}`,
    `[*] Hosts found:`,
    `-------------------`,
    `www.${t}`, `mail.${t}`, `vpn.${t}`,
  ];
}
function simAmass(t){
  return [
    `www.${t}`,
    `mail.${t} (FQDN) --> a_record --> 203.0.113.43 (IPAddress)`,
    `vpn.${t} (FQDN) --> a_record --> 203.0.113.44 (IPAddress)`,
    `api.${t}`,
    `dev.${t} (FQDN) --> cname_record --> ${t.split('.').slice(-2).join('.')}.netlify.app (FQDN)`,
  ];
}
function simWhois(t){
  const yr = 2009 + (t.length % 9);
  return [
    `Domain Name: ${t.toUpperCase()}`,
    `Registrar: Example Registrar, Inc.`,
    `Creation Date: ${yr}-05-14T18:09:11Z`,
    `Updated Date: 2023-11-02T07:21:46Z`,
    `Registry Expiry Date: 2026-05-14T18:09:11Z`,
    `Registrant Organization: ${t.split('.')[0]} Holdings LLC`,
    `Name Server: NS1.${t.toUpperCase()}`,
    `Name Server: NS2.${t.toUpperCase()}`,
    `DNSSEC: unsigned`,
  ];
}
function simDnsrecon(t){
  return [
    `[*] std: Performing General Enumeration of Domain: ${t}`,
    `[*]      A ${t} 203.0.113.42`,
    `[*]      MX ${t} mail.${t} 10`,
    `[*]      NS ns1.${t} 203.0.113.2`,
    `[*]      TXT ${t} v=spf1 include:_spf.${t} ~all`,
  ];
}
function simHost(t){
  return [
    `${t} has address 203.0.113.42`,
    `${t} mail is handled by 10 mail.${t}`,
    `${t} has IPv6 address 2001:db8::42`,
  ];
}

/* ============================ minimal RFC-6455 ============================ */
const GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';
const accept = k => crypto.createHash('sha1').update(k + GUID).digest('base64');

function encodeFrame(str){
  const payload = Buffer.from(str, 'utf8'), len = payload.length;
  let header;
  if (len < 126){ header = Buffer.from([0x81, len]); }
  else if (len < 65536){ header = Buffer.alloc(4); header[0]=0x81; header[1]=126; header.writeUInt16BE(len,2); }
  else { header = Buffer.alloc(10); header[0]=0x81; header[1]=127; header.writeUInt32BE(Math.floor(len/2**32),2); header.writeUInt32BE(len>>>0,6); }
  return Buffer.concat([header, payload]);
}
// decode masked client→server frames; returns {messages:[], closed, consumed}
function decodeFrames(buf){
  const messages = []; let off = 0; let closed = false;
  while (off + 2 <= buf.length){
    const b1 = buf[off+1];
    const opcode = buf[off] & 0x0f, masked = (b1 & 0x80) !== 0;
    let len = b1 & 0x7f, p = off + 2;
    if (len === 126){ if (p+2 > buf.length) break; len = buf.readUInt16BE(p); p += 2; }
    else if (len === 127){ if (p+8 > buf.length) break; len = Number(buf.readBigUInt64BE(p)); p += 8; }
    let mask; if (masked){ if (p+4 > buf.length) break; mask = buf.subarray(p, p+4); p += 4; }
    if (p + len > buf.length) break;                       // frame incomplete — wait for more
    let payload = buf.subarray(p, p + len);
    if (masked){ const out = Buffer.allocUnsafe(len); for (let i=0;i<len;i++) out[i] = payload[i] ^ mask[i&3]; payload = out; }
    p += len; off = p;
    if (opcode === 0x8){ closed = true; break; }
    if (opcode === 0x1 || opcode === 0x0) messages.push(payload.toString('utf8'));
    // 0x9 ping / 0xA pong ignored
  }
  return { messages, closed, consumed: off };
}

/* ============================ server ============================ */
function startServer(opts){
  const { port, host, mode, ssh, fast, streamCmd, streamTag } = opts;
  const clients = new Set();
  const send = (sock, obj) => { try { sock.write(encodeFrame(JSON.stringify(obj))); } catch(_){ clients.delete(sock); } };
  const broadcast = obj => { for (const s of clients) send(s, obj); };
  const log = (tool, line) => { broadcast({ type:'log', tool, line }); process.stdout.write(`· [${tool}] ${line}\n`); };

  const server = http.createServer((req, res) => { res.writeHead(200, {'content-type':'text/plain'}); res.end('OSINT Holotable runner — connect a WebSocket.\n'); });
  server.on('upgrade', (req, socket) => {
    const key = req.headers['sec-websocket-key'];
    if (!key){ socket.destroy(); return; }
    socket.write('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ' + accept(key) + '\r\n\r\n');
    clients.add(socket);
    console.log(`[runner] client connected (${clients.size})`);
    send(socket, { type:'hello', mode, tools:Object.keys(REGISTRY), exec: mode!=='simulate' });
    let acc = Buffer.alloc(0);
    socket.on('data', chunk => {
      acc = Buffer.concat([acc, chunk]);
      const { messages, closed, consumed } = decodeFrames(acc);
      acc = acc.subarray(consumed);
      for (const m of messages){ try { onMessage(socket, JSON.parse(m)); } catch(_){} }
      if (closed){ clients.delete(socket); try { socket.end(); } catch(_){} }
    });
    socket.on('close', () => { clients.delete(socket); console.log(`[runner] client left (${clients.size})`); });
    socket.on('error', () => clients.delete(socket));
  });

  function onMessage(sock, msg){
    if (!msg || msg.type !== 'run') return;
    const target = String(msg.target || '').trim();
    const tools = (Array.isArray(msg.tools) ? msg.tools : []).filter(t => REGISTRY[t]);
    if (!validTarget(target)){ send(sock, { type:'log', tool:'runner', line:`# rejected target "${target}" — must be a domain, IP or CIDR` }); return; }
    if (!tools.length){ send(sock, { type:'log', tool:'runner', line:'# no known tools selected' }); return; }
    runJob(target, tools);
  }

  // run the selected tools one after another, streaming logs then a parsed result per tool
  async function runJob(target, tools){
    broadcast({ type:'run-start', target, tools });
    console.log(`[runner] job ${target} :: ${tools.join(', ')} (${mode})`);
    for (const toolKey of tools){
      const tool = REGISTRY[toolKey];
      log(tool.tag, `# === ${toolKey} ${target} ===`);
      try { await runOneTool(toolKey, target); }
      catch (e){ log(tool.tag, `# ${toolKey} error: ${e.message}`); }
    }
    broadcast({ type:'run-done', target });
    log('runner', `# run complete: ${target}`);
  }

  function runOneTool(toolKey, target){
    const tool = REGISTRY[toolKey];
    return new Promise(resolve => {
      if (mode === 'simulate'){
        const lines = tool.sim(target); let i = 0;
        const tick = () => {
          if (i < lines.length){ log(tool.tag, lines[i++]); setTimeout(tick, fast ? 0 : 90); }
          else { broadcast({ type:'result', tool: tool.tag, text: lines.join('\n') }); resolve(); }
        };
        tick();
        return;
      }
      // real execution (local or ssh)
      const argv = buildArgv(toolKey, target, ssh);
      let child;
      try { child = spawn(argv[0], argv.slice(1), { stdio:['ignore','pipe','pipe'] }); }
      catch (e){ log(tool.tag, `# spawn failed: ${e.message}`); return resolve(); }
      let buf = '', full = '';
      child.stdout.on('data', d => {
        buf += d.toString(); full += d.toString();
        const ls = buf.split(/\r?\n/); buf = ls.pop();
        for (const l of ls) if (l.length) log(tool.tag, l);
      });
      child.stderr.on('data', d => process.stderr.write(d));
      child.on('error', e => { log(tool.tag, `# ${tool.bin} not available (${e.code||e.message})`); resolve(); });
      child.on('close', code => {
        if (buf.trim()){ full += buf; log(tool.tag, buf); }
        if (full.trim()) broadcast({ type:'result', tool: tool.tag, text: full });
        log(tool.tag, `# ${toolKey} exited (${code})`);
        resolve();
      });
    });
  }

  /* legacy: stream one command's stdout (kept for power users) */
  function runStreamCmd(){
    log(streamTag, `# streaming: ${streamCmd.join(' ')}`);
    let child;
    try { child = spawn(streamCmd[0], streamCmd.slice(1), { stdio:['ignore','pipe','pipe'] }); }
    catch (e){ console.error('[runner] spawn failed:', e.message); return; }
    let buf = '';
    child.stdout.on('data', d => { buf += d.toString(); const ls = buf.split(/\r?\n/); buf = ls.pop(); for (const l of ls) if (l.length) log(streamTag, l); });
    child.stderr.on('data', d => process.stderr.write(d));
    child.on('close', code => { if (buf.trim()) log(streamTag, buf); log(streamTag, `# exited (${code})`); });
    child.on('error', e => console.error('[runner] spawn error:', e.message));
  }

  /* passive demo feed */
  function runDemo(){
    const feed = simNmap('demo.example.com').map(l=>['nmap',l])
      .concat(simAmass('demo.example.com').map(l=>['amass',l]))
      .concat(simWhois('demo.example.com').map(l=>['whois',l]));
    let i = 0; setInterval(() => { const [t,l] = feed[i++ % feed.length]; log(t, l); }, fast ? 50 : 1400);
  }

  server.listen(port, host, () => {
    console.log(`\n  OSINT Holotable runner`);
    console.log(`  listening  ws://${host}:${port}`);
    console.log(`  mode       ${mode}${ssh ? ' via ssh '+ssh : ''}`);
    console.log(`  tools      ${Object.keys(REGISTRY).join(', ')}`);
    console.log(`  in page    dock ▸ RECON ▸ target + tools ▸ Launch\n`);
    if (streamCmd) runStreamCmd();
    else if (mode === 'demo') runDemo();
  });
  return { server, broadcast, clients };
}

/* ============================ CLI ============================ */
function parseArgs(argv){
  let port = 7842, host = '127.0.0.1', mode = 'simulate', ssh = null, fast = false, streamCmd = null, streamTag = 'lines';
  for (let i = 0; i < argv.length; i++){
    const a = argv[i];
    if (a === '--port') port = parseInt(argv[++i], 10);
    else if (a === '--host') host = argv[++i];
    else if (a === '--exec') mode = 'exec';
    else if (a === '--ssh'){ mode = 'exec'; ssh = argv[++i]; }
    else if (a === '--demo') mode = 'demo';
    else if (a === '--fast') fast = true;
    else if (a === '--tool') streamTag = argv[++i];
    else if (a === '--') { streamCmd = argv.slice(i+1); break; }
    else if (a === '-h' || a === '--help'){ console.log('node bridge/pipe-server.js [--exec | --ssh user@host | --demo] [--port N] [--host H] [--tool tag -- cmd...]'); process.exit(0); }
  }
  return { port, host, mode, ssh, fast, streamCmd, streamTag };
}

if (require.main === module){
  process.on('SIGINT', () => { console.log('\n[runner] shutting down'); process.exit(0); });
  startServer(parseArgs(process.argv.slice(2)));
}

/* export pure parts for tests */
module.exports = { REGISTRY, validTarget, buildArgv, decodeFrames, encodeFrame,
  simNmap, simHarvester, simAmass, simWhois, simDnsrecon, simHost, startServer, parseArgs };
