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
  subfinder:    { bin:'subfinder',    tag:'subfinder',    args:t=>['-d',t,'-silent'],                   sim:simSubfinder },
  amass:        { bin:'amass',        tag:'amass',        args:t=>['enum','-passive','-d',t],           sim:simAmass },
  dnsx:         { bin:'dnsx',         tag:'dnsx',         args:t=>['-d',t,'-a','-resp','-silent'],      sim:simDnsx },
  httpx:        { bin:'httpx',        tag:'httpx',        args:t=>['-u',t,'-json','-silent'],           sim:simHttpx },
  nmap:         { bin:'nmap',         tag:'nmap',         args:t=>['-sV','-T4','--open',t],            sim:simNmap },
  theharvester: { bin:'theHarvester', tag:'theharvester', args:t=>['-d',t,'-b','crtsh,bing','-f','-'], sim:simHarvester },
  whois:        { bin:'whois',        tag:'whois',        args:t=>[t],                                  sim:simWhois },
  dnsrecon:     { bin:'dnsrecon',     tag:'dnsrecon',     args:t=>['-d',t,'-j','-'],                    sim:simDnsrecon },
  host:         { bin:'host',         tag:'dnsrecon',     args:t=>['-a',t],                             sim:simHost },
  bbot:         { bin:'bbot',         tag:'bbot',         args:t=>['-t',t,'-y','-f','subdomain-enum'],  sim:simBbot },
};

/* ---- scope allowlist (optional --scope file) ---- */
function ipToInt(ip){ const p=String(ip).split('.').map(Number); if(p.length!==4||p.some(x=>isNaN(x)||x<0||x>255)) return null; return ((p[0]<<24)>>>0)+(p[1]<<16)+(p[2]<<8)+p[3]; }
function ipInCidr(ip, cidr){ const [net,bitsS]=String(cidr).split('/'); const bits=parseInt(bitsS,10); const a=ipToInt(ip), b=ipToInt(net); if(a==null||b==null||isNaN(bits)||bits<0||bits>32) return false; const mask=bits===0?0:(~((1<<(32-bits))-1))>>>0; return (a&mask)===(b&mask); }
function inScope(target, scope){
  if (!scope || !scope.length) return true;            // no scope file → everything allowed
  const t=String(target).toLowerCase().trim();
  for (let e of scope){
    e=String(e).toLowerCase().trim(); if(!e||e[0]==='#') continue;
    if (e.startsWith('*.')) e=e.slice(2);
    if (t===e || t.endsWith('.'+e)) return true;
    if (e.includes('/') && ipInCidr(t, e)) return true;
  }
  return false;
}
function parseScope(text){ return String(text).split(/\r?\n/).map(s=>s.trim()).filter(s=>s&&s[0]!=='#'); }

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
function simSubfinder(t){ return ['www.'+t, 'mail.'+t, 'vpn.'+t, 'api.'+t, 'dev.'+t, 'staging.'+t]; }
function simDnsx(t){ return [`www.${t} [A] [203.0.113.42]`, `mail.${t} [A] [203.0.113.43]`, `vpn.${t} [A] [203.0.113.44]`, `${t} [MX] [mail.${t}]`]; }
function simHttpx(t){ return [
  `{"url":"https://www.${t}","host":"203.0.113.42","status_code":200,"title":"Home","tech":["nginx","React"]}`,
  `{"url":"https://api.${t}","host":"203.0.113.43","status_code":403,"title":"Forbidden","tech":["nginx"]}`,
  `{"url":"https://vpn.${t}","host":"203.0.113.44","status_code":200,"title":"VPN Portal","tech":["OpenResty"]}`,
]; }
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
// BBOT emits NDJSON — one event per line, each tagged with a scope_distance
// (hops from the seed target). The page's bbot parser reads this directly.
function simBbot(t){
  const ts = Math.floor(Date.now()/1000);
  return [
    JSON.stringify({type:'DNS_NAME',      data:t,                   module:'TARGET',       scope_distance:0, timestamp:ts}),
    JSON.stringify({type:'DNS_NAME',      data:'www.'+t,            module:'crt',          scope_distance:1, timestamp:ts}),
    JSON.stringify({type:'DNS_NAME',      data:'mail.'+t,           module:'crt',          scope_distance:1, timestamp:ts}),
    JSON.stringify({type:'IP_ADDRESS',    data:'203.0.113.42',      module:'A',            scope_distance:1, timestamp:ts}),
    JSON.stringify({type:'OPEN_TCP_PORT', data:'203.0.113.42:443',  module:'portscan',     scope_distance:1, timestamp:ts}),
    JSON.stringify({type:'URL',           data:'https://www.'+t+'/',module:'httpx',        scope_distance:1, timestamp:ts}),
    JSON.stringify({type:'EMAIL_ADDRESS', data:'admin@'+t,          module:'emailformat',  scope_distance:1, timestamp:ts}),
    JSON.stringify({type:'FINDING',       data:{description:'Open S3 bucket',host:'203.0.113.42'}, module:'bucket_amazon', scope_distance:1, timestamp:ts}),
    JSON.stringify({type:'VULNERABILITY', data:{severity:'HIGH',description:'CVE-2023-1234 exposed admin panel',host:'203.0.113.42'}, module:'nuclei', scope_distance:1, timestamp:ts}),
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
  const timeoutSec = opts.timeoutSec || 0;
  const concurrency = Math.max(1, opts.concurrency || 1);
  const outDir = opts.outDir || null;

  // merge any custom tools from --config; load scope allowlist from --scope
  const REG = Object.assign({}, REGISTRY);
  if (opts.configFile){
    try{ const cfg = JSON.parse(require('fs').readFileSync(opts.configFile, 'utf8'));
      for (const k in cfg){ const c = cfg[k]; const tmpl = c.args || ['{target}'];
        REG[k] = { bin:c.bin, tag:c.tag||'lines', args:t=>tmpl.map(a=>a==='{target}'?t:a), sim:t=>[`# custom tool ${k} (${c.bin}) — run with --exec`, `# would run: ${c.bin} ${tmpl.map(a=>a==='{target}'?t:a).join(' ')}`] };
      }
      console.log(`[runner] loaded ${Object.keys(cfg).length} custom tool(s) from ${opts.configFile}`);
    }catch(e){ console.error('[runner] --config failed:', e.message); }
  }
  let scope = [];
  if (opts.scopeFile){
    try{ scope = parseScope(require('fs').readFileSync(opts.scopeFile, 'utf8')); console.log(`[runner] scope: ${scope.length} entr${scope.length===1?'y':'ies'} from ${opts.scopeFile}`); }
    catch(e){ console.error('[runner] --scope failed:', e.message); }
  }
  if (outDir){ try{ require('fs').mkdirSync(outDir, { recursive:true }); }catch(e){} }

  const clients = new Set();
  const send = (sock, obj) => { try { sock.write(encodeFrame(JSON.stringify(obj))); } catch(_){ clients.delete(sock); } };
  const broadcast = obj => { for (const s of clients) send(s, obj); };
  const log = (tool, line) => { broadcast({ type:'log', tool, line }); process.stdout.write(`· [${tool}] ${line}\n`); };
  const argvFor = (toolKey, target) => { const tool=REG[toolKey]; const targs=tool.args(target); return ssh?['ssh','-o','BatchMode=yes','-o','ConnectTimeout=10',ssh,tool.bin,...targs]:[tool.bin,...targs]; };
  const saveOut = (toolKey, target, text) => { if(!outDir) return; try{ require('fs').writeFileSync(require('path').join(outDir, `${target}-${toolKey}.txt`.replace(/[^\w.@-]+/g,'_')), text); }catch(e){} };

  const server = http.createServer((req, res) => { res.writeHead(200, {'content-type':'text/plain'}); res.end('OSINT Holotable runner — connect a WebSocket.\n'); });
  server.on('upgrade', (req, socket) => {
    const key = req.headers['sec-websocket-key'];
    if (!key){ socket.destroy(); return; }
    socket.write('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ' + accept(key) + '\r\n\r\n');
    clients.add(socket);
    console.log(`[runner] client connected (${clients.size})`);
    send(socket, { type:'hello', mode, tools:Object.keys(REG), exec: mode!=='simulate', scoped: scope.length>0 });
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
    const tools = (Array.isArray(msg.tools) ? msg.tools : []).filter(t => REG[t]);
    if (!validTarget(target)){ send(sock, { type:'log', tool:'runner', line:`# rejected target "${target}" — must be a domain, IP or CIDR` }); return; }
    if (!inScope(target, scope)){ send(sock, { type:'log', tool:'runner', line:`# rejected target "${target}" — out of scope (--scope)` }); return; }
    if (!tools.length){ send(sock, { type:'log', tool:'runner', line:'# no known tools selected' }); return; }
    runJob(target, tools);
  }

  // run the selected tools (up to `concurrency` at once), streaming logs then a parsed result per tool
  async function runJob(target, tools){
    broadcast({ type:'run-start', target, tools });
    console.log(`[runner] job ${target} :: ${tools.join(', ')} (${mode}${concurrency>1?', x'+concurrency:''})`);
    const queue = tools.slice();
    const worker = async () => {
      let toolKey;
      while ((toolKey = queue.shift())){
        log(REG[toolKey].tag, `# === ${toolKey} ${target} ===`);
        try { await runOneTool(toolKey, target); }
        catch (e){ log(REG[toolKey].tag, `# ${toolKey} error: ${e.message}`); }
      }
    };
    await Promise.all(Array.from({length:Math.min(concurrency, tools.length)}, worker));
    broadcast({ type:'run-done', target });
    log('runner', `# run complete: ${target}`);
  }

  function runOneTool(toolKey, target){
    const tool = REG[toolKey];
    return new Promise(resolve => {
      if (mode === 'simulate'){
        const lines = tool.sim(target); let i = 0;
        const tick = () => {
          if (i < lines.length){ log(tool.tag, lines[i++]); setTimeout(tick, fast ? 0 : 90); }
          else { const text=lines.join('\n'); saveOut(toolKey, target, text); broadcast({ type:'result', tool: tool.tag, text }); resolve(); }
        };
        tick();
        return;
      }
      // real execution (local or ssh)
      const argv = argvFor(toolKey, target);
      let child, done=false, killer=null;
      const finish = (full) => { if(done) return; done=true; if(killer) clearTimeout(killer); if(full && full.trim()){ saveOut(toolKey, target, full); broadcast({ type:'result', tool: tool.tag, text: full }); } resolve(); };
      try { child = spawn(argv[0], argv.slice(1), { stdio:['ignore','pipe','pipe'] }); }
      catch (e){ log(tool.tag, `# spawn failed: ${e.message}`); return finish(''); }
      if (timeoutSec>0) killer = setTimeout(()=>{ log(tool.tag, `# ${toolKey} timed out after ${timeoutSec}s — killed`); try{ child.kill('SIGKILL'); }catch(_){} }, timeoutSec*1000);
      let buf = '', full = '';
      child.stdout.on('data', d => {
        buf += d.toString(); full += d.toString();
        const ls = buf.split(/\r?\n/); buf = ls.pop();
        for (const l of ls) if (l.length) log(tool.tag, l);
      });
      child.stderr.on('data', d => process.stderr.write(d));
      child.on('error', e => { log(tool.tag, `# ${tool.bin} not available (${e.code||e.message})`); finish(''); });
      child.on('close', code => { if (buf.trim()){ full += buf; log(tool.tag, buf); } log(tool.tag, `# ${toolKey} exited (${code})`); finish(full); });
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
    console.log(`  mode       ${mode}${ssh ? ' via ssh '+ssh : ''}${concurrency>1?' · x'+concurrency:''}${timeoutSec?' · timeout '+timeoutSec+'s':''}${scope.length?' · scoped':''}${outDir?' · out '+outDir:''}`);
    console.log(`  tools      ${Object.keys(REG).join(', ')}`);
    console.log(`  in page    dock ▸ RECON ▸ target + tools ▸ Launch\n`);
    if (streamCmd) runStreamCmd();
    else if (mode === 'demo') runDemo();
  });
  return { server, broadcast, clients };
}

/* ============================ CLI ============================ */
function parseArgs(argv){
  let port = 7842, host = '127.0.0.1', mode = 'simulate', ssh = null, fast = false, streamCmd = null, streamTag = 'lines';
  let scopeFile = null, configFile = null, outDir = null, timeoutSec = 0, concurrency = 1;
  for (let i = 0; i < argv.length; i++){
    const a = argv[i];
    if (a === '--port') port = parseInt(argv[++i], 10);
    else if (a === '--host') host = argv[++i];
    else if (a === '--exec') mode = 'exec';
    else if (a === '--ssh'){ mode = 'exec'; ssh = argv[++i]; }
    else if (a === '--demo') mode = 'demo';
    else if (a === '--fast') fast = true;
    else if (a === '--scope') scopeFile = argv[++i];
    else if (a === '--config') configFile = argv[++i];
    else if (a === '--out') outDir = argv[++i];
    else if (a === '--timeout') timeoutSec = parseInt(argv[++i], 10) || 0;
    else if (a === '--concurrency') concurrency = parseInt(argv[++i], 10) || 1;
    else if (a === '--tool') streamTag = argv[++i];
    else if (a === '--list-tools'){ console.log(Object.keys(REGISTRY).join('\n')); process.exit(0); }
    else if (a === '--') { streamCmd = argv.slice(i+1); break; }
    else if (a === '-h' || a === '--help'){
      console.log('node bridge/pipe-server.js [options] [--tool tag -- cmd...]\n' +
        '  --exec | --ssh user@host | --demo   real local / over-ssh / passive demo (default: simulate)\n' +
        '  --scope FILE       only allow targets in this allowlist (domains / *.domain / CIDR)\n' +
        '  --config FILE      add custom tools (JSON: {"name":{"bin":"x","args":["-d","{target}"],"tag":"lines"}})\n' +
        '  --out DIR          save each tool\'s raw output to DIR\n' +
        '  --timeout SEC      kill any tool after SEC seconds\n' +
        '  --concurrency N    run up to N tools at once (default 1)\n' +
        '  --port N --host H  bind address (default 127.0.0.1:7842)\n' +
        '  --list-tools       print the built-in tool registry and exit');
      process.exit(0);
    }
  }
  return { port, host, mode, ssh, fast, streamCmd, streamTag, scopeFile, configFile, outDir, timeoutSec, concurrency };
}

if (require.main === module){
  process.on('SIGINT', () => { console.log('\n[runner] shutting down'); process.exit(0); });
  startServer(parseArgs(process.argv.slice(2)));
}

/* export pure parts for tests */
module.exports = { REGISTRY, validTarget, buildArgv, decodeFrames, encodeFrame,
  ipToInt, ipInCidr, inScope, parseScope,
  simNmap, simHarvester, simAmass, simWhois, simDnsrecon, simHost, simSubfinder, simHttpx, simDnsx, simBbot,
  startServer, parseArgs };
