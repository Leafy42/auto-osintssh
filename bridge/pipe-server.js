#!/usr/bin/env node
/* ====================================================================
   OSINT Holotable — live pipe bridge  (optional, zero dependencies)

   Streams a CLI tool's stdout into the Holotable over a WebSocket so the
   table updates live as a scan runs — "a pipe into a VNC". Pure Node, no
   npm install, so it runs on a locked-down forensic/jump box.

   The pipe is ONE-WAY: the browser only RECEIVES lines. The web page can
   never send commands back here, so opening the page cannot run anything
   on this machine. You choose the command on the CLI, for tools you are
   authorized to run.

   Usage:
     node bridge/pipe-server.js                       # demo feed (synthetic)
     node bridge/pipe-server.js --tool nmap -- nmap -sV -T4 target.example.com
     node bridge/pipe-server.js --tool amass -- amass enum -d target.example.com
     node bridge/pipe-server.js --tool spiderfoot --port 7842 -- tail -f scan.csv

   Then in the page: dock ▸ LIVE PIPE ▸ ws://localhost:7842 ▸ connect.
   The chosen --tool selects which parser the page runs on each line.
   ==================================================================== */
'use strict';
const http = require('http');
const crypto = require('crypto');
const { spawn } = require('child_process');

/* ---- args ---- */
const argv = process.argv.slice(2);
let tool = 'lines', port = 7842, host = '127.0.0.1', cmd = null;
for (let i = 0; i < argv.length; i++) {
  const a = argv[i];
  if (a === '--tool') tool = argv[++i];
  else if (a === '--port') port = parseInt(argv[++i], 10);
  else if (a === '--host') host = argv[++i];
  else if (a === '--demo') cmd = null;
  else if (a === '--') { cmd = argv.slice(i + 1); break; }
  else if (a === '-h' || a === '--help') { printHelp(); process.exit(0); }
}
function printHelp() {
  console.log('node bridge/pipe-server.js [--tool <name>] [--port N] [--host H] [-- <command...>]');
  console.log('tools: spiderfoot theharvester nmap amass shodan reconng whois dnsrecon csv json lines');
}

/* ---- minimal RFC-6455 server (text frames, server→client only) ---- */
const GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';
const clients = new Set();
const accept = k => crypto.createHash('sha1').update(k + GUID).digest('base64');

function encodeFrame(str) {
  const payload = Buffer.from(str, 'utf8'), len = payload.length;
  let header;
  if (len < 126) { header = Buffer.from([0x81, len]); }
  else if (len < 65536) { header = Buffer.alloc(4); header[0] = 0x81; header[1] = 126; header.writeUInt16BE(len, 2); }
  else { header = Buffer.alloc(10); header[0] = 0x81; header[1] = 127; header.writeUInt32BE(Math.floor(len / 2 ** 32), 2); header.writeUInt32BE(len >>> 0, 6); }
  return Buffer.concat([header, payload]);
}
function send(socket, obj) { try { socket.write(encodeFrame(JSON.stringify(obj))); } catch (_) { clients.delete(socket); } }
function broadcast(obj) { for (const s of clients) send(s, obj); }

const server = http.createServer((req, res) => {
  res.writeHead(200, { 'content-type': 'text/plain' });
  res.end('OSINT Holotable pipe bridge. Connect a WebSocket to this URL.\n');
});
server.on('upgrade', (req, socket) => {
  const key = req.headers['sec-websocket-key'];
  if (!key) { socket.destroy(); return; }
  socket.write(
    'HTTP/1.1 101 Switching Protocols\r\n' +
    'Upgrade: websocket\r\nConnection: Upgrade\r\n' +
    'Sec-WebSocket-Accept: ' + accept(key) + '\r\n\r\n'
  );
  clients.add(socket);
  console.log(`[pipe] client connected (${clients.size} total)`);
  send(socket, { tool, line: `# connected to holotable pipe — tool=${tool}` });
  socket.on('data', buf => { if (buf.length && (buf[0] & 0x0f) === 0x8) { clients.delete(socket); try { socket.end(); } catch (_) {} } });
  socket.on('close', () => { clients.delete(socket); console.log(`[pipe] client left (${clients.size} total)`); });
  socket.on('error', () => clients.delete(socket));
});

server.listen(port, host, () => {
  console.log(`\n  OSINT Holotable pipe bridge`);
  console.log(`  listening  ws://${host}:${port}   tool=${tool}`);
  console.log(cmd ? `  streaming  ${cmd.join(' ')}` : `  mode       demo (synthetic feed)`);
  console.log(`  in page    dock ▸ LIVE PIPE ▸ connect\n`);
  cmd ? runCommand() : runDemo();
});

/* ---- stream a real command's stdout, line by line ---- */
function runCommand() {
  let child;
  try { child = spawn(cmd[0], cmd.slice(1), { stdio: ['ignore', 'pipe', 'pipe'] }); }
  catch (e) { console.error('[pipe] failed to spawn:', e.message); return; }
  let buf = '';
  const pump = chunk => {
    buf += chunk.toString();
    const lines = buf.split(/\r?\n/); buf = lines.pop();
    for (const line of lines) { if (line.length) { broadcast({ tool, line }); process.stdout.write('· ' + line + '\n'); } }
  };
  child.stdout.on('data', pump);
  child.stderr.on('data', d => process.stderr.write(d));
  child.on('close', code => { if (buf.trim()) broadcast({ tool, line: buf }); broadcast({ tool, line: `# process exited (${code})` }); console.log(`[pipe] command exited ${code}`); });
  child.on('error', e => console.error('[pipe] spawn error:', e.message));
}

/* ---- demo feed so you can see the pipe work with no tools installed ---- */
function runDemo() {
  const feed = [
    ['nmap', 'Nmap scan report for target.example.com (203.0.113.42)'],
    ['nmap', '22/tcp   open  ssh        OpenSSH 8.2p1'],
    ['nmap', '443/tcp  open  ssl/https  nginx 1.18.0'],
    ['spiderfoot', '"' + ts() + '","Email Address","sfp_hunter","target.example.com","","ops@target.example.com"'],
    ['amass', 'cdn.target.example.com (FQDN) --> a_record --> 198.51.100.9 (IPAddress)'],
    ['lines', 'leaked credential found: svc_backup@target.example.com'],
  ];
  let i = 0;
  setInterval(() => {
    const [t, line] = feed[i % feed.length]; i++;
    broadcast({ tool: t, line });
    process.stdout.write(`· [${t}] ${line}\n`);
  }, 1500);
}
function ts() { const d = new Date(); const p = n => String(n).padStart(2, '0'); return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`; }

process.on('SIGINT', () => { console.log('\n[pipe] shutting down'); process.exit(0); });
