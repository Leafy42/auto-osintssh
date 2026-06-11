/* Unit tests for the OSINT runner's pure parts (no sockets, no spawning). */
const R = require('../bridge/pipe-server.js');
const A = require('../app.js');
let pass = 0, fail = 0;
const ok = (n, c, extra) => { if (c) pass++; else { fail++; console.error('FAIL  ' + n + (extra ? '  → ' + extra : '')); } };

/* ---- target validation (the injection guard) ---- */
ok('accepts domain', R.validTarget('target.example.com'));
ok('accepts ipv4', R.validTarget('203.0.113.42'));
ok('accepts cidr', R.validTarget('10.0.0.0/24'));
ok('accepts ipv6', R.validTarget('2001:db8::42'));
ok('rejects shell injection', !R.validTarget('example.com; rm -rf /'));
ok('rejects spaces', !R.validTarget('a b'));
ok('rejects backticks', !R.validTarget('`whoami`.com'));
ok('rejects pipe', !R.validTarget('x|y'));
ok('rejects empty', !R.validTarget(''));
ok('rejects overlong', !R.validTarget('a'.repeat(300) + '.com'));

/* ---- argv building: no shell, target lands as its own arg ---- */
{
  const local = R.buildArgv('nmap', 'target.example.com', null);
  ok('local nmap bin', local[0] === 'nmap');
  ok('local nmap target is a discrete arg', local.includes('target.example.com'));
  const viaSsh = R.buildArgv('nmap', 'target.example.com', 'user@box');
  ok('ssh wraps with ssh', viaSsh[0] === 'ssh' && viaSsh.includes('user@box') && viaSsh.includes('nmap'));
  ok('ssh batchmode set', viaSsh.includes('BatchMode=yes'));
  ok('unknown tool → null', R.buildArgv('nope', 'x.com', null) === null);
}

/* ---- WS frame round-trip (server encode → client-style decode) ---- */
{
  const obj = { type: 'log', tool: 'nmap', line: 'hello ☃ unicode' };
  const framed = R.encodeFrame(JSON.stringify(obj));
  // a client frame is masked; re-mask the server frame's payload to exercise the decoder
  const payload = framed.subarray(2);
  const mask = Buffer.from([1, 2, 3, 4]);
  const masked = Buffer.allocUnsafe(payload.length);
  for (let i = 0; i < payload.length; i++) masked[i] = payload[i] ^ mask[i & 3];
  const clientFrame = Buffer.concat([Buffer.from([0x81, 0x80 | payload.length]), mask, masked]);
  const dec = R.decodeFrames(clientFrame);
  ok('decode one masked frame', dec.messages.length === 1, JSON.stringify(dec.messages));
  ok('decode payload intact', dec.messages[0] === JSON.stringify(obj));
  // partial frame → waits (consumes 0)
  ok('partial frame buffered', R.decodeFrames(clientFrame.subarray(0, 4)).consumed === 0);
  // close opcode detected
  ok('close frame flagged', R.decodeFrames(Buffer.from([0x88, 0x80, 0, 0, 0, 0])).closed === true);
}

/* ---- every simulator parses through the matching PAGE parser ---- */
const simChecks = [
  ['nmap', R.simNmap, 'nmap', e => e.some(x => /22 ssh|:22/.test(x.data))],
  ['theharvester', R.simHarvester, 'theharvester', e => e.some(x => x.type === 'email')],
  ['amass', R.simAmass, 'amass', e => e.some(x => /mail\./.test(x.data))],
  ['whois', R.simWhois, 'whois', e => e.some(x => /creation/i.test(x.type) && x.t > 0)],
  ['host', R.simHost, 'dnsrecon', e => e.length > 0],
  ['subfinder', R.simSubfinder, 'subfinder', e => e.length >= 4 && e.every(x => x.type === 'domain')],
  ['httpx', R.simHttpx, 'httpx', e => e.some(x => x.type === 'url' && /www\./.test(x.data))],
  ['dnsx', R.simDnsx, 'dnsx', e => e.some(x => x.type === 'domain') && e.some(x => x.type === 'ip')],
];

/* ---- scope allowlist + CIDR ---- */
ok('inScope: empty scope allows all', R.inScope('anything.com', []));
ok('inScope: exact domain', R.inScope('target.com', ['target.com']));
ok('inScope: subdomain of scope', R.inScope('api.target.com', ['target.com']));
ok('inScope: wildcard entry', R.inScope('api.target.com', ['*.target.com']));
ok('inScope: out of scope rejected', !R.inScope('evil.com', ['target.com']));
ok('inScope: sibling not matched', !R.inScope('nottarget.com', ['target.com']));
ok('inScope: CIDR match', R.inScope('10.0.0.5', ['10.0.0.0/24']));
ok('inScope: CIDR miss', !R.inScope('10.0.1.5', ['10.0.0.0/24']));
ok('ipInCidr /32', R.ipInCidr('1.2.3.4', '1.2.3.4/32') && !R.ipInCidr('1.2.3.5', '1.2.3.4/32'));
ok('parseScope strips comments/blanks', JSON.stringify(R.parseScope('a.com\n# c\n\n b.com ')) === JSON.stringify(['a.com', 'b.com']));

/* ---- new flags parse ---- */
{
  const a = R.parseArgs(['--scope', 's.txt', '--timeout', '30', '--concurrency', '4', '--out', '/tmp/o', '--config', 'c.json']);
  ok('--scope file', a.scopeFile === 's.txt');
  ok('--timeout sec', a.timeoutSec === 30);
  ok('--concurrency n', a.concurrency === 4);
  ok('--out dir', a.outDir === '/tmp/o');
  ok('--config file', a.configFile === 'c.json');
}
for (const [name, sim, tag, check] of simChecks) {
  const text = sim('target.example.com').join('\n');
  const events = A.TOOLS[tag].parse(text);
  ok(`${name} sim parses via page parser`, events.length > 0, `0 events for ${name}`);
  ok(`${name} sim yields expected shape`, check(events), JSON.stringify(events.slice(0, 3)));
}

/* ---- arg parsing ---- */
ok('default mode simulate', R.parseArgs([]).mode === 'simulate');
ok('--exec → exec', R.parseArgs(['--exec']).mode === 'exec');
ok('--ssh sets host+exec', (a => a.mode === 'exec' && a.ssh === 'u@h')(R.parseArgs(['--ssh', 'u@h'])));
ok('--port parsed', R.parseArgs(['--port', '9000']).port === 9000);

console.log(`\nrunner: ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
