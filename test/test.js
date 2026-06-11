/* Node unit tests for the pure helpers in app.js (no DOM required). */
const A = require('../app.js');
let pass=0, fail=0;
function ok(name, cond, extra){ if(cond){pass++; /*console.log('  ok  '+name)*/} else {fail++; console.error('FAIL  '+name+(extra?'  → '+extra:''));} }
function eq(name,a,b){ ok(name, a===b, `got ${JSON.stringify(a)} want ${JSON.stringify(b)}`); }

/* ---- time ---- */
eq('epoch seconds', A.parseTime('1622383200'), 1622383200000);
eq('epoch ms', A.parseTime('1622383200000'), 1622383200000);
ok('iso parses', A.parseTime('2021-05-30T14:00:00') > 0);
ok('space datetime parses', A.parseTime('2021-05-30 14:00:00') > 0);
eq('garbage → null', A.parseTime('not a date'), null);
eq('empty → null', A.parseTime(''), null);
// round-trip datetime-local
{
  const ms = A.parseTime('2021-05-30 14:23:00');
  const li = A.toLocalInput(ms);
  ok('local input shape', /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$/.test(li), li);
  const back = A.fromLocalInput(li);
  ok('round-trip within a minute', Math.abs(back-ms) < 60000);
}

/* ---- bucketing ---- */
{
  const t = A.parseTime('2021-05-30 14:23:45');
  eq('bucket second', A.bucketMs(t,'second'), Math.floor(t/1000)*1000);
  eq('bucket minute', A.bucketMs(t,'minute'), Math.floor(t/60000)*60000);
  eq('bucket hour', A.bucketMs(t,'hour'), Math.floor(t/3600000)*3600000);
  eq('bucket raw passes through', A.bucketMs(t,'raw'), t);
  const d=new Date(A.bucketMs(t,'day')); eq('bucket day h', d.getHours(), 0);
}

/* ---- classify ---- */
eq('classify email', A.classify('a@b.com'), 'email');
eq('classify ip', A.classify('203.0.113.7'), 'ip');
eq('classify url', A.classify('https://x.io/p'), 'url');
eq('classify domain', A.classify('sub.example.com'), 'domain');
eq('classify md5', A.classify('d41d8cd98f00b204e9800998ecf8427e'), 'hash-md5');
eq('classify cve', A.classify('CVE-2021-1234'), 'cve');

/* ---- CSV ---- */
{
  const rows = A.parseCSV('a,b,c\n1,"two, 2",3\r\n4,"q""q",6\n');
  eq('csv rows', rows.length, 3);
  eq('csv embedded comma', rows[1][1], 'two, 2');
  eq('csv escaped quote', rows[2][1], 'q"q');
}

/* ---- SpiderFoot ---- */
{
  const csv = '"Updated","Type","Module","Source","F/P","Data"\n'+
              '"2021-05-30 14:23:01","IP Address","sfp_dnsresolve","example.com","","203.0.113.7"\n'+
              '"2021-05-30 14:24:10","Email","sfp_hunter","example.com","","a@example.com"\n';
  const ev = A.parseSpiderfoot(csv);
  eq('sf count', ev.length, 2);
  eq('sf type', ev[0].type, 'IP Address');
  eq('sf data', ev[0].data, '203.0.113.7');
  eq('sf module', ev[0].module, 'sfp_dnsresolve');
  ok('sf timed', ev[0].t>0);
  eq('sf source tag', ev[0].source, 'spiderfoot');
  // reordered headers still map
  const csv2='Data,Module,Type,Updated\nfoo.com,sfp_x,Domain,2020-01-01 00:00:00\n';
  const ev2=A.parseSpiderfoot(csv2);
  eq('sf reordered data', ev2[0].data, 'foo.com');
  eq('sf reordered type', ev2[0].type, 'Domain');
}

/* ---- generic JSON / theHarvester shape ---- */
{
  const j = JSON.stringify({ emails:['a@x.com','b@x.com'], hosts:['h1.x.com','h2.x.com'], ips:['1.1.1.1'] });
  const ev = A.parseHarvester(j);
  ok('harvester json count', ev.length===5, ev.length);
  ok('harvester has email', ev.some(e=>e.data==='a@x.com'));
  // text form
  const txt='[*] Emails found:\n----\nc@x.com\n[*] Hosts found:\n----\nh3.x.com\n';
  const ev2=A.parseHarvester(txt);
  ok('harvester text emails', ev2.some(e=>e.data==='c@x.com'&&e.type==='email'));
  ok('harvester text hosts', ev2.some(e=>e.data==='h3.x.com'));
}

/* ---- nmap ---- */
{
  const grep='Host: 203.0.113.7 () Ports: 22/open/tcp//ssh///, 443/open/tcp//https///\n';
  const ev=A.parseNmap(grep);
  ok('nmap host', ev.some(e=>e.data==='203.0.113.7'));
  ok('nmap ssh port', ev.some(e=>/22 ssh/.test(e.data)));
  const norm='Nmap scan report for host.x.com (203.0.113.9)\nPORT   STATE SERVICE\n22/tcp open  ssh\n80/tcp closed http\n';
  const ev2=A.parseNmap(norm);
  ok('nmap normal open only', ev2.some(e=>/22 ssh/.test(e.data)) && !ev2.some(e=>/80/.test(e.data)));
  ok('nmap splits hostname', ev2.some(e=>e.data==='host.x.com'&&e.type==='domain'));
  ok('nmap splits ip', ev2.some(e=>e.data==='203.0.113.9'&&e.type==='ip'));
}

/* ---- shodan JSON ---- */
{
  const j='[{"ip_str":"203.0.113.42","port":443,"org":"ExHost","hostnames":["t.example.com"],"timestamp":"2024-03-10T11:05:02"},{"ip_str":"203.0.113.44","port":1194,"hostnames":["vpn.example.com"]}]';
  const ev=A.parseShodan(j);
  ok('shodan ip:port', ev.some(e=>e.type==='port'&&/203\.0\.113\.42:443/.test(e.data)));
  ok('shodan keeps host', ev.some(e=>/t\.example\.com/.test(e.data)));
  ok('shodan timed where available', ev.some(e=>e.t>0));
}

/* ---- amass ---- */
{
  const ev=A.parseAmass('www.example.com\nmail.example.com (FQDN) --> a_record --> 1.2.3.4 (IPAddress)\n');
  ok('amass domain', ev.some(e=>e.data==='www.example.com'));
  ok('amass relation ip', ev.some(e=>e.data==='1.2.3.4'));
}

/* ---- whois ---- */
{
  const w='Registrar: Example Inc\nCreation Date: 2010-03-04T00:00:00Z\nName Server: ns1.x.com\nFoo: bar\n';
  const ev=A.parseWhois(w);
  ok('whois registrar', ev.some(e=>e.data==='Example Inc'));
  ok('whois creation timed', ev.some(e=>e.type==='creation_date'&&e.t>0));
  ok('whois drops boring', !ev.some(e=>e.data==='bar'));
}

/* ---- eventsToPoints + layout ---- */
{
  const t1=A.parseTime('2021-05-30 14:23:01'), t2=A.parseTime('2021-05-30 14:23:50'), t3=A.parseTime('2021-05-30 15:00:00');
  const events=[{t:t1,type:'ip',data:'a',source:'x'},{t:t2,type:'ip',data:'b',source:'x'},{t:t3,type:'ip',data:'c',source:'x'},{t:null,type:'note',data:'d',source:'x'}];
  const ptsMin=A.eventsToPoints(events,'minute');
  // t1,t2 share the minute bucket → one point; t3 another; null → untimed
  eq('minute buckets', ptsMin.length, 3);
  const merged=ptsMin.find(p=>p.boxes.length===2);
  ok('two events merged into a minute', !!merged);
  ok('untimed sorts first', ptsMin[0].t===null);
  const ptsHour=A.eventsToPoints(events,'hour');
  eq('hour buckets', ptsHour.length, 3); // 14:xx (2), 15:xx (1), untimed
  const w=A.layoutPoints(ptsMin);
  ok('layout assigns x', ptsMin.every((p,i)=> p.x === ptsMin[0].x + i*( (ptsMin[1].x-ptsMin[0].x) )), 'even spacing');
  ok('points dont overlap (>=150px apart)', ptsMin.slice(1).every((p,i)=> p.x-ptsMin[i].x >= 150));
  ok('canvas widens with count', w >= ptsMin[ptsMin.length-1].x);
}

/* ---- source color stable ---- */
ok('known tool color', A.sourceColor('nmap')==='#27e8a7');
ok('unknown source deterministic', A.sourceColor('weirdtool')===A.sourceColor('weirdtool'));

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail?1:0);
