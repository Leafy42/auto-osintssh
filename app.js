/* ====================================================================
   OSINT HOLOTABLE — engine
   A free-floating, MS-Paint-style intel table: multiple timelines that
   stack events into expandable boxes, multi-tool ingestion, a live CLI
   pipe, links, notes and freehand drawing. Fully client-side / offline.

   Layout note: pure helpers (parsers, time, geometry) live at the top and
   are exported for Node unit tests. Everything that touches the DOM is
   inside functions called from init(), which only runs in a browser.
   ==================================================================== */
'use strict';

/* ---------------------------------------------------------------- ids */
let _uid = 0;
function uid(p){ return (p||'id') + '_' + (Date.now().toString(36)) + (_uid++).toString(36) + Math.random().toString(36).slice(2,6); }

/* -------------------------------------------------------------- time */
// Parse a wide range of timestamp forms → epoch ms, or null if not a time.
function parseTime(v){
  if (v == null) return null;
  if (typeof v === 'number') return v < 1e12 ? v*1000 : v;     // sec vs ms
  let s = String(v).trim();
  if (!s) return null;
  if (/^\d{10}$/.test(s)) return parseInt(s,10)*1000;          // epoch seconds
  if (/^\d{13}$/.test(s)) return parseInt(s,10);               // epoch ms
  // "YYYY-MM-DD HH:MM:SS" → make it ISO-ish for Date.parse
  let iso = s.replace(/^(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}(:\d{2})?)/, '$1T$2');
  let t = Date.parse(iso);
  if (!isNaN(t)) return t;
  t = Date.parse(s);
  return isNaN(t) ? null : t;
}
function pad2(n){ return n<10 ? '0'+n : ''+n; }
function fmtTime(ms){
  if (ms == null) return 'untimed';
  const d = new Date(ms);
  return d.getFullYear()+'-'+pad2(d.getMonth()+1)+'-'+pad2(d.getDate())+' '+
         pad2(d.getHours())+':'+pad2(d.getMinutes())+':'+pad2(d.getSeconds());
}
function toLocalInput(ms){
  if (ms == null) return '';
  const d = new Date(ms);
  return d.getFullYear()+'-'+pad2(d.getMonth()+1)+'-'+pad2(d.getDate())+'T'+
         pad2(d.getHours())+':'+pad2(d.getMinutes());
}
function fromLocalInput(s){ const t = Date.parse(s); return isNaN(t)?null:t; }

const GRAN = { second:1000, minute:60000, hour:3600000, day:86400000 };
function bucketMs(ms, gran){
  if (ms == null) return null;
  if (gran === 'raw' || !GRAN[gran]) return ms;
  if (gran === 'day'){ const d=new Date(ms); d.setHours(0,0,0,0); return d.getTime(); }
  const step = GRAN[gran];
  return Math.floor(ms/step)*step;
}

/* --------------------------------------------------- classify a value */
function classify(v){
  const s = String(v||'').trim();
  if (!s) return 'data';
  if (/^https?:\/\//i.test(s)) return 'url';
  if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(s)) return 'email';
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(s)) return 'ip';
  if (/^[0-9a-f]{1,4}(:[0-9a-f]{0,4}){2,7}$/i.test(s) && s.includes('::')|| /^([0-9a-f]{1,4}:){7}[0-9a-f]{1,4}$/i.test(s)) return 'ipv6';
  if (/^CVE-\d{4}-\d+$/i.test(s)) return 'cve';
  if (/^AS\d+$/i.test(s)) return 'asn';
  if (/^[a-f0-9]{32}$/i.test(s)) return 'hash-md5';
  if (/^[a-f0-9]{40}$/i.test(s)) return 'hash-sha1';
  if (/^[a-f0-9]{64}$/i.test(s)) return 'hash-sha256';
  if (/^(bc1|[13])[a-km-zA-HJ-NP-Z0-9]{25,42}$/.test(s)) return 'btc';
  if (/^\+?\d[\d\s().-]{6,}\d$/.test(s)) return 'phone';
  if (/^([a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$/i.test(s)) return 'domain';
  return 'data';
}

/* --------------------------------------------------------- CSV parser */
// RFC-4180-ish: quoted fields, embedded commas/newlines, "" escapes, CRLF.
function parseCSV(text){
  const rows = []; let row = [], field = '', i = 0, q = false;
  const s = String(text);
  while (i < s.length){
    const c = s[i];
    if (q){
      if (c === '"'){ if (s[i+1] === '"'){ field+='"'; i+=2; continue; } q=false; i++; continue; }
      field += c; i++; continue;
    }
    if (c === '"'){ q = true; i++; continue; }
    if (c === ','){ row.push(field); field=''; i++; continue; }
    if (c === '\r'){ i++; continue; }
    if (c === '\n'){ row.push(field); rows.push(row); row=[]; field=''; i++; continue; }
    field += c; i++;
  }
  row.push(field); rows.push(row);
  // drop a trailing empty row
  if (rows.length && rows[rows.length-1].length===1 && rows[rows.length-1][0]==='') rows.pop();
  return rows;
}
function headerIndex(headers, names){
  const low = headers.map(h => String(h||'').trim().toLowerCase());
  for (const n of names){ const i = low.indexOf(n); if (i>=0) return i; }
  // fuzzy contains
  for (const n of names){ const i = low.findIndex(h => h.includes(n)); if (i>=0) return i; }
  return -1;
}

/* ============================ TOOL PARSERS ============================ */
/* Each returns: [{ t, type, module, data, source }]                     */

function ev(o){ return { t:o.t??null, type:o.type||'data', module:o.module||'', data:o.data==null?'':String(o.data), source:o.source||'' }; }

function parseSpiderfoot(text){
  const rows = parseCSV(text); if (!rows.length) return [];
  const h = rows[0];
  const iDate = headerIndex(h, ['updated','date','last seen','seen','time']);
  const iType = headerIndex(h, ['type','event type','data type']);
  const iMod  = headerIndex(h, ['module','source module','scanned by']);
  const iData = headerIndex(h, ['data','value']);
  const iSrc  = headerIndex(h, ['source','source data']);
  const hasHeader = (iType>=0 || iData>=0 || iDate>=0);
  const body = hasHeader ? rows.slice(1) : rows;
  return body.filter(r=>r.length>1 || (r[0]&&r[0].trim())).map(r=>{
    const data = iData>=0 ? r[iData] : r[r.length-1];
    return ev({
      t: parseTime(iDate>=0 ? r[iDate] : null),
      type: (iType>=0 ? r[iType] : '') || classify(data),
      module: (iMod>=0 ? r[iMod] : '') || (iSrc>=0 ? r[iSrc] : ''),
      data, source:'spiderfoot'
    });
  });
}

function parseCSVGeneric(text, source){
  const rows = parseCSV(text); if (!rows.length) return [];
  const h = rows[0];
  const iDate = headerIndex(h, ['date','time','timestamp','updated','seen','created','first seen','last seen']);
  const iType = headerIndex(h, ['type','category','kind','record','event']);
  const iMod  = headerIndex(h, ['module','source','tool','provider','scanner']);
  const iData = headerIndex(h, ['data','value','host','ip','domain','name','address','result','target','indicator']);
  const looksHeader = /[a-z]/i.test(h.join('')) && (iDate>=0||iType>=0||iData>=0);
  const body = looksHeader ? rows.slice(1) : rows;
  return body.filter(r=>r.join('').trim()).map(r=>{
    const data = iData>=0 ? r[iData] : r[r.length-1];
    return ev({
      t: parseTime(iDate>=0 ? r[iDate] : null),
      type: (iType>=0 ? r[iType] : '') || classify(data),
      module: iMod>=0 ? r[iMod] : (looksHeader?'':''),
      data, source: source||'csv'
    });
  });
}

function flattenJSON(obj, source){
  // Try to coerce arbitrary JSON into events.
  const out = [];
  const mapObj = (o)=>{
    const get = (...k)=>{ for (const key of k){ if (o[key]!=null && typeof o[key] !== 'object') return o[key]; } return undefined; };
    const t = parseTime(get('date','time','timestamp','updated','seen','last_seen','first_seen','created_at','created'));
    const data = get('data','value','host','hostname','ip','ip_str','domain','name','address','url','email','result','indicator','target');
    const type = get('type','category','record_type','kind') || (data!=null?classify(data):'data');
    const module = get('module','source','tool','provider','scanner','org','isp');
    if (data!=null) out.push(ev({t,type,module,data,source}));
    return data!=null;
  };
  const walk = (node, keyHint)=>{
    if (Array.isArray(node)){ node.forEach(n=>walk(n,keyHint)); return; }
    if (node && typeof node === 'object'){
      const used = mapObj(node);
      // also descend into array-valued props (theHarvester-style {emails:[...], hosts:[...]})
      for (const k in node){
        const val = node[k];
        if (Array.isArray(val)){
          val.forEach(v=>{
            if (v && typeof v === 'object') walk(v, k);
            else if (v!=null) out.push(ev({type:classify(v)||k, module:k, data:v, source}));
          });
        } else if (val && typeof val === 'object' && !used){
          walk(val, k);
        }
      }
      return;
    }
  };
  walk(obj, '');
  return out;
}
// True only when the text is *actually* valid JSON — guards against console
// markers like "[*]" / "[+]" that merely start with a bracket.
function looksLikeJSON(s){
  s = String(s).trim();
  if (s[0] !== '{' && s[0] !== '[') return false;
  try { JSON.parse(s); return true; } catch(_){ return false; }
}
function parseJSONGeneric(text, source){
  let obj; try { obj = JSON.parse(text); } catch(e){
    // maybe NDJSON
    const lines = String(text).split(/\r?\n/).filter(Boolean);
    const arr = []; for (const ln of lines){ try{ arr.push(JSON.parse(ln)); }catch(_){} }
    if (!arr.length) return [];
    obj = arr;
  }
  return flattenJSON(obj, source||'json');
}

function parseHarvester(text){
  const s = String(text).trim();
  if (looksLikeJSON(s)) return parseJSONGeneric(text, 'theharvester');
  // plain text report: sections like "[*] Emails found:" then a list
  const out = []; let section = '';
  for (let line of s.split(/\r?\n/)){
    line = line.trim(); if (!line) continue;
    const m = line.match(/^\[\*\]\s*(.+?)(?:\s*found)?\s*:?\s*$/i);
    if (m){ section = m[1].toLowerCase(); continue; }
    if (/^[-=]{3,}$/.test(line)) continue;
    if (/^\[/.test(line)) continue;
    const type = section.includes('email') ? 'email'
               : section.includes('host')||section.includes('subdomain') ? 'domain'
               : section.includes('ip') ? 'ip'
               : section.includes('url') ? 'url' : classify(line);
    out.push(ev({type, module: section||'theharvester', data:line, source:'theharvester'}));
  }
  return out.length ? out : parseLines(text, 'theharvester');
}

function parseNmap(text){
  const out = []; const s = String(text);
  if (s.startsWith('<?xml') || s.includes('<nmaprun')){
    // minimal XML scrape
    const hosts = s.split(/<host\b/);
    for (let i=1;i<hosts.length;i++){
      const blk = hosts[i];
      const addr = (blk.match(/addr="([^"]+)"/)||[])[1] || '';
      const re = /<port[^>]*portid="(\d+)"[^>]*>([\s\S]*?)<\/port>/g; let m;
      while ((m = re.exec(blk))){
        const port = m[1], inner = m[2];
        const state = (inner.match(/state="([^"]+)"/)||[])[1]||'';
        const svc = (inner.match(/<service[^>]*name="([^"]+)"/)||[])[1]||'';
        if (state==='open') out.push(ev({type:'port', module:'nmap', data:`${addr}:${port} ${svc}`.trim(), source:'nmap'}));
      }
      if (addr) out.push(ev({type:'ip', module:'nmap', data:addr, source:'nmap'}));
    }
    return out;
  }
  // greppable: "Host: 1.2.3.4 () Ports: 22/open/tcp//ssh///, 80/open/tcp//http///"
  let curHost = '';
  for (let line of s.split(/\r?\n/)){
    line = line.trim(); if (!line) continue;
    let m = line.match(/^Host:\s*([\d.]+|[\da-f:]+)\s*\(([^)]*)\)\s*Ports:\s*(.+)$/i);
    if (m){
      const host = m[1]; out.push(ev({type:'ip',module:'nmap',data:host,source:'nmap'}));
      m[3].split(',').forEach(p=>{
        const parts = p.trim().split('/');
        if (parts[1]==='open') out.push(ev({type:'port',module:'nmap',data:`${host}:${parts[0]} ${parts[4]||''}`.trim(),source:'nmap'}));
      });
      continue;
    }
    m = line.match(/Nmap scan report for\s+([^\s(]+)(?:\s+\(([\d.]+)\))?/i);
    if (m){
      curHost = m[1];
      out.push(ev({type:classify(curHost),module:'nmap',data:curHost,source:'nmap'}));
      if (m[2]) out.push(ev({type:'ip',module:'nmap',data:m[2],source:'nmap'}));
      continue;
    }
    // normal: "22/tcp   open  ssh    OpenSSH 8.2"
    m = line.match(/^(\d+)\/(tcp|udp)\s+(\w+)\s+([^\s]+)(?:\s+(.*))?$/i);
    if (m && m[3].toLowerCase()==='open'){
      const svc = m[4], extra = (m[5]||'').trim();
      out.push(ev({type:'port',module:'nmap',data:`${curHost?curHost+':':''}${m[1]} ${svc}${extra?' '+extra:''}`.trim(),source:'nmap'}));
    }
  }
  return out;
}

function parseAmass(text){
  const s = String(text).trim();
  if (looksLikeJSON(s)) return parseJSONGeneric(text,'amass');
  const out = [];
  for (let line of s.split(/\r?\n/)){
    line = line.trim(); if (!line) continue;
    // "host.example.com (FQDN) --> a_record --> 1.2.3.4 (IPAddress)"
    const rel = line.match(/^(\S+)\s+\([^)]*\)\s*-->\s*(\S+)\s*-->\s*(\S+)/);
    if (rel){
      out.push(ev({type:'domain',module:'amass',data:rel[1],source:'amass'}));
      out.push(ev({type:classify(rel[3])||'ip',module:'amass:'+rel[2],data:rel[3],source:'amass'}));
      continue;
    }
    const first = line.split(/\s+/)[0];
    out.push(ev({type:classify(first),module:'amass',data:first,source:'amass'}));
  }
  return out;
}

function parseShodan(text){
  const s = String(text).trim();
  if (looksLikeJSON(s)){
    let obj; try{ obj = JSON.parse(s); }catch(_){ return parseJSONGeneric(text,'shodan'); }
    const arr = Array.isArray(obj) ? obj : (obj.matches || obj.services || [obj]);
    const out = [];
    for (const o of (Array.isArray(arr)?arr:[arr])){
      if (!o || typeof o !== 'object') continue;
      const ip = o.ip_str || o.ip; const port = o.port;
      const host = (Array.isArray(o.hostnames) && o.hostnames[0]) || '';
      const t = parseTime(o.timestamp || o.last_seen);
      const mod = o.org || o.isp || o.product || 'shodan';
      if (ip!=null && port!=null) out.push(ev({t, type:'port', module:mod, data:`${ip}:${port}${host?' '+host:''}`, source:'shodan'}));
      else if (ip!=null) out.push(ev({t, type:'ip', module:mod, data:ip, source:'shodan'}));
      else if (host) out.push(ev({t, type:'domain', module:mod, data:host, source:'shodan'}));
    }
    if (out.length) return out;
    return parseJSONGeneric(text,'shodan');
  }
  // "shodan host" text output
  const out = [];
  for (let line of s.split(/\r?\n/)){
    line = line.trim(); if (!line) continue;
    let m = line.match(/^(\d+)\s+(tcp|udp)\s+(.*)$/i);
    if (m){ out.push(ev({type:'port',module:'shodan',data:`${m[1]} ${m[3]||''}`.trim(),source:'shodan'})); continue; }
    m = line.match(/^([\w.-]+):\s*(.+)$/);
    if (m){ out.push(ev({type:m[1].toLowerCase(),module:'shodan',data:m[2],source:'shodan'})); continue; }
    out.push(ev({type:classify(line),module:'shodan',data:line,source:'shodan'}));
  }
  return out;
}

function parseWhois(text){
  const out = [];
  for (let line of String(text).split(/\r?\n/)){
    line = line.trim(); if (!line || line.startsWith('%')||line.startsWith('#')||line.startsWith('>>>')) continue;
    const m = line.match(/^([A-Za-z][\w \/.-]+?):\s*(.+)$/);
    if (!m) continue;
    const key = m[1].trim().toLowerCase(), val = m[2].trim();
    const interesting = /(registrar|registrant|creation|created|updated|expir|name server|nserver|admin|tech|org|email|dnssec|status|country)/i.test(key);
    if (!interesting) continue;
    const t = /(creation|created|updated|expir)/i.test(key) ? parseTime(val) : null;
    out.push(ev({t, type:key.replace(/\s+/g,'_'), module:'whois', data:val, source:'whois'}));
  }
  return out;
}

function parseDns(text){
  const s = String(text).trim();
  if (looksLikeJSON(s)) return parseJSONGeneric(text,'dnsrecon');
  if (s.includes(',')) return parseCSVGeneric(text, 'dnsrecon');
  return parseLines(text, 'dnsrecon');
}

function parseLines(text, source){
  const out = [];
  for (let line of String(text).split(/\r?\n/)){
    line = line.trim(); if (!line) continue;
    out.push(ev({type:classify(line), module:'', data:line, source:source||'lines'}));
  }
  return out;
}

/* -------- modern recon tools (ProjectDiscovery & friends) -------- */
function parseHttpx(text){
  const out=[];
  for (let line of String(text).split(/\r?\n/)){
    line=line.trim(); if(!line) continue;
    if (line[0]==='{'){
      try{ const o=JSON.parse(line);
        const url=o.url||o.input||o.host||''; const sc=o.status_code||o.status||'';
        const tech=Array.isArray(o.tech||o.technologies)?(o.tech||o.technologies).join(','):'';
        const mod=['httpx', sc&&('['+sc+']'), tech].filter(Boolean).join(' ');
        if (url) out.push(ev({type:'url', module:mod, data:url+(o.title?(' — '+o.title):''), source:'httpx'}));
        if (o.host && o.host!==url) out.push(ev({type:classify(o.host), module:'httpx', data:o.host, source:'httpx'}));
      }catch(_){}
      continue;
    }
    // text form: "https://x.com [200] [Title] [nginx]"
    const m=line.match(/^(\S+)\s*(.*)$/);
    if (m){ const meta=(m[2]||'').replace(/\[[0-9;]*m/g,'').replace(/\s+/g,' ').trim();
      out.push(ev({type:'url', module:('httpx'+(meta?' '+meta:'')).slice(0,80), data:m[1], source:'httpx'})); }
  }
  return out;
}
function parseNuclei(text){
  const out=[];
  for (let line of String(text).split(/\r?\n/)){
    line=line.trim(); if(!line) continue;
    if (line[0]==='{'){
      try{ const o=JSON.parse(line);
        const id=o['template-id']||o.templateID||o.template_id||'finding';
        const host=o.host||o['matched-at']||o.matched||o.url||'';
        const sev=(o.info&&o.info.severity)||o.severity||'nuclei';
        if (host) out.push(ev({type:sev, module:'nuclei:'+id, data:host, source:'nuclei'}));
      }catch(_){}
      continue;
    }
    // "[template-id] [protocol] [severity] matched-at"
    const m=line.replace(/\[[0-9;]*m/g,'').match(/^\[([^\]]+)\]\s*\[([^\]]+)\]\s*\[([^\]]+)\]\s*(\S+)/);
    if (m) out.push(ev({type:m[3], module:'nuclei:'+m[1], data:m[4], source:'nuclei'}));
  }
  return out;
}
function parseMasscan(text){
  const s=String(text).trim();
  if (looksLikeJSON(s)) return parseJSONGeneric(text,'masscan');
  const out=[];
  for (let line of s.split(/\r?\n/)){
    line=line.trim(); if(!line||line[0]==='#') continue;
    let m=line.match(/^open\s+(tcp|udp)\s+(\d+)\s+([\d.]+|[\da-f:]+)/i);   // list format
    if (m){ out.push(ev({type:'port', module:'masscan', data:`${m[3]}:${m[2]} ${m[1]}`, source:'masscan'})); continue; }
    m=line.match(/Host:\s*([\d.]+|[\da-f:]+).*Ports:\s*(\d+)\/open/i);     // grepable
    if (m) out.push(ev({type:'port', module:'masscan', data:`${m[1]}:${m[2]}`, source:'masscan'}));
  }
  return out;
}
function parseDnsx(text){
  const out=[];
  for (let line of String(text).split(/\r?\n/)){
    line=line.trim(); if(!line) continue;
    if (line[0]==='{'){
      try{ const o=JSON.parse(line);
        const host=o.host||o.name; if(host) out.push(ev({type:'domain', module:'dnsx', data:host, source:'dnsx'}));
        ['a','aaaa','cname'].forEach(k=>{ const v=o[k]; (Array.isArray(v)?v:v?[v]:[]).forEach(x=>out.push(ev({type:classify(x), module:'dnsx:'+k.toUpperCase(), data:x, source:'dnsx'}))); });
      }catch(_){}
      continue;
    }
    // "host.com [A] [1.2.3.4]"
    const m=line.match(/^(\S+)\s+\[([A-Z]+)\]\s+\[([^\]]+)\]/);
    if (m){ out.push(ev({type:'domain', module:'dnsx', data:m[1], source:'dnsx'}));
      m[3].split(/[,\s]+/).forEach(v=>v&&out.push(ev({type:classify(v), module:'dnsx:'+m[2], data:v, source:'dnsx'}))); continue; }
    out.push(ev({type:classify(line.split(/\s+/)[0]), module:'dnsx', data:line.split(/\s+/)[0], source:'dnsx'}));
  }
  return out;
}
function parseSubdomains(text, source){       // subfinder / assetfinder / sublist3r / findomain
  const out=[]; source=source||'subfinder';
  for (let line of String(text).split(/\r?\n/)){
    line=line.trim(); if(!line) continue;
    if (line[0]==='{'){ try{ const o=JSON.parse(line); const h=o.host||o.name||o.subdomain||o.input; if(h) out.push(ev({type:'domain', module:source, data:h, source})); }catch(_){} continue; }
    const h=line.split(/[\s,]+/)[0];
    out.push(ev({type:classify(h)||'domain', module:source, data:h, source}));
  }
  return out;
}
function parseUrls(text, source){             // gau / waybackurls / katana / hakrawler / gospider
  const out=[]; source=source||'urls';
  for (let line of String(text).split(/\r?\n/)){
    line=line.trim(); if(!line) continue;
    const toks=line.split(/\s+/); const u=toks.find(t=>/^https?:\/\//.test(t))||toks[toks.length-1];
    out.push(ev({type:'url', module:source, data:u, source}));
  }
  return out;
}
function parseSecrets(text){                  // gitleaks / trufflehog JSON
  const s=String(text).trim();
  let arr;
  try{ arr=JSON.parse(s); }catch(_){ arr=[]; for(const l of s.split(/\r?\n/)){ if(l.trim()) try{ arr.push(JSON.parse(l)); }catch(e){} } }
  if (!arr || (!Array.isArray(arr) && typeof arr!=='object')) return parseLines(text,'secrets');
  if (!Array.isArray(arr)) arr=arr.results||arr.findings||[arr];
  const out=[];
  for (const o of arr){ if(!o||typeof o!=='object') continue;
    const rule=o.RuleID||o.rule||o.DetectorName||o.detector_name||o.detector||'secret';
    const file=o.File||o.file||(o.SourceMetadata?JSON.stringify(o.SourceMetadata).slice(0,40):'');
    const secret=o.Secret||o.Match||o.Raw||o.raw||o.match||'';
    out.push(ev({type:'secret', module:'secret:'+rule, data:((file?file+' ':'')+String(secret).slice(0,60)).trim()||rule, source:'secrets'}));
  }
  return out.length?out:parseJSONGeneric(text,'secrets');
}

/* -------- format auto-detection -------- */
function detectTool(text, filename){
  const name=(filename||'').toLowerCase();
  const s=String(text||'').trim();
  const head=s.slice(0,4000);
  const byName={spiderfoot:/spiderfoot/,nmap:/nmap/,masscan:/masscan/,amass:/amass/,subfinder:/subfinder|assetfinder|sublist3r|findomain/,httpx:/httpx/,nuclei:/nuclei/,dnsx:/dnsx/,shodan:/shodan/,whois:/whois/,theharvester:/harvest/,urls:/gau|wayback|katana|hakrawler/,maltego:/maltego/,secrets:/gitleaks|trufflehog|secret/,censys:/censys/};
  for (const k in byName) if (byName[k].test(name)) return k;
  if (!head) return 'lines';
  if (/"template-id"|"matched-at"/.test(head) || /^\[[\w-]+\]\s*\[\w+\]\s*\[(info|low|medium|high|critical)\]/im.test(head)) return 'nuclei';
  if (/"status_code"|"webserver"|"content_length"/.test(head) && /"url"|"host"/.test(head)) return 'httpx';
  if (/^open\s+(tcp|udp)\s+\d+/im.test(head)) return 'masscan';
  if (/Nmap scan report|Ports:\s*\d+\/open|^\d+\/tcp\s+open/im.test(head)) return 'nmap';
  if (/-->\s*\w*_?record\s*-->/.test(head)) return 'amass';
  if (/^\[\*\]\s|Emails found|Hosts found/im.test(head)) return 'theharvester';
  if (/(Registrar|Creation Date|Domain Name|Registry Expiry):/i.test(head)) return 'whois';
  if (/^\S+\s+\[[A-Z]+\]\s+\[/m.test(head)) return 'dnsx';
  const lines=head.split(/\r?\n/).map(l=>l.trim()).filter(Boolean).slice(0,25);
  if (lines.length && lines.filter(l=>/^https?:\/\//.test(l)).length >= lines.length*0.8) return 'urls';
  if (looksLikeJSON(s) || /^\{.*\}$/m.test(head)) return 'json';
  const first=head.split('\n')[0]||'';
  if (first.includes(',') && /[a-z]/i.test(first)) return 'csv';
  if (lines.length && lines.filter(l=>/^([a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$/i.test(l)).length >= lines.length*0.7) return 'subfinder';
  return 'lines';
}

const TOOLS = {
  auto:        { label:'⚡ Auto-detect',color:'#16e0ff', parse:t=>(TOOLS[detectTool(t)]||TOOLS.lines).parse(t), detect:true },
  spiderfoot:  { label:'SpiderFoot',   color:'#16e0ff', parse:t=>parseSpiderfoot(t) },
  theharvester:{ label:'theHarvester', color:'#9d7bff', parse:t=>parseHarvester(t) },
  nmap:        { label:'Nmap',         color:'#27e8a7', parse:t=>parseNmap(t) },
  masscan:     { label:'Masscan',      color:'#ff6b35', parse:t=>parseMasscan(t) },
  amass:       { label:'Amass',        color:'#ff9f43', parse:t=>parseAmass(t) },
  subfinder:   { label:'Subfinder/…',  color:'#ffb347', parse:t=>parseSubdomains(t,'subfinder') },
  httpx:       { label:'httpx',        color:'#36d399', parse:t=>parseHttpx(t) },
  dnsx:        { label:'dnsx',         color:'#64ffda', parse:t=>parseDnsx(t) },
  nuclei:      { label:'Nuclei',       color:'#f471b5', parse:t=>parseNuclei(t) },
  shodan:      { label:'Shodan',       color:'#ff4d6d', parse:t=>parseShodan(t) },
  censys:      { label:'Censys',       color:'#a78bfa', parse:t=>parseJSONGeneric(t,'censys') },
  urls:        { label:'URLs (gau/…)', color:'#7fd1c7', parse:t=>parseUrls(t,'urls') },
  reconng:     { label:'Recon-ng',     color:'#ffe066', parse:t=>parseCSVGeneric(t,'reconng') },
  whois:       { label:'WHOIS',        color:'#4dd6ff', parse:t=>parseWhois(t) },
  dnsrecon:    { label:'DNSRecon',     color:'#64ffda', parse:t=>parseDns(t) },
  maltego:     { label:'Maltego CSV',  color:'#2dd4bf', parse:t=>parseCSVGeneric(t,'maltego') },
  secrets:     { label:'Secrets',      color:'#fb7185', parse:t=>parseSecrets(t) },
  csv:         { label:'Generic CSV',  color:'#9bb0bd', parse:t=>parseCSVGeneric(t,'csv') },
  json:        { label:'Generic JSON', color:'#b0a0ff', parse:t=>parseJSONGeneric(t,'json') },
  lines:       { label:'Raw lines',    color:'#7fd1c7', parse:t=>parseLines(t,'lines') },
  manual:      { label:'Manual',       color:'#9bb0bd' },
};
// stable color for a source name even if not a known tool
const EXTRA_COLORS = ['#16e0ff','#9d7bff','#27e8a7','#ff9f43','#ff4d6d','#ffe066','#4dd6ff','#64ffda','#ff7fd8','#a0e85b'];
function sourceColor(src){
  if (TOOLS[src]) return TOOLS[src].color;
  let h=0; for (let i=0;i<src.length;i++) h=(h*31+src.charCodeAt(i))>>>0;
  return EXTRA_COLORS[h % EXTRA_COLORS.length];
}

/* ----------------------------------------------- events → timeline pts */
function eventsToPoints(events, gran){
  const map = new Map();
  for (const e of events){
    const key = gran==='raw' ? uid('pt') : (e.t==null ? 'untimed' : String(bucketMs(e.t, gran)));
    if (!map.has(key)) map.set(key, { id:uid('pt'), t: e.t==null?null:bucketMs(e.t,gran), boxes:[] });
    map.get(key).boxes.push({ id:uid('bx'), type:e.type, module:e.module, data:e.data, source:e.source, t:e.t });
  }
  const pts = [...map.values()];
  pts.sort((a,b)=> (a.t==null?-1:b.t==null?1:a.t-b.t));
  return pts;
}

/* --------------------------------------------------- point layout (x) */
const PT_PAD = 130, PT_GAP = 212;   // > stack width (200px) so expanded stacks never overlap and grips don't cover neighbours' buttons
function layoutPoints(points){
  points.forEach((p,i)=>{ p.x = PT_PAD + i*PT_GAP; });
  const w = points.length ? PT_PAD + (points.length-1)*PT_GAP + PT_PAD : 360;
  return Math.max(360, w);
}

/* ==================================================================== */
/* Everything below is browser-only (DOM). Guarded so Node can require   */
/* this file just for the pure helpers above.                            */
/* ==================================================================== */
function init(){
  const $  = s => document.querySelector(s);
  const $$ = s => [...document.querySelectorAll(s)];
  const el = (tag, props, kids)=>{
    const n = document.createElement(tag);
    if (props) for (const k in props){
      if (k==='class') n.className = props[k];
      else if (k==='text') n.textContent = props[k];
      else if (k==='html') n.innerHTML = props[k];          // only for trusted static markup
      else if (k.startsWith('on')) n.addEventListener(k.slice(2), props[k]);
      else if (k==='data') for (const d in props.data) n.dataset[d]=props.data[d];
      else if (k==='style') n.setAttribute('style', props[k]);
      else if (props[k]!=null) n.setAttribute(k, props[k]);
    }
    (kids||[]).forEach(c=>c!=null && n.appendChild(typeof c==='string'?document.createTextNode(c):c));
    return n;
  };
  const SVGNS='http://www.w3.org/2000/svg';
  const svgEl=(tag,attrs)=>{ const n=document.createElementNS(SVGNS,tag); for(const k in (attrs||{})) n.setAttribute(k,attrs[k]); return n; };

  /* ---------------- DOM refs ---------------- */
  const grid = $('#grid'), gx = grid.getContext('2d');
  const viewport = $('#viewport'), world = $('#world');
  const objects = $('#objects'), overlay = $('#overlay'), drawLayer = $('#layer-draw');
  const SVG_OFF = 50000;

  /* ---------------- state ---------------- */
  const ST = {
    cam: { x: 0, y: 0, zoom: 1 },
    timelines: [], notes: [], links: [], strokes: [],
    hiddenSources: {},
  };
  let mode = 'select';
  let penColor = '#16e0ff';
  const selection = new Set();          // ids of selected boxes/notes/timelines
  let history = [], future = [];
  let suppressFocusSnap = false;        // skip the pre-edit snapshot for auto-focused new objects

  /* ---------------- persistence ---------------- */
  const LS_SAVES='holotable_saves', LS_AUTO='holotable_auto';
  function lsGet(k){ try{ return localStorage.getItem(k); }catch(e){ return null; } }
  function lsSet(k,v){ try{ localStorage.setItem(k,v); return true; }catch(e){ return false; } }
  let lsOK = (()=>{ try{ localStorage.setItem('__t','1'); localStorage.removeItem('__t'); return true; }catch(e){ return false; } })();

  function serialize(){ return { v:3, cam:ST.cam, timelines:ST.timelines, notes:ST.notes, links:ST.links, strokes:ST.strokes, hiddenSources:ST.hiddenSources }; }
  function load(data){
    if (!data) return;
    ST.timelines = data.timelines||[]; ST.notes = data.notes||[]; ST.links = data.links||[];
    ST.strokes = data.strokes||[]; ST.hiddenSources = data.hiddenSources||{};
    if (data.cam) ST.cam = data.cam;
    // backfill ids / fields
    ST.timelines.forEach(tl=>{ tl.id=tl.id||uid('tl'); tl.color=tl.color||'#16e0ff';
      (tl.points||[]).forEach(p=>{ p.id=p.id||uid('pt'); (p.boxes||[]).forEach(b=>{ b.id=b.id||uid('bx'); }); }); });
  }
  const clone = o => JSON.parse(JSON.stringify(o));
  function snapshot(){ history.push(JSON.stringify(serialize())); if (history.length>80) history.shift(); future.length=0; }
  function autosave(){ if (lsOK) lsSet(LS_AUTO, JSON.stringify(serialize())); }
  let autoTimer=null; function autosaveSoon(){ clearTimeout(autoTimer); autoTimer=setTimeout(autosave,400); }

  function commit(label){ snapshot(); renderObjects(); autosave(); }
  function undo(){ if(!history.length) return; future.push(JSON.stringify(serialize())); load(JSON.parse(history.pop())); renderObjects(); updateWorld(); autosave(); toast('undo'); }
  function redo(){ if(!future.length) return; history.push(JSON.stringify(serialize())); load(JSON.parse(future.pop())); renderObjects(); updateWorld(); autosave(); toast('redo'); }

  /* ---------------- camera / world ---------------- */
  function screenToWorld(sx,sy){ return { x:(sx-ST.cam.x)/ST.cam.zoom, y:(sy-ST.cam.y)/ST.cam.zoom }; }
  function worldToScreen(wx,wy){ return { x:wx*ST.cam.zoom+ST.cam.x, y:wy*ST.cam.zoom+ST.cam.y }; }
  function updateWorld(){
    world.style.transform = `translate(${ST.cam.x}px,${ST.cam.y}px) scale(${ST.cam.zoom})`;
    drawGrid(); drawLinks();
  }
  function drawGrid(){
    const w = grid.width = innerWidth, h = grid.height = innerHeight;
    gx.clearRect(0,0,w,h);
    const z = ST.cam.zoom;
    const base = 40*z;
    if (base < 6) return;
    const ox = ((ST.cam.x % base)+base)%base, oy = ((ST.cam.y % base)+base)%base;
    gx.lineWidth = 1;
    gx.strokeStyle = 'rgba(20,57,74,0.35)';
    gx.beginPath();
    for (let x=ox; x<w; x+=base){ gx.moveTo(x,0); gx.lineTo(x,h); }
    for (let y=oy; y<h; y+=base){ gx.moveTo(0,y); gx.lineTo(w,y); }
    gx.stroke();
    // major lines every 5
    const major = base*5;
    const mox = ((ST.cam.x % major)+major)%major, moy = ((ST.cam.y % major)+major)%major;
    gx.strokeStyle = 'rgba(22,224,255,0.10)';
    gx.beginPath();
    for (let x=mox; x<w; x+=major){ gx.moveTo(x,0); gx.lineTo(x,h); }
    for (let y=moy; y<h; y+=major){ gx.moveTo(0,y); gx.lineTo(w,y); }
    gx.stroke();
    // origin crosshair
    const o = worldToScreen(0,0);
    if (o.x>-50&&o.x<w+50&&o.y>-50&&o.y<h+50){
      gx.strokeStyle='rgba(22,224,255,0.25)'; gx.beginPath();
      gx.moveTo(o.x-9,o.y); gx.lineTo(o.x+9,o.y); gx.moveTo(o.x,o.y-9); gx.lineTo(o.x,o.y+9); gx.stroke();
    }
  }

  /* ================================================================ */
  /*  RENDER                                                          */
  /* ================================================================ */
  const boxIndex = new Map();   // boxId -> {box, point, tl, anchorEl}

  function renderObjects(){
    objects.textContent=''; boxIndex.clear();
    ST.timelines.forEach(renderTimeline);
    ST.notes.forEach(renderNote);
    renderLegend();
    drawLinks();
    applyFilter();
    autosaveSoon();
  }

  function renderTimeline(tl){
    const node = el('div',{class:'timeline'+(selection.has(tl.id)?' sel':'')+(tl.min?' tl-min':''),
      style:`left:${tl.x}px;top:${tl.y}px`, data:{id:tl.id, kind:'tl'}});

    const head = el('div',{class:'tl-header'},[
      el('span',{class:'tl-grip', title:'drag timeline', data:{grip:'tl'}, text:'⠿'}),
      el('span',{class:'tl-accent', style:`background:${tl.color};color:${tl.color}`}),
      el('input',{class:'tl-title', value:tl.title||'', placeholder:'timeline name', data:{edit:'tl-title', id:tl.id}}),
      el('span',{class:'tl-meta', text:tlMeta(tl)}),
      el('div',{class:'tl-btns'},[
        el('button',{title:'expand all on this timeline', data:{act:'tl-expand', id:tl.id}, text:'⤢'}),
        el('button',{title:'collapse all', data:{act:'tl-collapse', id:tl.id}, text:'⤡'}),
        el('button',{title:'add point', data:{act:'tl-addpoint', id:tl.id}, text:'＋'}),
        el('button',{title:'minimise', data:{act:'tl-min', id:tl.id}, text: tl.min?'▾':'▸'}),
        el('button',{title:'menu', data:{act:'tl-menu', id:tl.id}, text:'⋯'}),
      ])
    ]);
    node.appendChild(head);

    const railWrap = el('div',{class:'tl-rail-wrap'});
    const rail = el('div',{class:'tl-rail'});
    const width = layoutPoints(tl.points||[]);
    node.style.width = Math.max(360, width)+'px';
    rail.style.width = width+'px';
    rail.appendChild(el('div',{class:'rail-line'}));

    let maxOpen = 0;
    (tl.points||[]).forEach(p=>{
      const isOpen = !!p.expanded;
      const visBoxes = (p.boxes||[]).filter(b=>!ST.hiddenSources[b.source]);
      if (isOpen) maxOpen = Math.max(maxOpen, visBoxes.length);
      const point = el('div',{class:'point'+(isOpen?' expanded':''), style:`left:${p.x}px`, data:{pid:p.id, tid:tl.id}});
      point.appendChild(el('div',{class:'dropzone'}));
      point.appendChild(el('div',{class:'dot', title:'click to expand · drop events here', data:{act:'pt-toggle', pid:p.id, tid:tl.id}}));
      if (visBoxes.length>1 || !isOpen) point.appendChild(el('div',{class:'count', text:String(visBoxes.length)}));
      point.appendChild(el('div',{class:'ptime'},[
        el('input',{value: p.t==null?'':toLocalInput(p.t), type:'datetime-local', title: p.t==null?'untimed':fmtTime(p.t), data:{edit:'pt-time', pid:p.id, tid:tl.id}})
      ]));

      const stack = el('div',{class:'stack'+(isOpen?' open':''), style:`color:${tl.color}`});
      visBoxes.forEach(b=> stack.appendChild(renderBox(b, p, tl)));
      point.appendChild(stack);

      if (isOpen) point.appendChild(el('div',{class:'add-box', style:`top:${visBoxes.length*46+30}px`, title:'add event', data:{act:'add-box', pid:p.id, tid:tl.id}, text:'＋ event'}));
      rail.appendChild(point);
    });

    // add-point button at the end of the rail
    rail.appendChild(el('button',{class:'tl-addpoint', style:`left:${width-46}px`, title:'add point', data:{act:'tl-addpoint', id:tl.id}, text:'＋'}));

    if (maxOpen>0) rail.style.height = (96 + maxOpen*46 + 26)+'px';
    railWrap.appendChild(rail);
    node.appendChild(railWrap);
    objects.appendChild(node);
  }

  function tlMeta(tl){
    const np = (tl.points||[]).length;
    const nb = (tl.points||[]).reduce((s,p)=>s+(p.boxes||[]).length,0);
    return `${np}pt · ${nb}ev`;
  }

  function renderBox(b, p, tl){
    const col = sourceColor(b.source||'manual');
    const node = el('div',{class:'box'+(selection.has(b.id)?' sel':''), style:`border-left-color:${col}`, data:{bid:b.id, pid:p.id, tid:tl.id}});
    node.appendChild(el('span',{class:'b-grip', title:'drag to another point', data:{grip:'box', bid:b.id}, text:'⠿'}));
    node.appendChild(el('button',{class:'b-link', title:'link from this event', data:{act:'box-link', bid:b.id}, text:'⌥'}));
    node.appendChild(el('button',{class:'b-del', title:'delete event', data:{act:'box-del', bid:b.id}, text:'✕'}));
    node.appendChild(el('div',{class:'b-type', contenteditable:'true', spellcheck:'false', data:{edit:'b-type', bid:b.id}, text:b.type||''}));
    node.appendChild(el('div',{class:'b-data', contenteditable:'true', spellcheck:'false', data:{edit:'b-data', bid:b.id}, text:b.data||''}));
    node.appendChild(el('div',{class:'b-foot'},[
      el('div',{class:'b-module', contenteditable:'true', spellcheck:'false', data:{edit:'b-module', bid:b.id}, text:b.module||''}),
      el('span',{class:'b-src', style:`color:${col}`, title:'source tool — click to retag', data:{act:'box-src', bid:b.id}, text:b.source||'manual'})
    ]));
    boxIndex.set(b.id, { b, p, tl, el:node });
    return node;
  }

  function renderNote(n){
    const node = el('div',{class:'note'+(n.tone?(' tone-'+n.tone):'')+(selection.has(n.id)?' sel':''),
      style:`left:${n.x}px;top:${n.y}px`+(n.w?`;width:${n.w}px`:''), data:{id:n.id, kind:'note'}});
    node.appendChild(el('span',{class:'n-grip', data:{grip:'note', id:n.id}, text:'⠿ note'}));
    node.appendChild(el('button',{class:'n-del', data:{act:'note-del', id:n.id}, text:'✕'}));
    node.appendChild(el('div',{class:'n-text', contenteditable:'true', spellcheck:'false', data:{edit:'note', id:n.id}, text:n.text||''}));
    objects.appendChild(node);
  }

  /* ---------------- links + strokes (SVG world layer) ---------------- */
  function boxAnchorWorld(bid){
    const rec = boxIndex.get(bid); if (!rec) return null;
    // if the box is in a collapsed stack, anchor to the point dot instead
    let target = rec.el;
    const stack = rec.el.closest('.stack');
    if (stack && !stack.classList.contains('open')){
      const dot = rec.el.closest('.point')?.querySelector('.dot'); if (dot) target = dot;
    }
    const r = target.getBoundingClientRect();
    if (!r.width && !r.height) return null;
    return screenToWorld(r.left + r.width/2, r.top + r.height/2);
  }
  function drawLinks(){
    drawLayer.textContent='';
    // freehand strokes
    for (const s of ST.strokes){
      if (!s.points || s.points.length<2) continue;
      const d = 'M'+s.points.map(pt=>`${pt[0]+SVG_OFF},${pt[1]+SVG_OFF}`).join(' L');
      drawLayer.appendChild(svgEl('path',{class:'stroke', d, stroke:s.color||'#16e0ff', 'stroke-width':(s.w||2)}));
    }
    // links between events
    for (const lk of ST.links){
      const a = boxAnchorWorld(lk.from), b = boxAnchorWorld(lk.to);
      if (!a||!b) continue;
      const mx=(a.x+b.x)/2;
      const d = `M${a.x+SVG_OFF},${a.y+SVG_OFF} C${mx+SVG_OFF},${a.y+SVG_OFF} ${mx+SVG_OFF},${b.y+SVG_OFF} ${b.x+SVG_OFF},${b.y+SVG_OFF}`;
      const path = svgEl('path',{class:'link'+(selection.has(lk.id)?' sel':''), d, stroke:lk.color||'#16e0ff'});
      const hit = svgEl('path',{class:'hit', d, stroke:'transparent','stroke-width':14,fill:'none','pointer-events':'stroke'});
      hit.style.cursor='pointer';
      hit.addEventListener('click',e=>{ e.stopPropagation(); selectOnly(lk.id); drawLinks(); });
      hit.addEventListener('dblclick',e=>{ e.stopPropagation(); snapshot(); ST.links=ST.links.filter(x=>x!==lk); drawLinks(); autosave(); toast('link removed'); });
      drawLayer.appendChild(path); drawLayer.appendChild(hit);
      drawLayer.appendChild(svgEl('circle',{class:'link-end', cx:a.x+SVG_OFF, cy:a.y+SVG_OFF, r:3}));
      drawLayer.appendChild(svgEl('circle',{class:'link-end', cx:b.x+SVG_OFF, cy:b.y+SVG_OFF, r:3}));
    }
  }

  /* ---------------- legend / sources ---------------- */
  function sourceCounts(){
    const m = new Map();
    for (const tl of ST.timelines) for (const p of tl.points||[]) for (const b of p.boxes||[]){
      const s=b.source||'manual'; m.set(s,(m.get(s)||0)+1);
    }
    return m;
  }
  function renderLegend(){
    const legend = $('#legend'); legend.textContent='';
    const counts = sourceCounts();
    if (!counts.size){ legend.appendChild(el('div',{class:'lg-count', style:'padding:4px', text:'no events yet — Ingest ▸'})); return; }
    [...counts.entries()].sort((a,b)=>b[1]-a[1]).forEach(([src,n])=>{
      const off = !!ST.hiddenSources[src];
      const row = el('div',{class:'lg'+(off?' off':''), title:'click to toggle visibility', data:{act:'src-toggle', src}});
      row.appendChild(el('span',{class:'sw', style:`background:${sourceColor(src)};color:${sourceColor(src)}`}));
      row.appendChild(el('span',{class:'lg-name', text:src}));
      row.appendChild(el('span',{class:'lg-count', text:String(n)}));
      legend.appendChild(row);
    });
  }

  /* ---------------- search / filter ---------------- */
  let filterText='';
  function applyFilter(){
    const q = filterText.trim().toLowerCase();
    let shown=0, total=0;
    $$('.box').forEach(node=>{
      const bid = node.dataset.bid; const rec = boxIndex.get(bid); if(!rec) return; total++;
      const b = rec.b;
      const hidSrc = ST.hiddenSources[b.source];
      const hay = (b.type+' '+b.data+' '+b.module+' '+b.source).toLowerCase();
      const match = (!q || hay.includes(q)) && !hidSrc;
      node.classList.toggle('dim', !match);
      if (match) shown++;
    });
    const sc = $('#search-count'); sc.textContent = q ? `${shown}/${total}` : '';
  }

  /* ================================================================ */
  /*  MUTATIONS                                                       */
  /* ================================================================ */
  function findTL(id){ return ST.timelines.find(t=>t.id===id); }
  function findPoint(tid,pid){ const tl=findTL(tid); return tl && (tl.points||[]).find(p=>p.id===pid); }
  function findBox(bid){ return boxIndex.get(bid)?.b || null; }

  function estTLHeight(tl){
    const maxOpen = (tl.points||[]).reduce((m,p)=> p.expanded ? Math.max(m,(p.boxes||[]).length) : m, 0);
    return 140 + (maxOpen?maxOpen*46+26:0);
  }
  function nextSpot(){
    // stack new timelines into clear space below the lowest existing one
    if (!ST.timelines.length) return screenToWorld(innerWidth/2 - 200, 120);
    let maxB=-1e9, minL=1e9;
    ST.timelines.forEach(t=>{ maxB=Math.max(maxB, t.y+estTLHeight(t)); minL=Math.min(minL, t.x); });
    return { x:minL, y:maxB+44 };
  }
  function addTimeline(opts){
    opts=opts||{};
    const spot = (opts.x!=null && opts.y!=null) ? {x:opts.x,y:opts.y} : nextSpot();
    const tl = { id:uid('tl'), title:opts.title||('TIMELINE '+(ST.timelines.length+1)),
      x: opts.x!=null?opts.x:spot.x, y: opts.y!=null?opts.y:spot.y,
      color: opts.color||['#16e0ff','#9d7bff','#27e8a7','#ff9f43','#ff4d6d'][ST.timelines.length%5],
      points: opts.points||[] };
    ST.timelines.push(tl); return tl;
  }
  function addPoint(tl, t){
    const p = { id:uid('pt'), t: t!==undefined?t:Date.now(), expanded:true, boxes:[] };
    tl.points = tl.points||[]; tl.points.push(p);
    tl.points.sort((a,b)=> (a.t==null?-1:b.t==null?1:a.t-b.t));
    return p;
  }
  function addBox(p, data){
    const b = Object.assign({ id:uid('bx'), type:'data', module:'', data:'', source:'manual' }, data||{});
    p.boxes = p.boxes||[]; p.boxes.push(b); return b;
  }

  // Ingest parsed events into a target timeline (or new one).
  function ingest(events, opts){
    opts=opts||{};
    if (!events.length){ toast('nothing parsed — check the tool/format'); return; }
    snapshot();
    let tl = opts.timelineId ? findTL(opts.timelineId) : null;
    if (!tl){ tl = addTimeline({ title: opts.title || (TOOLS[opts.source]?.label || 'IMPORT'), color: opts.source?sourceColor(opts.source):undefined }); }
    const pts = eventsToPoints(events, opts.gran||'minute');
    // merge into existing points that share a bucket time
    const byT = new Map(); (tl.points||[]).forEach(p=>{ if(p.t!=null) byT.set(p.t, p); });
    for (const np of pts){
      if (np.t!=null && byT.has(np.t)){ const ex=byT.get(np.t); ex.boxes.push(...np.boxes); }
      else { tl.points.push(np); if (np.t!=null) byT.set(np.t, np); }
    }
    tl.points.sort((a,b)=> (a.t==null?-1:b.t==null?1:a.t-b.t));
    renderObjects(); autosave();
    flashConsole(events, opts.source);
    toast(`ingested ${events.length} event${events.length>1?'s':''} → ${tl.title}`);
    return tl;
  }

  /* ================================================================ */
  /*  CONSOLE                                                         */
  /* ================================================================ */
  let conCount=0;
  function conLine(msg, cls, src){
    const feed = $('#console-feed');
    const line = el('div',{class:'cl'+(cls?' '+cls:'')},[
      el('span',{class:'ts', text:new Date().toLocaleTimeString()}),
      src? el('span',{class:'src', style:`color:${sourceColor(src)}`, text:src}) : null,
      el('span',{class:'msg', text:msg})
    ].filter(Boolean));
    feed.appendChild(line);
    while (feed.childElementCount>400) feed.firstChild.remove();
    feed.scrollTop = feed.scrollHeight;
    conCount++; $('#con-stats').textContent = conCount+' lines';
  }
  function flashConsole(events, src){
    conLine(`+${events.length} events`, 'sys', src);
    events.slice(0,8).forEach(e=> conLine(`${e.type}  ${e.data}`.slice(0,90), '', e.source||src));
    if (events.length>8) conLine(`…and ${events.length-8} more`, 'sys', src);
  }

  /* ================================================================ */
  /*  POINTER INTERACTION (the anti-clunk core)                       */
  /* ================================================================ */
  const drag = { kind:null };
  let spaceDown=false;

  function setMode(m){
    mode=m; document.body.className = 'mode-'+m;
    $$('#modes .mode').forEach(b=>b.classList.toggle('active', b.dataset.mode===m));
    viewport.classList.toggle('viewport-pan', m==='pan');
  }

  function ancestor(node, sel){ while(node && node!==document){ if(node.matches&&node.matches(sel)) return node; node=node.parentNode; } return null; }

  viewport.addEventListener('pointerdown', onDown);

  function onDown(e){
    if (e.button===2) return;                      // right-click handled by contextmenu
    const t = e.target;
    closeCtx();

    // Mode gestures take precedence over the edit guard, so a click on a box's
    // text still links/draws instead of dropping a caret. (Editable fields have
    // pointer-events:none outside select mode, so they never steal focus here.)
    if (mode==='pen'){ e.preventDefault(); startStroke(e); return; }
    if (mode==='note'){ if (!t.closest('.note') && !t.closest('.box')){ e.preventDefault(); dropNote(e); } return; }
    if (mode==='link'){ const bx=t.closest('.box'); if (bx){ e.preventDefault(); handleLinkClick(bx.dataset.bid); } return; }

    // SELECT mode: editing fields → let the browser place the caret
    if (t.closest('[contenteditable="true"]') || t.tagName==='INPUT' || t.tagName==='TEXTAREA' || t.tagName==='SELECT'){
      return;
    }

    // a grip → free drag the event / timeline / note
    const grip = t.closest('[data-grip]');
    if (grip){
      const g = grip.dataset.grip;
      if (g==='box'){ startBoxDrag(e, grip.dataset.bid); return; }
      if (g==='tl'){ startObjectDrag(e, grip.closest('.timeline').dataset.id, 'tl'); return; }
      if (g==='note'){ startObjectDrag(e, grip.closest('.note').dataset.id, 'note'); return; }
    }

    // clicking a box → select it (boxes are moved via their own ⠿ grip)
    const bx = t.closest('.box');
    if (bx){
      if (t.closest('[data-act]')) return;   // a box button (delete / link / source) — let its own click handler run
      selectOnly(bx.dataset.bid, e.shiftKey); renderObjects(); return;
    }

    const onTL = t.closest('.timeline'), onNote = t.closest('.note');

    // SELECT mode: grab a timeline (or note) anywhere on its body — minus its
    // interactive bits (boxes, dots, buttons) — to move the whole thing freely.
    if (mode==='select' && !spaceDown){
      if (onNote && !t.closest('button')){ startObjectDrag(e, onNote.dataset.id, 'note'); return; }
      if (onTL && !t.closest('button') && !t.closest('.dot') && !t.closest('.add-box')){ startObjectDrag(e, onTL.dataset.id, 'tl'); return; }
    }

    // empty canvas: pan (Shift = marquee-select); pan mode / held Space pan anywhere
    const onEmpty = !onTL && !onNote;
    if (mode==='pan' || spaceDown || (onEmpty && mode==='select' && !e.shiftKey)){ startPan(e); return; }
    if (onEmpty && mode==='select' && e.shiftKey){ startMarquee(e); return; }
  }

  /* ---- pan ---- */
  function startPan(e){
    drag.kind='pan'; drag.sx=e.clientX; drag.sy=e.clientY; drag.cx=ST.cam.x; drag.cy=ST.cam.y;
    viewport.classList.add('panning'); capture(e);
  }
  /* ---- move a timeline / note ---- */
  function startObjectDrag(e, id, kind){
    const obj = kind==='tl'?findTL(id):ST.notes.find(n=>n.id===id);
    if (!obj) return;
    drag.kind='object'; drag.obj=obj; drag.sx=e.clientX; drag.sy=e.clientY; drag.ox=obj.x; drag.oy=obj.y; drag.snapped=false;
    document.body.classList.add('dragging-obj');
    selectOnly(id); capture(e);
  }
  /* ---- marquee select ---- */
  function startMarquee(e){
    drag.kind='marquee'; drag.sx=e.clientX; drag.sy=e.clientY; drag.shift=e.shiftKey;
    drag.node = el('div',{class:'marquee'}); overlay.appendChild(drag.node);
    capture(e);
  }
  /* ---- drag a box freely between points ---- */
  function startBoxDrag(e, bid){
    const rec = boxIndex.get(bid); if(!rec) return;
    drag.kind='box'; drag.bid=bid; drag.src=rec;
    document.body.classList.add('dragging-box');
    const r = rec.el.getBoundingClientRect();
    const clone = rec.el.cloneNode(true);
    clone.classList.add('drag-clone'); clone.style.width=r.width+'px';
    clone.style.left=r.left+'px'; clone.style.top=r.top+'px';
    document.body.appendChild(clone);
    drag.clone=clone; drag.dx=e.clientX-r.left; drag.dy=e.clientY-r.top;
    rec.el.style.opacity='0.25';
    capture(e);
  }
  /* ---- freehand stroke ---- */
  function startStroke(e){
    snapshot();
    const w0 = screenToWorld(e.clientX,e.clientY);
    drag.kind='stroke'; drag.stroke={ id:uid('st'), color:penColor, w:2, points:[[w0.x,w0.y]] };
    ST.strokes.push(drag.stroke); capture(e);
  }

  function capture(e){ viewport.setPointerCapture?.(e.pointerId); drag.pid=e.pointerId; }

  viewport.addEventListener('pointermove', onMove);
  window.addEventListener('pointermove', onMove);
  function onMove(e){
    if (!drag.kind) return;
    if (drag.kind==='pan'){
      ST.cam.x = drag.cx + (e.clientX-drag.sx);
      ST.cam.y = drag.cy + (e.clientY-drag.sy);
      updateWorld(); return;
    }
    if (drag.kind==='object'){
      if (!drag.snapped){ snapshot(); drag.snapped=true; }   // checkpoint only once a real move begins
      const z=ST.cam.zoom;
      drag.obj.x = drag.ox + (e.clientX-drag.sx)/z;
      drag.obj.y = drag.oy + (e.clientY-drag.sy)/z;
      const node = objects.querySelector(`[data-id="${drag.obj.id}"]`);
      if (node){ node.style.left=drag.obj.x+'px'; node.style.top=drag.obj.y+'px'; }
      drawLinks(); return;
    }
    if (drag.kind==='box'){
      drag.clone.style.left=(e.clientX-drag.dx)+'px';
      drag.clone.style.top=(e.clientY-drag.dy)+'px';
      // highlight nearest dropzone
      drag.clone.style.display='none';
      const under = document.elementFromPoint(e.clientX,e.clientY);
      drag.clone.style.display='';
      const point = under && under.closest('.point');
      $$('.point.drop-hot').forEach(p=>{ if(p!==point) p.classList.remove('drop-hot'); });
      if (point) point.classList.add('drop-hot');
      drag.overPoint = point; return;
    }
    if (drag.kind==='stroke'){
      const w=screenToWorld(e.clientX,e.clientY);
      drag.stroke.points.push([w.x,w.y]); drawLinks(); return;
    }
    if (drag.kind==='marquee'){
      const x=Math.min(e.clientX,drag.sx), y=Math.min(e.clientY,drag.sy);
      const w=Math.abs(e.clientX-drag.sx), h=Math.abs(e.clientY-drag.sy);
      Object.assign(drag.node.style,{left:x+'px',top:y+'px',width:w+'px',height:h+'px'});
      return;
    }
  }

  window.addEventListener('pointerup', onUp);
  // if a drag is interrupted (lost capture, OS gesture, touch cancel), reset
  // cleanly instead of leaving the grab cursor / drag state stuck
  window.addEventListener('pointercancel', cancelDrag);
  window.addEventListener('lostpointercapture', ()=>{ if(drag.kind) cancelDrag(); });
  function cancelDrag(){
    if (!drag.kind) return;
    document.body.classList.remove('dragging-obj','dragging-box');
    viewport.classList.remove('panning');
    if (drag.clone) drag.clone.remove();
    if (drag.src) drag.src.el.style.opacity='';
    $$('.point.drop-hot').forEach(p=>p.classList.remove('drop-hot'));
    if (drag.node) drag.node.remove();
    drag.kind=null; drag.obj=null; drag.src=null; drag.clone=null; drag.overPoint=null;
    renderObjects();
  }
  function onUp(e){
    const k=drag.kind;
    viewport.classList.remove('panning');
    if (k==='object'){ document.body.classList.remove('dragging-obj'); renderObjects(); autosave(); }
    if (k==='box'){
      document.body.classList.remove('dragging-box');
      if (drag.clone) drag.clone.remove();
      if (drag.src) drag.src.el.style.opacity='';
      const point = drag.overPoint;
      $$('.point.drop-hot').forEach(p=>p.classList.remove('drop-hot'));
      if (point){
        const tid=point.dataset.tid, pid=point.dataset.pid;
        moveBox(drag.bid, tid, pid);
      } else { renderObjects(); }
    }
    if (k==='stroke'){ if(drag.stroke.points.length<2) ST.strokes.pop(); autosave(); }
    if (k==='marquee'){ finishMarquee(); drag.node?.remove(); }
    drag.kind=null; drag.obj=null; drag.src=null; drag.clone=null; drag.overPoint=null;
  }

  function moveBox(bid, tid, pid){
    const rec = boxIndex.get(bid); if(!rec){ renderObjects(); return; }
    if (rec.p.id===pid){ renderObjects(); return; }              // dropped on same point — no change, no checkpoint
    snapshot();                                                   // real cross-point move → checkpoint for undo
    rec.p.boxes = rec.p.boxes.filter(b=>b.id!==bid);
    const tgt = findPoint(tid,pid);
    if (tgt){ tgt.boxes.push(rec.b); }
    // drop empty points
    rec.tl.points = rec.tl.points.filter(p=> p.boxes.length || p===tgt);
    renderObjects(); autosave(); toast('event moved');
  }

  function finishMarquee(){
    const r = drag.node.getBoundingClientRect();
    if (!drag.shift) selection.clear();
    $$('.box').forEach(node=>{
      const br=node.getBoundingClientRect();
      if (br.left<r.right&&br.right>r.left&&br.top<r.bottom&&br.bottom>r.top) selection.add(node.dataset.bid);
    });
    renderObjects();
  }

  /* ---- selection ---- */
  function selectOnly(id, additive){ if(!additive) selection.clear(); selection.add(id); }

  /* ---- notes ---- */
  function dropNote(e){
    snapshot();
    const w=screenToWorld(e.clientX,e.clientY);
    const n={ id:uid('nt'), x:w.x, y:w.y, text:'', tone: e.altKey?'cyan':'' };
    ST.notes.push(n); renderObjects(); autosave();
    suppressFocusSnap=true;
    setTimeout(()=>{ const el2=objects.querySelector(`[data-id="${n.id}"] .n-text`); el2&&el2.focus(); },0);
  }

  /* ---- links ---- */
  let linkFrom=null;
  function handleLinkClick(bid){
    if (!linkFrom){ linkFrom=bid; toast('link: now click the target event'); boxIndex.get(bid)?.el.classList.add('hit'); return; }
    if (linkFrom===bid){ linkFrom=null; renderObjects(); return; }
    snapshot();
    ST.links.push({ id:uid('lk'), from:linkFrom, to:bid, color:'#16e0ff' });
    linkFrom=null; renderObjects(); autosave(); toast('linked');
  }
  function handleBoxLinkBtn(bid){ setMode('link'); handleLinkClick(bid); }

  /* ================================================================ */
  /*  CLICK / EDIT delegation                                         */
  /* ================================================================ */
  objects.addEventListener('click', e=>{
    const act = e.target.closest('[data-act]'); if(!act) return;
    const a=act.dataset.act;
    if (a==='pt-toggle'){ const p=findPoint(act.dataset.tid,act.dataset.pid); if(p){ p.expanded=!p.expanded; renderObjects(); } }
    else if (a==='tl-expand'){ const tl=findTL(act.dataset.id); tl.points.forEach(p=>p.expanded=true); renderObjects(); }
    else if (a==='tl-collapse'){ const tl=findTL(act.dataset.id); tl.points.forEach(p=>p.expanded=false); renderObjects(); }
    else if (a==='tl-min'){ const tl=findTL(act.dataset.id); tl.min=!tl.min; renderObjects(); }
    else if (a==='tl-addpoint'){ snapshot(); const tl=findTL(act.dataset.id); const p=addPoint(tl); addBox(p,{}); renderObjects(); autosave(); }
    else if (a==='add-box'){ snapshot(); const p=findPoint(act.dataset.tid,act.dataset.pid); addBox(p,{}); renderObjects(); autosave(); }
    else if (a==='box-del'){ snapshot(); deleteBox(act.dataset.bid); }
    else if (a==='box-link'){ handleBoxLinkBtn(act.dataset.bid); }
    else if (a==='box-src'){ retagSource(act.dataset.bid, act); }
    else if (a==='note-del'){ snapshot(); ST.notes=ST.notes.filter(n=>n.id!==act.dataset.id); renderObjects(); autosave(); }
    else if (a==='tl-menu'){ openTLMenu(act.dataset.id, act); }
  });

  function deleteBox(bid){
    const rec=boxIndex.get(bid); if(!rec) return;
    rec.p.boxes=rec.p.boxes.filter(b=>b.id!==bid);
    rec.tl.points=rec.tl.points.filter(p=>p.boxes.length);
    ST.links=ST.links.filter(l=>l.from!==bid&&l.to!==bid);
    renderObjects(); autosave();
  }
  function retagSource(bid, anchor){
    const b=findBox(bid); if(!b) return;
    const items = Object.keys(TOOLS).map(k=>({label:TOOLS[k].label, fn:()=>{ snapshot(); b.source=k; renderObjects(); autosave(); }}));
    showCtx(anchor.getBoundingClientRect().left, anchor.getBoundingClientRect().bottom+4, items);
  }

  // live editing of contenteditable / inputs
  objects.addEventListener('input', e=>{
    const ed=e.target.closest('[data-edit]'); if(!ed) return;
    const f=ed.dataset.edit;
    if (f==='b-type'||f==='b-data'||f==='b-module'){ const b=findBox(ed.dataset.bid); if(b){ b[f==='b-type'?'type':f==='b-data'?'data':'module']=ed.textContent; autosaveSoon(); } }
    else if (f==='tl-title'){ const tl=findTL(ed.dataset.id); if(tl){ tl.title=ed.value; autosaveSoon(); } }
    else if (f==='note'){ const n=ST.notes.find(x=>x.id===ed.dataset.id); if(n){ n.text=ed.textContent; autosaveSoon(); } }
    else if (f==='pt-time'){ /* applied on change to avoid re-sorting mid-type */ }
  });
  objects.addEventListener('change', e=>{
    const ed=e.target.closest('[data-edit="pt-time"]'); if(!ed) return;
    snapshot();
    const p=findPoint(ed.dataset.tid,ed.dataset.pid); if(p){ p.t=fromLocalInput(ed.value); }
    const tl=findTL(ed.dataset.tid); tl.points.sort((a,b)=>(a.t==null?-1:b.t==null?1:a.t-b.t));
    renderObjects(); autosave();
  });
  // snapshot once when a text edit session begins (for undo granularity), but
  // not when we auto-focus a freshly-created object (its creation already snapshotted)
  objects.addEventListener('focusin', e=>{
    if (suppressFocusSnap){ suppressFocusSnap=false; return; }
    if (e.target.matches('[data-edit]') && e.target.dataset.edit!=='pt-time'){ snapshot(); }
  });

  /* ================================================================ */
  /*  CONTEXT MENU                                                    */
  /* ================================================================ */
  const ctx=$('#ctx');
  function showCtx(x,y,items){
    ctx.textContent='';
    items.forEach(it=>{
      if (it.sep){ ctx.appendChild(el('div',{class:'sep-i'})); return; }
      const ci=el('div',{class:'ci'+(it.danger?' danger':'')},[ el('span',{text:it.label}), it.key?el('span',{class:'k',text:it.key}):null ].filter(Boolean));
      ci.addEventListener('click',()=>{ closeCtx(); it.fn&&it.fn(); });
      ctx.appendChild(ci);
    });
    ctx.hidden=false;
    const w=ctx.offsetWidth,h=ctx.offsetHeight;
    ctx.style.left=Math.min(x,innerWidth-w-6)+'px'; ctx.style.top=Math.min(y,innerHeight-h-6)+'px';
  }
  function closeCtx(){ ctx.hidden=true; }
  window.addEventListener('contextmenu', e=>{
    const bx=e.target.closest('.box');
    const tl=e.target.closest('.timeline');
    const onEmpty = !tl && !e.target.closest('.note');
    if (bx){
      e.preventDefault(); const bid=bx.dataset.bid;
      showCtx(e.clientX,e.clientY,[
        {label:'Link from here', fn:()=>handleBoxLinkBtn(bid)},
        {label:'Duplicate', fn:()=>{ snapshot(); const r=boxIndex.get(bid); const nb=Object.assign({},r.b,{id:uid('bx')}); r.p.boxes.push(nb); renderObjects(); autosave(); }},
        {label:'Set source…', fn:()=>retagSource(bid, bx.querySelector('.b-src'))},
        {sep:true},
        {label:'Delete event', danger:true, fn:()=>{ snapshot(); deleteBox(bid); }},
      ]);
    } else if (tl){
      e.preventDefault(); openTLMenu(tl.dataset.id, {getBoundingClientRect:()=>({left:e.clientX,bottom:e.clientY})});
    } else if (onEmpty){
      e.preventDefault();
      const w=screenToWorld(e.clientX,e.clientY);
      showCtx(e.clientX,e.clientY,[
        {label:'New timeline here', fn:()=>{ snapshot(); addTimeline({x:w.x,y:w.y}); renderObjects(); autosave(); }},
        {label:'New note here', fn:()=>{ snapshot(); ST.notes.push({id:uid('nt'),x:w.x,y:w.y,text:''}); renderObjects(); autosave(); }},
        {label:'Ingest…', fn:openIngest},
        {sep:true},
        {label:'Fit to content', key:'F', fn:fitView},
        {label:'Reset zoom', fn:()=>{ ST.cam.zoom=1; updateWorld(); }},
      ]);
    }
  });
  function openTLMenu(id, anchor){
    const tl=findTL(id); const r=anchor.getBoundingClientRect();
    showCtx(r.left, r.bottom+4, [
      {label:'Expand all', key:'E', fn:()=>{ tl.points.forEach(p=>p.expanded=true); renderObjects(); }},
      {label:'Collapse all', fn:()=>{ tl.points.forEach(p=>p.expanded=false); renderObjects(); }},
      {label:'Add point', fn:()=>{ snapshot(); const p=addPoint(tl); addBox(p,{}); renderObjects(); autosave(); }},
      {label:'Recolor', fn:()=>{ snapshot(); const cs=['#16e0ff','#9d7bff','#27e8a7','#ff9f43','#ff4d6d','#ffe066']; tl.color=cs[(cs.indexOf(tl.color)+1)%cs.length]; renderObjects(); autosave(); }},
      {label:'Duplicate timeline', fn:()=>{ snapshot(); const c=clone(tl); c.id=uid('tl'); c.x+=40; c.y+=40; c.points.forEach(p=>{p.id=uid('pt');p.boxes.forEach(b=>b.id=uid('bx'));}); ST.timelines.push(c); renderObjects(); autosave(); }},
      {sep:true},
      {label:'Delete timeline', danger:true, fn:()=>{ snapshot(); ST.timelines=ST.timelines.filter(t=>t!==tl); renderObjects(); autosave(); }},
    ]);
  }
  window.addEventListener('pointerdown', e=>{ if(!e.target.closest('.ctx')) closeCtx(); }, true);

  /* ================================================================ */
  /*  ZOOM                                                            */
  /* ================================================================ */
  viewport.addEventListener('wheel', e=>{
    e.preventDefault();
    const rect=viewport.getBoundingClientRect();
    const sx=e.clientX-rect.left, sy=e.clientY-rect.top;
    const w=screenToWorld(sx,sy);
    const factor=Math.exp(-e.deltaY*0.0015);
    ST.cam.zoom=Math.min(3.2,Math.max(0.12,ST.cam.zoom*factor));
    ST.cam.x=sx-w.x*ST.cam.zoom; ST.cam.y=sy-w.y*ST.cam.zoom;
    updateWorld();
  },{passive:false});

  function fitView(){
    const nodes=$$('.timeline,.note');
    if (!nodes.length){ ST.cam={x:innerWidth/2,y:innerHeight/2,zoom:1}; updateWorld(); return; }
    let minX=1e9,minY=1e9,maxX=-1e9,maxY=-1e9;
    // use world coords from model + measured sizes
    nodes.forEach(n=>{
      const id=n.dataset.id; const obj=findTL(id)||ST.notes.find(x=>x.id===id); if(!obj) return;
      const w=n.offsetWidth, h=n.offsetHeight;
      minX=Math.min(minX,obj.x); minY=Math.min(minY,obj.y);
      maxX=Math.max(maxX,obj.x+w); maxY=Math.max(maxY,obj.y+h);
    });
    const pad=80; const bw=maxX-minX+pad*2, bh=maxY-minY+pad*2;
    const z=Math.min(2, Math.max(0.15, Math.min((innerWidth-40)/bw,(innerHeight-100)/bh)));
    ST.cam.zoom=z;
    ST.cam.x=(innerWidth-bw*z)/2 - (minX-pad)*z;
    ST.cam.y=(innerHeight-bh*z)/2 - (minY-pad)*z + 20;
    updateWorld();
  }

  /* ================================================================ */
  /*  INGEST MODAL                                                    */
  /* ================================================================ */
  const ingestModal=$('#ingest');
  function fillToolSelect(sel){
    sel.textContent='';
    Object.keys(TOOLS).filter(k=>k!=='manual').forEach(k=> sel.appendChild(el('option',{value:k, text:TOOLS[k].label})));
  }
  function fillTargets(sel){
    sel.textContent=''; sel.appendChild(el('option',{value:'', text:'＋ new timeline'}));
    ST.timelines.forEach(tl=> sel.appendChild(el('option',{value:tl.id, text:tl.title})));
  }
  function openIngest(preset){
    fillToolSelect($('#ingest-tool')); fillTargets($('#ingest-target'));
    $('#ingest-tool').value = preset || 'auto';
    ingestModal.hidden=false; setTimeout(()=>$('#ingest-text').focus(),0); updatePreview();
  }
  function closeIngest(){ ingestModal.hidden=true; }
  // resolve 'auto' to a concrete tool so we can tag the source and report it
  function currentParse(){
    const sel=$('#ingest-tool').value; const txt=$('#ingest-text').value;
    const resolved = sel==='auto' ? detectTool(txt) : sel;
    if (!txt.trim()) return {tool:sel, resolved, events:[]};
    let events=[]; try{ events=(TOOLS[resolved]||TOOLS.lines).parse(txt); }catch(e){ events=[]; }
    return {tool:sel, resolved, events};
  }
  function updatePreview(){
    const {tool,resolved,events}=currentParse();
    const withT=events.filter(e=>e.t!=null).length;
    const det = tool==='auto' ? ` · detected <b>${TOOLS[resolved]?.label||resolved}</b>` : '';
    $('#ingest-preview').innerHTML = events.length
      ? `parsed <b>${events.length}</b> events · <b>${withT}</b> timed · ${new Set(events.map(e=>e.type)).size} types${det}`
      : (($('#ingest-text').value.trim())?`<b>0</b> parsed${det} — try another tool`:'—');
  }
  $('#ingest-text').addEventListener('input', updatePreview);
  $('#ingest-tool').addEventListener('change', updatePreview);
  $('#ingest-go').addEventListener('click', ()=>{
    const {resolved,events}=currentParse();
    ingest(events, { source:resolved, gran:$('#ingest-group').value, timelineId:$('#ingest-target').value||null });
    closeIngest(); $('#ingest-text').value='';
  });
  $('#ingest-close').addEventListener('click', closeIngest);
  ingestModal.addEventListener('click', e=>{ if(e.target===ingestModal) closeIngest(); });
  $('#ingest-file-btn').addEventListener('click', ()=>$('#ingest-file').click());
  $('#ingest-file').addEventListener('change', e=>{ const f=e.target.files[0]; if(f) readFileInto(f); });

  function readFileInto(f){
    const r=new FileReader();
    r.onload=()=>{ $('#ingest-text').value=r.result; $('#ingest-tool').value=detectTool(r.result, f.name); updatePreview(); };
    r.readAsText(f);
  }

  // drag-drop file onto modal
  const dz=$('#dropzone');
  ['dragenter','dragover'].forEach(ev=>dz.addEventListener(ev,e=>{e.preventDefault();dz.classList.add('hot');}));
  ['dragleave','drop'].forEach(ev=>dz.addEventListener(ev,e=>{e.preventDefault();if(ev==='drop'||e.target===dz)dz.classList.remove('hot');}));
  dz.addEventListener('drop',e=>{ const f=e.dataTransfer.files[0]; if(f) readFileInto(f); });
  // drop a file anywhere on the table → open ingest with it (boards load via Import ⤒)
  window.addEventListener('dragover', e=>e.preventDefault());
  window.addEventListener('drop', e=>{
    if (ingestModal.hidden && e.dataTransfer.files.length){
      e.preventDefault();
      openIngest(); readFileInto(e.dataTransfer.files[0]);
    }
  });

  /* ================================================================ */
  /*  LIVE PIPE (WebSocket → parser → timeline)                       */
  /* ================================================================ */
  let pipe=null, pipeBuf='', pipeTL=null, pipeMode='';
  const RECON_TOOLS=['subfinder','amass','dnsx','httpx','nmap','whois','theharvester'];
  function setPipeStatus(cls, msg){ const s=$('#pipe-status'); if(s){ s.className='pipe-status '+cls; s.textContent=msg; } }
  function setReconStatus(cls, msg){ const s=$('#recon-status'); if(s){ s.className='pipe-status '+cls; s.textContent=msg; } }

  function connectPipe(onOpen){
    const url=$('#pipe-url').value.trim();
    if (pipe && pipe.readyState<=1){ if(onOpen) (pipe.readyState===1?onOpen():pipe.addEventListener('open',onOpen,{once:true})); return; }
    if (typeof WebSocket==='undefined'){ setPipeStatus('err','no WebSocket'); return; }
    setPipeStatus('off','connecting…'); setReconStatus('off','connecting…');
    try{ pipe=new WebSocket(url); }catch(e){ setPipeStatus('err','bad url'); return; }
    pipe.onopen=()=>{ setPipeStatus('on','● live · '+url); conLine('pipe connected '+url,'sys'); pipeTL=null; if(onOpen) onOpen(); };
    pipe.onclose=()=>{ setPipeStatus('off','offline · paste mode'); setReconStatus('off','runner offline — Launch will connect'); pipe=null; };
    pipe.onerror=()=>{ setPipeStatus('err','connect failed — run bridge/pipe-server.js'); setReconStatus('err','no runner — start bridge/pipe-server.js'); };
    pipe.onmessage=ev=>{
      try{ const j=JSON.parse(ev.data); if(j&&typeof j==='object'){ handlePipeJSON(j); return; } }catch(_){}
      handlePipeText(String(ev.data));
    };
  }
  function sendPipe(msg){
    if (pipe && pipe.readyState===1){ pipe.send(JSON.stringify(msg)); return true; }
    connectPipe(()=>{ try{ pipe.send(JSON.stringify(msg)); }catch(e){} });
    return false;
  }

  function ensurePipeTL(){
    if (pipeTL && findTL(pipeTL.id)) return pipeTL;
    pipeTL = addTimeline({ title:'LIVE FEED', color:'#27e8a7' });
    renderObjects(); return pipeTL;
  }
  // dispatch the runner protocol: hello | run-start | log | result | run-done, plus legacy {tool,line|events}
  function handlePipeJSON(j){
    if (j.type==='hello'){ pipeMode=j.mode||''; const exec=j.exec; setPipeStatus('on','● '+(exec?'exec':'simulate')+' · runner'); setReconStatus('on','● runner ready · '+(exec?'LIVE EXEC':'simulate')); return; }
    if (j.type==='run-start'){ snapshot(); pipeTL = addTimeline({ title:'RECON · '+j.target, color:'#27e8a7' }); renderObjects(); fitView(); setReconStatus('on','● running '+j.target+'…'); conLine('# recon '+j.target+' :: '+(j.tools||[]).join(', '),'sys','runner'); return; }
    if (j.type==='run-done'){ setReconStatus('on','● done · '+j.target); toast('recon complete: '+j.target); pipeTL=null; renderLegend(); return; }
    if (j.type==='log'){ const line=String(j.line||''); if(line.trim()) conLine(line.length>140?line.slice(0,140)+'…':line, /^#/.test(line)?'sys':'', j.tool); return; }
    if (j.type==='result'){ const tool=j.tool||'lines'; let events=[]; try{ events=TOOLS[tool].parse(String(j.text||'')); }catch(e){} pipeIngest(events, tool); return; }
    // legacy
    const tool=j.tool||'lines';
    if (Array.isArray(j.events)){ pipeIngest(j.events, tool); return; }
    if (j.line!=null){
      const line=String(j.line);
      if (!line.trim() || /^#/.test(line)){ conLine(line.trim()||' ','sys',tool); return; }
      let events=[]; try{ events=TOOLS[tool].parse(line); }catch(e){}
      if (events.length) pipeIngest(events, tool); else conLine(line,'',tool);
      return;
    }
    pipeIngest([ev(j)], tool);
  }
  function handlePipeText(text, tool){
    tool=tool||$('#ingest-tool')?.value||'lines';
    pipeBuf+=text;
    const lines=pipeBuf.split(/\r?\n/); pipeBuf=lines.pop();
    const events=[]; for(const ln of lines){ if(ln.trim()) try{ events.push(...TOOLS[tool].parse(ln)); }catch(e){} }
    if (events.length) pipeIngest(events, tool);
    else lines.forEach(ln=>ln.trim()&&conLine(ln,'',tool));
  }
  function pipeIngest(events, tool){
    if (!events.length) return;
    const tl=ensurePipeTL();
    const pts=eventsToPoints(events,'minute');
    const byT=new Map(); tl.points.forEach(p=>{ if(p.t!=null) byT.set(p.t,p); });
    for (const np of pts){ if(np.t!=null&&byT.has(np.t)) byT.get(np.t).boxes.push(...np.boxes); else { tl.points.push(np); if(np.t!=null) byT.set(np.t,np);} }
    tl.points.sort((a,b)=>(a.t==null?-1:b.t==null?1:a.t-b.t));
    renderObjects(); flashConsole(events, tool); autosaveSoon();
  }

  function renderReconTools(){
    const box=$('#recon-tools'); if(!box) return; box.textContent='';
    RECON_TOOLS.forEach((k,i)=>{
      const lab=el('label',{class:i<3?'on':'', style:`--c:${sourceColor(k)}`});
      const cb=el('input',{type:'checkbox', value:k}); if(i<3) cb.checked=true;
      cb.addEventListener('change',()=>lab.classList.toggle('on',cb.checked));
      lab.appendChild(cb); lab.appendChild(document.createTextNode(TOOLS[k]?.label||k));
      box.appendChild(lab);
    });
  }
  function launchRecon(){
    const target=$('#recon-target').value.trim();
    const tools=$$('#recon-tools input:checked').map(c=>c.value);
    if (!target){ setReconStatus('err','enter a target'); $('#recon-target').focus(); return; }
    if (!tools.length){ setReconStatus('err','pick at least one tool'); return; }
    setReconStatus('off','launching '+target+'…');
    const ok=sendPipe({type:'run', target, tools});
    if (!ok) conLine('# connecting to runner, then launching '+target,'sys','runner');
  }
  $('#pipe-connect').addEventListener('click', ()=>connectPipe());
  $('#recon-launch').addEventListener('click', launchRecon);
  $('#recon-target').addEventListener('keydown', e=>{ if(e.key==='Enter') launchRecon(); });

  /* ================================================================ */
  /*  SAVES / EXPORT / IMPORT                                         */
  /* ================================================================ */
  function refreshSaveList(){
    const sel=$('#save-list'); const cur=sel.value;
    const saves=getSaves(); sel.textContent='';
    sel.appendChild(el('option',{value:'', text: lsOK?'load…':'load… (no storage)'}));
    Object.keys(saves).sort().forEach(name=> sel.appendChild(el('option',{value:name, text:name})));
    sel.value=cur;
  }
  function getSaves(){ try{ return JSON.parse(lsGet(LS_SAVES)||'{}'); }catch(e){ return {}; } }
  function saveBoard(){
    const name=($('#save-name').value||'').trim() || ('case-'+new Date().toISOString().slice(0,10));
    const saves=getSaves(); saves[name]=serialize();
    if (!lsSet(LS_SAVES, JSON.stringify(saves))){ toast('storage blocked — use Export ⤓'); return; }
    refreshSaveList(); $('#save-list').value=name; toast('saved “'+name+'”');
  }
  function loadBoard(name){
    const saves=getSaves(); if(!saves[name]) return;
    snapshot(); load(saves[name]); renderObjects(); updateWorld(); fitView(); toast('loaded “'+name+'”'); $('#save-name').value=name;
  }
  function delSave(){
    const name=$('#save-list').value; if(!name) return;
    const saves=getSaves(); delete saves[name]; lsSet(LS_SAVES,JSON.stringify(saves)); refreshSaveList(); toast('deleted “'+name+'”');
  }
  function baseName(){ return ($('#save-name').value||'holotable').replace(/[^\w.-]+/g,'_'); }
  function download(name, text, mime){
    const blob=new Blob([text],{type:mime||'text/plain'});
    const a=el('a',{href:URL.createObjectURL(blob), download:name});
    document.body.appendChild(a); a.click(); setTimeout(()=>{ a.remove(); URL.revokeObjectURL(a.href); },0);
  }
  function allEvents(){
    const out=[];
    for (const tl of ST.timelines) for (const p of (tl.points||[])) for (const b of (p.boxes||[]))
      out.push({timeline:tl.title||'', t:p.t, type:b.type||'', module:b.module||'', data:b.data||'', source:b.source||''});
    return out;
  }
  const csvCell=s=>{ s=String(s==null?'':s); return /[",\n\r]/.test(s)?'"'+s.replace(/"/g,'""')+'"':s; };
  const mdCell=s=>String(s==null?'':s).replace(/\|/g,'\\|').replace(/[\r\n]+/g,' ');

  function exportBoard(){ download(baseName()+'.json', JSON.stringify(serialize(),null,2), 'application/json'); toast('exported board .json'); }
  function exportCSV(){
    const rows=[['timeline','timestamp','type','module','data','source']];
    allEvents().forEach(e=> rows.push([e.timeline, e.t!=null?fmtTime(e.t):'', e.type, e.module, e.data, e.source]));
    download(baseName()+'.csv', rows.map(r=>r.map(csvCell).join(',')).join('\r\n'), 'text/csv');
    toast('exported events .csv');
  }
  function exportMaltego(){
    const map={ip:'maltego.IPv4Address',ipv6:'maltego.IPv6Address',domain:'maltego.Domain',email:'maltego.EmailAddress',url:'maltego.URL',phone:'maltego.PhoneNumber',port:'maltego.Service',asn:'maltego.AS','hash-md5':'maltego.Hash','hash-sha1':'maltego.Hash','hash-sha256':'maltego.Hash',cve:'maltego.Vulnerability'};
    const rows=[['entity','value','source','module','timestamp']];
    allEvents().forEach(e=> rows.push([ map[e.type]||'maltego.Phrase', e.data, e.source, e.module, e.t!=null?fmtTime(e.t):'' ]));
    download(baseName()+'-maltego.csv', rows.map(r=>r.map(csvCell).join(',')).join('\r\n'), 'text/csv');
    toast('exported Maltego .csv');
  }
  function exportMarkdown(){
    const evAll=allEvents();
    const out=['# OSINT Holotable — '+baseName(), '', '_generated '+new Date().toISOString()+' · '+evAll.length+' events_', ''];
    const counts={}; evAll.forEach(e=>counts[e.source]=(counts[e.source]||0)+1);
    out.push('## Sources',''); Object.entries(counts).sort((a,b)=>b[1]-a[1]).forEach(([s,n])=>out.push(`- **${s}** — ${n}`)); out.push('');
    for (const tl of ST.timelines){
      out.push('## '+(tl.title||'timeline'),'', '| time | type | data | module | source |','|---|---|---|---|---|');
      const evs=[]; (tl.points||[]).forEach(p=>(p.boxes||[]).forEach(b=>evs.push(Object.assign({t:p.t},b))));
      evs.sort((a,b)=>(a.t==null?-1:b.t==null?1:a.t-b.t));
      evs.forEach(e=>out.push(`| ${e.t!=null?fmtTime(e.t):''} | ${mdCell(e.type)} | ${mdCell(e.data)} | ${mdCell(e.module)} | ${e.source||''} |`));
      out.push('');
    }
    if (ST.links.length){ out.push('## Linked events',''); ST.links.forEach(l=>{ const a=findBox(l.from), b=findBox(l.to); if(a&&b) out.push(`- ${mdCell(a.data)} ↔ ${mdCell(b.data)}`); }); out.push(''); }
    download(baseName()+'.md', out.join('\n'), 'text/markdown');
    toast('exported report .md');
  }
  function importBoard(file){
    const r=new FileReader();
    r.onload=()=>{ try{ const data=JSON.parse(r.result); snapshot(); load(data); renderObjects(); updateWorld(); fitView(); toast('imported board'); }catch(e){ toast('bad json'); } };
    r.readAsText(file);
  }
  $('#save-btn').addEventListener('click', saveBoard);
  $('#save-list').addEventListener('change', e=>{ if(e.target.value) loadBoard(e.target.value); });
  $('#del-save').addEventListener('click', delSave);
  $('#export-btn').addEventListener('click', e=>{
    const r=e.currentTarget.getBoundingClientRect();
    showCtx(r.left, r.bottom+4, [
      {label:'Board (.json)', key:'state', fn:exportBoard},
      {label:'Events (.csv)', key:'flat', fn:exportCSV},
      {label:'Maltego (.csv)', key:'graph', fn:exportMaltego},
      {label:'Report (.md)', key:'doc', fn:exportMarkdown},
    ]);
  });
  $('#import-btn').addEventListener('click', ()=>$('#import-file').click());
  $('#import-file').addEventListener('change', e=>{ const f=e.target.files[0]; if(f) importBoard(f); e.target.value=''; });

  /* ================================================================ */
  /*  TOOLBAR + DOCK wiring                                           */
  /* ================================================================ */
  $$('#modes .mode').forEach(b=> b.addEventListener('click', ()=>setMode(b.dataset.mode)));
  // drop a new timeline in the middle of what you're currently looking at,
  // lightly staggered so repeats don't overlap — then it's yours to drag anywhere.
  function addTimelineHere(){
    const c = screenToWorld(innerWidth/2, innerHeight/2);
    const k = ST.timelines.length;
    const off = (k % 6) * 28 + Math.floor(k / 6) * 12;   // diagonal cascade — never lands exactly on a prior one
    return addTimeline({ x: c.x - 180 + off, y: c.y - 70 + off });
  }
  $('#add-timeline').addEventListener('click', ()=>{ snapshot(); addTimelineHere(); renderObjects(); autosave(); });
  $('#open-ingest').addEventListener('click', ()=>openIngest());
  $('#expand-all').addEventListener('click', ()=>{ ST.timelines.forEach(tl=>tl.points.forEach(p=>p.expanded=true)); renderObjects(); });
  $('#collapse-all').addEventListener('click', ()=>{ ST.timelines.forEach(tl=>tl.points.forEach(p=>p.expanded=false)); renderObjects(); });
  $('#fit').addEventListener('click', fitView);
  $('#search').addEventListener('input', e=>{ filterText=e.target.value; applyFilter(); });

  $('#dock-collapse').addEventListener('click', ()=>{ $('#dock').classList.toggle('collapsed'); $('#dock-collapse').textContent=$('#dock').classList.contains('collapsed')?'›':'‹'; });
  $('#console-toggle').addEventListener('click', toggleConsole);
  $('#console-head').addEventListener('click', e=>{ if(e.target.id!=='console-toggle') toggleConsole(); });
  function toggleConsole(){ const c=$('#console'); c.classList.toggle('collapsed'); $('#console-toggle').textContent=c.classList.contains('collapsed')?'▴':'▾'; }

  // legend toggles
  $('#legend').addEventListener('click', e=>{ const r=e.target.closest('[data-act="src-toggle"]'); if(!r) return; const s=r.dataset.src; ST.hiddenSources[s]=!ST.hiddenSources[s]; renderObjects(); });

  // quick-ingest chips
  function renderQuickTools(){
    const q=$('#quick-tools'); q.textContent='';
    ['auto','spiderfoot','nmap','masscan','amass','subfinder','httpx','dnsx','nuclei','shodan','theharvester','whois','urls','maltego','secrets','json','csv'].forEach(k=>{
      if(!TOOLS[k]) return;
      q.appendChild(el('span',{class:'qt', style:`color:${TOOLS[k].color}`, text:TOOLS[k].label, onclick:()=>openIngest(k)}));
    });
  }

  $('#hint-x').addEventListener('click', ()=>$('#hint').style.display='none');

  /* ================================================================ */
  /*  KEYBOARD                                                        */
  /* ================================================================ */
  window.addEventListener('keydown', e=>{
    const typing = e.target.matches('input,textarea,[contenteditable="true"]');
    if (e.code==='Space' && !typing){ spaceDown=true; viewport.classList.add('viewport-pan'); }
    const m = e.metaKey||e.ctrlKey;
    // undo/redo work globally — even while editing a field (canvas-app convention)
    if (m && e.key.toLowerCase()==='z'){ e.preventDefault(); e.shiftKey?redo():undo(); return; }
    if (m && e.key.toLowerCase()==='y'){ e.preventDefault(); redo(); return; }
    if (typing) return;
    if (m) return;
    switch(e.key.toLowerCase()){
      case 'v': setMode('select'); break;
      case 'h': setMode('pan'); break;
      case 'l': setMode('link'); break;
      case 'p': setMode('pen'); break;
      case 'n': setMode('note'); break;
      case 't': snapshot(); addTimelineHere(); renderObjects(); autosave(); break;
      case 'i': openIngest(); break;
      case 'e': ST.timelines.forEach(tl=>tl.points.forEach(p=>p.expanded=true)); renderObjects(); break;
      case 'c': ST.timelines.forEach(tl=>tl.points.forEach(p=>p.expanded=false)); renderObjects(); break;
      case 'f': fitView(); break;
      case 'escape': closeIngest(); closeCtx(); linkFrom=null; renderObjects(); break;
      case 'delete': case 'backspace':
        if (selection.size){ snapshot(); selection.forEach(id=>{ if(boxIndex.get(id)) deleteBox(id); else { ST.notes=ST.notes.filter(n=>n.id!==id); ST.timelines=ST.timelines.filter(t=>t.id!==id);} }); selection.clear(); renderObjects(); autosave(); }
        break;
    }
  });
  window.addEventListener('keyup', e=>{ if(e.code==='Space'){ spaceDown=false; if(mode!=='pan') viewport.classList.remove('viewport-pan'); } });

  window.addEventListener('resize', ()=>{ drawGrid(); });

  /* ================================================================ */
  /*  TOAST                                                           */
  /* ================================================================ */
  let toastT=null;
  function toast(msg){ const t=$('#toast'); t.textContent=msg; t.hidden=false; clearTimeout(toastT); toastT=setTimeout(()=>t.hidden=true,1700); }

  /* ================================================================ */
  /*  BOOT                                                            */
  /* ================================================================ */
  function seed(){
    const now=Date.now();
    const tl=addTimeline({title:'WELCOME · drop a tool export here', x:-260, y:-40, color:'#16e0ff'});
    const mk=(min,arr)=>{ const p={id:uid('pt'),t:now-min*60000,expanded:false,boxes:arr.map(a=>({id:uid('bx'),type:a[0],module:a[1],data:a[2],source:a[3]}))}; tl.points.push(p); };
    mk(42,[['domain','spiderfoot','target.example.com','spiderfoot'],['ip','spiderfoot','203.0.113.42','spiderfoot'],['email','spiderfoot','admin@target.example.com','spiderfoot']]);
    mk(30,[['port','nmap','203.0.113.42:22 ssh','nmap'],['port','nmap','203.0.113.42:443 https','nmap']]);
    mk(12,[['domain','amass','vpn.target.example.com','amass'],['domain','amass','mail.target.example.com','amass']]);
    mk(2,[['email','theharvester','j.doe@target.example.com','theharvester']]);
    tl.points.sort((a,b)=>a.t-b.t);
    ST.notes.push({id:uid('nt'), x:560, y:-40, tone:'cyan', text:'Drag a timeline anywhere on the table to lay out a scenario. Ingest ▸ pick a tool ▸ paste output. Drag the ⠿ on any event to move it between points. Press E to fan every stack open, F to frame the table.'});
  }

  // restore autosave or seed
  const auto = lsGet(LS_AUTO);
  if (auto){ try{ load(JSON.parse(auto)); }catch(e){ seed(); } } else { seed(); }
  if (!ST.cam || (ST.cam.x===0&&ST.cam.y===0&&ST.cam.zoom===1)) ST.cam={x:innerWidth/2,y:innerHeight/2-40,zoom:1};

  // Scripting / automation handle. Lets power users (or a local script) push
  // events straight onto the table, and gives tests a deterministic surface.
  //   holotable.push([{t,type,module,data,source}], {title})
  //   holotable.setCam({x,y,zoom}); holotable.fit()
  window.holotable = {
    get state(){ return ST; },
    push(events, opts){ return ingest((events||[]).map(ev), opts||{}); },
    parse(tool, text){ try{ return (TOOLS[tool]||TOOLS.lines).parse(text); }catch(e){ return []; } },
    ingestText(tool, text, opts){ return ingest(this.parse(tool,text), Object.assign({source:tool},opts||{})); },
    addTimeline, fit:fitView, render:renderObjects, undo, redo,
    setCam(c){ Object.assign(ST.cam, c); updateWorld(); },
    TOOLS,
  };

  fillToolSelect($('#ingest-tool'));
  renderQuickTools();
  renderReconTools();
  refreshSaveList();
  setMode('select');
  renderObjects();
  updateWorld();
  if (!ST.timelines.length && !ST.notes.length) fitView(); else setTimeout(fitView,30);
  conLine('holotable ready — '+ (lsOK?'local storage ok':'storage blocked (export to save)'), 'sys');
}

/* run only in a browser */
if (typeof document !== 'undefined'){
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
}

/* export pure helpers for Node tests */
if (typeof module !== 'undefined' && module.exports){
  module.exports = {
    parseTime, fmtTime, toLocalInput, fromLocalInput, bucketMs, classify, parseCSV, headerIndex,
    parseSpiderfoot, parseCSVGeneric, parseJSONGeneric, parseHarvester, parseNmap, parseAmass,
    parseShodan, parseWhois, parseDns, parseLines, flattenJSON,
    parseHttpx, parseNuclei, parseMasscan, parseDnsx, parseSubdomains, parseUrls, parseSecrets, detectTool,
    eventsToPoints, layoutPoints, sourceColor, TOOLS,
  };
}
