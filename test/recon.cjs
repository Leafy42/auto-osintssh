/* Integration test: real runner process + real page, driven through the RECON
   panel over a live WebSocket. Run: NODE_PATH=$(npm root -g) node test/recon.cjs */
const { chromium } = require('playwright');
const { spawn } = require('child_process');
const path = require('path');

const PORT = 7847;
const URL = 'file://' + path.resolve(__dirname, '..', 'index.html');
let fails = 0;
const ok = (n, c, extra) => { if (c) console.log('  ok  ' + n); else { fails++; console.error('FAIL  ' + n + (extra ? '  → ' + extra : '')); } };

(async () => {
  // launch the runner in simulate + fast mode (no real tools, no delays)
  const srv = spawn('node', [path.resolve(__dirname, '..', 'bridge/pipe-server.js'), '--port', String(PORT), '--fast'], { stdio: 'ignore' });
  await new Promise(r => setTimeout(r, 500));

  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 1400, height: 900 } });
  const errors = [];
  page.on('pageerror', e => errors.push(e.message));
  page.on('console', m => { if (m.type() === 'error') errors.push(m.text()); });
  await page.goto(URL);
  await page.waitForTimeout(250);

  ok('recon panel present', await page.locator('#recon-launch').count() === 1);
  ok('recon tool chips rendered', await page.locator('#recon-tools label').count() >= 4);

  // point the pipe at our runner, choose a target, pick tools, launch
  await page.fill('#pipe-url', 'ws://localhost:' + PORT);
  await page.fill('#recon-target', 'target.example.com');
  // ensure nmap, amass, whois are checked
  await page.evaluate(() => {
    const want = ['nmap', 'amass', 'whois'];
    document.querySelectorAll('#recon-tools input').forEach(cb => { cb.checked = want.includes(cb.value); cb.dispatchEvent(new Event('change')); });
  });
  const tl0 = await page.locator('.timeline').count();
  await page.click('#recon-launch');

  // wait for the runner to stream a run-start + results back
  await page.waitForFunction(() =>
    [...document.querySelectorAll('.tl-title')].some(i => /^RECON · /.test(i.value)), null, { timeout: 8000 }
  ).catch(() => {});

  const reconTitle = await page.evaluate(() => [...document.querySelectorAll('.tl-title')].map(i => i.value).find(v => /^RECON · /.test(v)) || '');
  ok('recon timeline created', /target\.example\.com/.test(reconTitle), reconTitle);
  ok('timeline count grew', await page.locator('.timeline').count() === tl0 + 1);

  // give results a moment to ingest, then check content
  await page.waitForTimeout(800);
  const legend = (await page.locator('#legend').textContent()).toLowerCase();
  ok('nmap results ingested', legend.includes('nmap'));
  ok('amass results ingested', legend.includes('amass'));
  ok('whois results ingested', legend.includes('whois'));

  const boxes = await page.evaluate(() => {
    const tl = [...document.querySelectorAll('.timeline')].find(t => /^RECON · /.test(t.querySelector('.tl-title')?.value || ''));
    return tl ? tl.querySelectorAll('.box').length : 0;
  });
  ok('recon timeline has events', boxes > 3, 'boxes=' + boxes);

  const consoleLines = await page.locator('#console-feed .cl').count();
  ok('console streamed log lines', consoleLines > 5, 'lines=' + consoleLines);
  ok('status shows done', /done|running/.test((await page.locator('#recon-status').textContent()) || ''));
  ok('no page errors', errors.length === 0, errors.join(' | '));

  // bad target is rejected by the runner (no new timeline, a rejection log)
  const before = await page.locator('.timeline').count();
  await page.fill('#recon-target', 'evil.com; rm -rf /');
  await page.click('#recon-launch');
  await page.waitForTimeout(600);
  ok('malicious target rejected (no new timeline)', await page.locator('.timeline').count() === before);
  ok('rejection logged', (await page.locator('#console-feed').textContent()).toLowerCase().includes('reject'));

  await browser.close();
  srv.kill('SIGINT');
  console.log(`\nrecon: ${fails ? fails + ' FAILED' : 'all passed'}`);
  process.exit(fails ? 1 : 0);
})().catch(e => { console.error(e); process.exit(1); });
