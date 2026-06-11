/* Headless browser smoke test: loads index.html, runs init(), exercises core flows.
   Run: NODE_PATH=$(npm root -g) node test/smoke.cjs */
const { chromium } = require('playwright');
const path = require('path');

const URL = 'file://' + path.resolve(__dirname, '..', 'index.html');
let fails = 0;
const ok = (n, c, extra) => { if (c) console.log('  ok  ' + n); else { fails++; console.error('FAIL  ' + n + (extra ? '  → ' + extra : '')); } };

(async () => {
  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 1400, height: 900 } });
  const errors = [];
  page.on('console', m => { if (m.type() === 'error') errors.push(m.text()); });
  page.on('pageerror', e => errors.push('PAGEERROR: ' + e.message));

  await page.goto(URL);
  await page.waitForTimeout(250);

  // ---- 1. clean boot ----
  ok('no console/page errors on load', errors.length === 0, errors.join(' | '));
  ok('scripting hook exposed', await page.evaluate(() => !!window.holotable));
  ok('seed timeline rendered', await page.locator('.timeline').count() >= 1);
  const boxes0 = await page.locator('.box').count();
  ok('seed events rendered', boxes0 > 0, 'boxes=' + boxes0);
  ok('legend populated', await page.locator('#legend .lg').count() >= 1);

  // Pin the camera so the seed timeline sits at a known, fully-visible spot.
  await page.evaluate(() => window.holotable.setCam({ x: 560, y: 200, zoom: 1 }));
  await page.keyboard.press('e');                 // expand all
  await page.waitForTimeout(150);
  ok('expand-all opens stacks', await page.locator('.stack.open').count() >= 1);

  // ---- 2. free drag a box between two points (headline interaction) ----
  const d = await page.evaluate(() => {
    const tl = document.querySelector('.timeline');
    const pts = [...tl.querySelectorAll('.point')];
    if (pts.length < 2) return { skip: true };
    const srcBox = pts[0].querySelector('.stack .box');
    const grip = srcBox.querySelector('.b-grip');
    const dot = pts[1].querySelector('.dot');
    const gr = grip.getBoundingClientRect(), dr = dot.getBoundingClientRect();
    return { gx: gr.left + gr.width / 2, gy: gr.top + gr.height / 2,
             dx: dr.left + dr.width / 2, dy: dr.top + dr.height / 2,
             bid: srcBox.dataset.bid, p1id: pts[1].dataset.pid };
  });
  ok('drag setup found two points', !d.skip && d.gy > 60, JSON.stringify(d));
  if (!d.skip) {
    await page.mouse.move(d.gx, d.gy);
    await page.mouse.down();
    await page.mouse.move((d.gx + d.dx) / 2, (d.gy + d.dy) / 2, { steps: 5 });
    await page.mouse.move(d.dx, d.dy, { steps: 5 });
    await page.waitForTimeout(40);
    ok('dropzones highlight while dragging', await page.locator('.point.drop-hot').count() >= 1);
    await page.mouse.up();
    await page.waitForTimeout(150);
    const movedTo = await page.evaluate((bid) => {
      const el = document.querySelector(`.box[data-bid="${bid}"]`);
      return el ? el.closest('.point').dataset.pid : null;
    }, d.bid);
    ok('box moved to target point', movedTo === d.p1id, `landed in ${movedTo} want ${d.p1id}`);
  }

  // ---- 3. link two events ----
  await page.keyboard.press('l');
  const lb = await page.evaluate(() => {
    const bs = [...document.querySelectorAll('.timeline .box')].slice(0, 2);
    return bs.map(b => { const r = b.getBoundingClientRect(); return { x: r.left + r.width / 2, y: r.top + r.height / 2 }; });
  });
  await page.mouse.click(lb[0].x, lb[0].y);
  await page.mouse.click(lb[1].x, lb[1].y);
  await page.waitForTimeout(120);
  ok('link drawn between events', await page.locator('#layer-draw path.link').count() >= 1);
  await page.keyboard.press('v');

  // ---- 4. drop a note on empty space ----
  const notes0 = await page.locator('.note').count();
  await page.keyboard.press('n');
  await page.mouse.click(1320, 820);              // far corner, empty world
  await page.waitForTimeout(100);
  ok('note dropped', await page.locator('.note').count() === notes0 + 1);
  await page.evaluate(() => document.activeElement && document.activeElement.blur());
  await page.keyboard.press('v');

  // ---- 5. add a timeline ----
  const tl0 = await page.locator('.timeline').count();
  await page.click('#add-timeline');
  await page.waitForTimeout(100);
  ok('add timeline', await page.locator('.timeline').count() === tl0 + 1);

  // ---- 6. ingest nmap output ----
  await page.click('#open-ingest');
  await page.waitForTimeout(80);
  ok('ingest modal opens', await page.locator('#ingest').isVisible());
  await page.selectOption('#ingest-tool', 'nmap');
  await page.fill('#ingest-text',
    'Host: 198.51.100.5 () Ports: 22/open/tcp//ssh///, 443/open/tcp//https///\n' +
    'Host: 198.51.100.6 () Ports: 80/open/tcp//http///\n');
  const prev = await page.locator('#ingest-preview').textContent();
  ok('ingest preview parses', /parsed/.test(prev) && /[1-9]/.test(prev), prev);
  const before6 = await page.locator('.box').count();
  await page.click('#ingest-go');
  await page.waitForTimeout(150);
  ok('ingest added events', await page.locator('.box').count() > before6);
  ok('nmap source in legend', (await page.locator('#legend').textContent()).toLowerCase().includes('nmap'));

  // ---- 7. search filter ----
  await page.fill('#search', 'ssh');
  await page.waitForTimeout(120);
  ok('search dims non-matches', await page.locator('.box.dim').count() >= 1);
  await page.fill('#search', '');
  await page.waitForTimeout(60);

  // ---- 8. zoom doesn't throw ----
  await page.mouse.move(700, 450);
  await page.mouse.wheel(0, -300);
  await page.waitForTimeout(60);
  ok('zoom updates world transform', /scale\(/.test(await page.locator('#world').getAttribute('style')));

  // ---- 9. save to localStorage ----
  await page.fill('#save-name', 'smoke-case');
  await page.click('#save-btn');
  await page.waitForTimeout(80);
  ok('board persisted to localStorage',
    await page.evaluate(() => { try { return !!JSON.parse(localStorage.getItem('holotable_saves') || '{}')['smoke-case']; } catch (e) { return false; } }));

  // ---- 10. undo (blur fields first so app-level undo runs) ----
  const before10 = await page.locator('.note').count();
  await page.keyboard.press('n'); await page.mouse.click(1100, 700); await page.keyboard.press('v');
  await page.evaluate(() => document.activeElement && document.activeElement.blur());
  await page.waitForTimeout(60);
  const add10 = await page.locator('.note').count();
  await page.keyboard.press('Control+z');
  await page.waitForTimeout(150);
  const undo10 = await page.locator('.note').count();
  ok('undo reverts last change', add10 === before10 + 1 && undo10 === before10, `b=${before10} add=${add10} undo=${undo10}`);

  ok('still no errors after interactions', errors.length === 0, errors.join(' | '));

  await browser.close();
  console.log(`\nsmoke: ${fails ? fails + ' FAILED' : 'all passed'}`);
  process.exit(fails ? 1 : 0);
})().catch(e => { console.error(e); process.exit(1); });
