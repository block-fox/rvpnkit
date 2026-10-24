/* Optional browser regression: NODE_PATH may point to an existing Playwright install. */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const http = require('node:http');
const {
  spawn
} = require('node:child_process');
const {
  chromium
} = require('playwright');
const fetch = (url, options = {}) => new Promise((resolve, reject) => {
  const req = http.request(url, {
    method: options.method || 'GET',
    headers: {
      ...(options.headers || {}),
      ...(options.body ? {
        'Content-Length': Buffer.byteLength(options.body)
      } : {})
    }
  }, response => {
    const chunks = [];
    response.on('data', c => chunks.push(c));
    response.on('end', () => {
      const body = Buffer.concat(chunks).toString('utf8');
      resolve({
        status: response.statusCode,
        ok: response.statusCode >= 200 && response.statusCode < 300,
        json: async () => JSON.parse(body)
      });
    });
  });
  req.on('error', reject);
  if (options.body) req.write(options.body);
  req.end();
});
const root = path.resolve(__dirname, '..');
const exe = process.env.RVPNKIT_WEB_EXE || path.join(root, 'rust', 'target', 'release', 'rvpnkit.exe');
const port = Number(process.env.RVPNKIT_TEST_PORT || 18788);
const base = `http://127.0.0.1:${port}`;
const server = spawn(exe, ['--demo', '--no-open', '--addr', `127.0.0.1:${port}`], {
  stdio: ['ignore', 'pipe', 'pipe'],
  windowsHide: true
});
let browser;
process.on('exit', () => server.kill());
server.on('error', e => {
  console.error(e.message);
  process.exitCode = 1;
});
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
async function ready() {
  for (let i = 0; i < 80; i++) {
    try {
      if ((await fetch(base + '/health')).ok) return;
    } catch {}
    await sleep(100);
  }
  throw new Error('Demo server did not start');
}
function rawRequest(payload) {
  return new Promise((resolve, reject) => {
    const net = require('node:net');
    const socket = net.createConnection(port, '127.0.0.1');
    let data = '';
    socket.on('connect', () => socket.end(payload));
    socket.on('data', chunk => data += chunk);
    socket.on('end', () => resolve(data));
    socket.on('error', reject);
  });
}
(async () => {
  await ready();
  const envelope = await (await fetch(base + '/api/state')).json();
  assert.equal(envelope.ok, true);
  assert.equal(envelope.data.demo, true);
  assert.equal(envelope.data.canWrite, false);
  assert.equal(envelope.data.networks.length, 6);
  assert.equal(typeof envelope.data.networks[0].members[0].nodeId, 'string');
  assert(!JSON.stringify(envelope).includes('"token"'));
  assert.equal((await fetch(base + '/api/power', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: '{"on":true}'
  })).status, 403);
  assert.equal((await fetch(base + '/api/power', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Origin': 'http://evil.test'
    },
    body: '{"on":true}'
  })).status, 403);
  assert.equal((await fetch(base + '/api/power', {
    method: 'POST',
    body: 'on=true'
  })).status, 415);
  assert((await rawRequest('POST /api/power HTTP/1.1\r\nHost: localhost\r\nContent-Length: 1000000000\r\n\r\n')).startsWith('HTTP/1.1 413'));
  assert((await rawRequest('GET / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n')).startsWith('HTTP/1.1 400'));
  for (const asset of ['/', '/assets/ui.css', '/assets/ui.js']) assert.equal((await fetch(base + asset)).status, 200);
  const candidates = [process.env.RVPNKIT_BROWSER, 'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe', 'C:/Program Files/Google/Chrome/Application/chrome.exe'].filter(Boolean);
  const executablePath = candidates.find(p => fs.existsSync(p));
  browser = await chromium.launch({
    headless: true,
    ...(executablePath ? {
      executablePath
    } : {})
  });
  const context = await browser.newContext({
    viewport: {
      width: 1440,
      height: 1100
    },
    acceptDownloads: true
  });
  const page = await context.newPage();
  const errors = [];
  page.on('pageerror', e => errors.push(e.message));
  await page.goto(base);
  await page.waitForSelector('#demo-banner:not([hidden])');
  assert.equal(await page.locator('#overview-networks .network-card').count(), 3);
  assert(await page.locator('#join-top').isDisabled());
  fs.mkdirSync(path.join(root, 'docs/screenshots'), {
    recursive: true
  });
  await page.screenshot({
    path: path.join(root, 'docs/screenshots/web-overview.png'),
    fullPage: true
  });
  await page.locator('[data-page=networks]').click();
  assert.equal(await page.locator('#all-networks .network-card').count(), 6);
  await page.locator('#all-networks [data-favorite]').first().click();
  await page.locator('#favorites-only').click();
  assert.equal(await page.locator('#all-networks .network-card').count(), 1);
  await page.reload();
  await page.waitForSelector('#all-networks .network-card');
  assert.equal(await page.locator('#all-networks .favorite-btn.active').count(), 1);
  await page.locator('#network-search').fill('Minecraft');
  assert.equal(await page.locator('#all-networks .network-card').count(), 1);
  await page.locator('#network-search').fill('不存在的网络');
  assert.equal(await page.locator('#all-networks .network-card').count(), 0);
  await page.locator('#network-search').fill('');
  await page.locator('#network-role').selectOption('admin');
  assert.equal(await page.locator('#all-networks .network-card').count(), 2);
  await page.locator('[data-page=members]').click();
  await page.locator('#member-network').selectOption(envelope.data.networks[1].guid);
  assert.equal(await page.locator('#members-body tr').count(), 12);
  await page.locator('#member-search').fill('NorthStar');
  assert.equal(await page.locator('[data-select-member]').count(), 1);
  await page.locator('[data-select-member]').check();
  assert(await page.locator('#batchbar').isVisible());
  await page.locator('#member-network').selectOption(envelope.data.networks[0].guid);
  assert(await page.locator('#batchbar').isHidden());
  await page.locator('#member-search').fill('');
  await page.locator('[data-member-detail]').first().click();
  assert(await page.locator('#action-dialog').isVisible());
  await page.keyboard.press('Escape');
  assert(await page.locator('#action-dialog').isHidden());
  await page.locator('[data-page=public]').click();
  await page.locator('#public-search').fill('Minecraft');
  await page.locator('#public-submit').click();
  await page.waitForSelector('[data-public-join]');
  assert.equal(await page.locator('[data-public-join]').count(), 1);
  assert(await page.locator('[data-public-join]').isDisabled());
  await page.locator('[data-page=settings]').click();
  await page.locator('#theme-setting').selectOption('dark');
  await page.locator('#refresh-interval').selectOption('0');
  await page.reload();
  await page.waitForSelector('#demo-banner:not([hidden])');
  assert.equal(await page.locator('html').getAttribute('data-theme'), 'dark');
  assert.equal(await page.locator('#refresh-interval').inputValue(), '0');
  await page.locator('[data-page=overview]').click();
  await page.screenshot({
    path: path.join(root, 'docs/screenshots/web-dark.png'),
    fullPage: true
  });
  await page.setViewportSize({
    width: 390,
    height: 844
  });
  await page.screenshot({
    path: path.join(root, 'docs/screenshots/web-mobile.png'),
    fullPage: true
  });
  assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
  await page.setViewportSize({
    width: 1440,
    height: 1100
  });
  // Local response fixtures: all service mutations remain intercepted.
  const fixture = structuredClone(envelope);
  fixture.data.demo = false;
  fixture.data.canWrite = true;
  fixture.data.networks[0].token = 'never-export-this';
  fixture.data.networks[0].members = Array.from({
    length: 120
  }, (_, i) => ({
    nodeId: i === 119 ? '18446744073709551615' : String(100000 + i),
    alias: i === 0 ? '=SUM(1,1)' : i === 1 ? '<img src=x onerror=alert(1)>' : `测试成员 ${i}`,
    publicIp: `192.0.2.${i + 1}`
  }));
  let offline = false;
  await page.route('**/api/state*', route => offline ? route.abort() : route.fulfill({
    json: fixture
  }));
  let posted;
  await page.route('**/api/networks/join', async route => {
    posted = route.request().postDataJSON();
    await route.fulfill({
      json: {
        ok: true,
        data: {
          requestId: 1
        }
      }
    });
  });
  await page.locator('#refresh').click();
  await page.waitForFunction(() => !document.querySelector('#join-top').disabled);
  await page.locator('#join-top').click();
  await page.locator('#dialog-name').fill('回归测试网络');
  await page.locator('#dialog-password').fill('test-only');
  await page.locator('#dialog-submit').click();
  await page.waitForFunction(() => !document.querySelector('#action-dialog').open);
  assert.deepEqual(posted, {
    name: '回归测试网络',
    password: 'test-only'
  });
  await page.locator('[data-page=members]').click();
  await page.locator('#member-network').selectOption(fixture.data.networks[0].guid);
  await page.locator('#member-sort').selectOption('id');
  assert.equal(await page.locator('[data-select-member]').count(), 50);
  assert.equal(await page.locator('#members-body img').count(), 0);
  await page.locator('#next-page').click();
  await page.locator('#next-page').click();
  assert.equal(await page.locator('[data-select-member]').count(), 20);
  assert((await page.locator('#members-body').innerText()).includes('18446744073709551615'));
  const csvDownload = page.waitForEvent('download');
  await page.locator('#export-members').click();
  const csv = fs.readFileSync(await (await csvDownload).path(), 'utf8');
  assert(csv.includes("'=SUM(1,1)"));
  assert(csv.includes('18446744073709551615'));
  const snapshotDownload = page.waitForEvent('download');
  await page.locator('#export-top').click();
  const snapshot = fs.readFileSync(await (await snapshotDownload).path(), 'utf8');
  assert(!snapshot.includes('never-export-this'));
  assert(!snapshot.includes('"token"'));
  offline = true;
  await page.locator('#refresh').click();
  await page.waitForSelector('#connection-banner:not([hidden])');
  assert(await page.locator('#join-top').isDisabled());
  offline = false;
  await page.locator('#refresh').click();
  await page.waitForFunction(() => document.querySelector('#connection-banner').hidden);
  assert(!(await page.locator('#join-top').isDisabled()));
  assert.deepEqual(errors, []);
  console.log('PASS: embedded assets, demo isolation, HTTP limits, origin validation, six-page navigation, favorites persistence, filters, member switching, details, discovery, theme/interval persistence, mobile layout, safe rendering, large node IDs, pagination, mocked join, CSV/JSON exports, disconnect/recovery; no browser exceptions.');
})().catch(e => {
  console.error(e);
  process.exitCode = 1;
}).finally(async () => {
  if (browser) await browser.close();
  server.kill();
});
