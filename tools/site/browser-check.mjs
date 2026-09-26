// Browser behavior checks using Chromium's DevTools protocol; no npm dependencies.
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {createServer} from 'node:http';
import {readFile, writeFile, mkdir, mkdtemp, rm, stat} from 'node:fs/promises';
import path from 'node:path';
import {setTimeout as delay} from 'node:timers/promises';

const [directory = 'dist/site', base = '/ysonet/', browser] = process.argv.slice(2);
if (!browser) throw new Error('Usage: node tools/site/browser-check.mjs OUTPUT BASE_PATH BROWSER');
const output = path.resolve(directory);
const artifacts = path.resolve('temp/site-browser');
await mkdir(artifacts, {recursive: true});
const profile = await mkdtemp(path.join(artifacts, 'profile-'));
const mime = {'.html': 'text/html; charset=utf-8', '.css': 'text/css', '.js': 'text/javascript', '.json': 'application/json', '.svg': 'image/svg+xml'};
const server = createServer(async (request, response) => {
  try {
    const url = new URL(request.url, 'http://localhost');
    if (!url.pathname.startsWith(base)) throw new Error('Outside base');
    let relative = decodeURIComponent(url.pathname.slice(base.length));
    if (!relative || relative.endsWith('/')) relative += 'index.html';
    const file = path.resolve(output, relative);
    if (!file.startsWith(output + path.sep)) throw new Error('Outside output');
    response.setHeader('Content-Type', mime[path.extname(file)] || 'application/octet-stream');
    response.end(await readFile(file));
  } catch (_) { response.writeHead(404); response.end('Not found'); }
});
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
const origin = `http://127.0.0.1:${server.address().port}`;
const child = spawn(browser, ['--headless', '--disable-gpu', '--no-first-run', '--disable-background-networking',
  '--remote-debugging-port=0', `--user-data-dir=${profile}`, 'about:blank'], {stdio: 'ignore'});
let socket;
const pending = new Map();
let sequence = 0;
const errors = [];
function call(method, params = {}) {
  return new Promise((resolve, reject) => {
    const id = ++sequence;
    const timeout = setTimeout(() => { pending.delete(id); reject(new Error(`CDP timeout: ${method}`)); }, 15000);
    pending.set(id, {resolve, reject, timeout});
    socket.send(JSON.stringify({id, method, params}));
  });
}
async function evaluate(expression) {
  const result = await call('Runtime.evaluate', {expression, returnByValue: true, awaitPromise: true});
  if (result.exceptionDetails) throw new Error(JSON.stringify(result.exceptionDetails));
  return result.result.value;
}
async function until(fn, message) {
  for (let i = 0; i < 100; i++) { if (await fn()) return; await delay(100); }
  throw new Error(message);
}
async function go(route = '') {
  const url = origin + base + route;
  await call('Page.navigate', {url});
  await until(() => evaluate(`location.href === ${JSON.stringify(url)} && document.readyState === 'complete'`), 'Page did not load: ' + route);
}
function contrast(a, b) {
  const luminance = color => {
    let hex = color.trim().slice(1);
    if (hex.length === 3) hex = [...hex].map(c => c + c).join('');
    const rgb = hex.match(/../g).map(c => parseInt(c, 16) / 255)
      .map(c => c <= 0.04045 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4);
    return rgb[0] * .2126 + rgb[1] * .7152 + rgb[2] * .0722;
  };
  const values = [luminance(a), luminance(b)].sort((x, y) => y - x);
  return (values[0] + .05) / (values[1] + .05);
}
async function checkContrast() {
  const colors = await evaluate(`Object.fromEntries(['text','muted','accent','bg','surface','soft','accent-soft','control-line'].map(name => [name, getComputedStyle(document.documentElement).getPropertyValue('--' + name)]))`);
  for (const [fg, bg] of [['text','bg'], ['muted','bg'], ['accent','bg'], ['muted','surface'], ['text','soft'], ['accent','accent-soft'], ['bg','accent']]) {
    assert.ok(contrast(colors[fg], colors[bg]) >= 4.5, `${fg} on ${bg} text contrast is below 4.5:1`);
  }
  assert.ok(contrast(colors['control-line'], colors.surface) >= 3, 'Control outline contrast is below 3:1');
}
async function screenshot(name) {
  await delay(250); // Let theme transitions finish before capturing.
  const {data} = await call('Page.captureScreenshot', {format: 'png', captureBeyondViewport: false});
  await writeFile(path.join(artifacts, name + '.png'), Buffer.from(data, 'base64'));
}
try {
  child.on('error', error => errors.push(error.message));
  await until(async () => { try { return (await stat(path.join(profile, 'DevToolsActivePort'))).isFile(); } catch { return false; } }, 'Browser did not start: ' + browser);
  const port = (await readFile(path.join(profile, 'DevToolsActivePort'), 'utf8')).split('\n')[0];
  const targets = await (await fetch(`http://127.0.0.1:${port}/json/list`)).json();
  socket = new WebSocket(targets.find(target => target.type === 'page').webSocketDebuggerUrl);
  await new Promise((resolve, reject) => { socket.onopen = resolve; socket.onerror = reject; });
  socket.onmessage = event => {
    const message = JSON.parse(event.data);
    if (message.id && pending.has(message.id)) {
      const item = pending.get(message.id);
      pending.delete(message.id); clearTimeout(item.timeout);
      if (message.error) item.reject(new Error(JSON.stringify(message.error))); else item.resolve(message.result);
    } else if (message.method === 'Runtime.exceptionThrown') errors.push(JSON.stringify(message.params));
    else if (message.method === 'Network.responseReceived' && message.params.response.status >= 400)
      errors.push(`${message.params.response.status}: ${message.params.response.url}`);
  };
  await call('Page.enable'); await call('Runtime.enable'); await call('Network.enable');
  await call('Emulation.setDeviceMetricsOverride', {width: 1440, height: 1100, deviceScaleFactor: 1, mobile: false});
  await call('Emulation.setEmulatedMedia', {features: [{name: 'prefers-color-scheme', value: 'dark'}]});
  await go();
  assert.equal(await evaluate('document.documentElement.dataset.theme'), 'system');
  assert.equal(await evaluate('getComputedStyle(document.body).backgroundColor'), 'rgb(17, 19, 24)');
  await evaluate("document.querySelector('#theme').click()");
  assert.equal(await evaluate('document.documentElement.dataset.theme'), 'light');
  assert.equal(await evaluate('getComputedStyle(document.body).backgroundColor'), 'rgb(244, 245, 247)');
  await checkContrast();
  await screenshot('desktop-light');
  await evaluate("document.querySelector('#theme').click()");
  await go('getting-started/');
  assert.equal(await evaluate('document.documentElement.dataset.theme'), 'dark', 'Theme persists across navigation');
  await screenshot('desktop-guide');
  await go(); await checkContrast(); await screenshot('desktop-dark');
  await call('Browser.grantPermissions', {origin, permissions: ['clipboardReadWrite', 'clipboardSanitizedWrite']});
  await call('Page.bringToFront');
  const point = await evaluate("(() => {const r = document.querySelector('.copy').getBoundingClientRect(); return {x: r.x + r.width / 2, y: r.y + r.height / 2};})()");
  await call('Input.dispatchMouseEvent', {type: 'mousePressed', ...point, button: 'left', clickCount: 1});
  await call('Input.dispatchMouseEvent', {type: 'mouseReleased', ...point, button: 'left', clickCount: 1});
  await until(() => evaluate("document.querySelector('.copy').textContent === 'Copied'"), 'Copy did not finish');
  assert.equal(await evaluate('navigator.clipboard.readText()'), '.\\ysonet.exe -i');
  await call('Input.dispatchKeyEvent', {type: 'keyDown', key: '/', code: 'Slash'});
  await until(() => evaluate(`location.pathname === ${JSON.stringify(base + 'search/')} && document.readyState === 'complete'`), 'Search shortcut did not navigate');
  await call('Input.dispatchKeyEvent', {type: 'keyDown', key: '/', code: 'Slash'});
  assert.equal(await evaluate('document.activeElement.id'), 'search-query');
  await go('search/?q=installation');
  await until(() => evaluate("document.querySelectorAll('#search-results li').length > 0"), 'Search has no results');
  assert.ok(await evaluate("[...document.querySelectorAll('#search-results a')].some(a => a.href.endsWith('/getting-started/'))"));
  await evaluate("document.querySelector('#search-query').value = 'zzzz-no-result-xyz'; document.querySelector('#search-form').requestSubmit()");
  await until(() => evaluate("document.querySelector('#search-status').textContent.startsWith('No results')"), 'No-result state missing');
  await go('catalog/'); await screenshot('desktop-catalog');
  await go('catalog/?q=ObjectDataProvider&type=gadget&formatter=Json.Net');
  assert.ok(await evaluate("document.querySelectorAll('.module-card:not([hidden])').length < document.querySelectorAll('.module-card').length"));
  assert.ok(await evaluate("[...document.querySelectorAll('.module-card:not([hidden]) h2')].some(h => h.textContent === 'ObjectDataProvider')"));
  await evaluate("document.querySelector('#catalog-query').value='zzzz-no-result-xyz'; document.querySelector('#catalog-query').dispatchEvent(new Event('input'))");
  assert.equal(await evaluate("document.querySelector('#catalog-empty').hidden"), false);
  assert.ok(await evaluate("location.search.includes('zzzz-no-result-xyz')"));
  await go('catalog/plugin/viewstate/');
  assert.ok(await evaluate("document.querySelector('main h1').textContent === 'ViewState'"));
  await call('Emulation.setDeviceMetricsOverride', {width: 390, height: 1250, deviceScaleFactor: 1, mobile: true});
  await go();
  assert.equal(await evaluate("document.querySelector('.navigation').open"), false);
  assert.ok(await evaluate('document.documentElement.scrollWidth <= innerWidth'), 'Mobile home overflows');
  await screenshot('mobile-dark');
  await evaluate("document.querySelector('.navigation summary').click()");
  assert.equal(await evaluate("document.querySelector('.navigation').open"), true);
  await go('catalog/gadget/objectdataprovider/');
  assert.ok(await evaluate('document.documentElement.scrollWidth <= innerWidth'), 'Mobile module overflows');
  await screenshot('mobile-module');
  await go('getting-started/');
  assert.equal(await evaluate("document.querySelector('.contents').open"), false);
  await evaluate("document.querySelector('.contents summary').click()");
  assert.equal(await evaluate("document.querySelector('.contents').open"), true);
  assert.ok(await evaluate('document.documentElement.scrollWidth <= innerWidth'), 'Mobile guide overflows');
  // Test storage denial before page script executes.
  const {identifier} = await call('Page.addScriptToEvaluateOnNewDocument', {source: "Object.defineProperty(window, 'localStorage', {get(){throw new Error('blocked')}})"});
  await go();
  assert.equal(await evaluate('document.documentElement.dataset.theme'), 'system');
  await evaluate("document.querySelector('#theme').click()");
  assert.equal(await evaluate('document.documentElement.dataset.theme'), 'light');
  await call('Page.removeScriptToEvaluateOnNewDocument', {identifier});
  await call('Emulation.setScriptExecutionDisabled', {value: true});
  await go('catalog/');
  assert.ok(await evaluate("document.querySelectorAll('.module-card:not([hidden])').length > 50"));
  assert.equal(await evaluate("document.querySelector('.navigation').open"), true);
  assert.equal(await evaluate("document.querySelector('#theme').hidden"), true);
  await call('Emulation.setScriptExecutionDisabled', {value: false});
  assert.deepEqual(errors, [], 'Browser errors');
  console.log('PASS: text/control contrast, system/light/dark themes, persistence, blocked storage, copy, keyboard search, search, empty states, shared filters, module links, mobile layout/navigation, no-JavaScript reading; no browser errors.');
  console.log('Screenshots: temp/site-browser/');
} finally {
  if (socket?.readyState === WebSocket.OPEN) {
    try { await call('Browser.close'); } catch (_) { /* Process may already be closed. */ }
    socket.close();
  }
  child.kill();
  server.closeAllConnections(); server.close();
  for (const item of pending.values()) clearTimeout(item.timeout);
  // Chromium can retain handles briefly after Browser.close on Windows.
  await rm(profile, {recursive: true, force: true, maxRetries: 10, retryDelay: 200}).catch(() => {});
}
