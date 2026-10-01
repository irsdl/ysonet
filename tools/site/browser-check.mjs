// Behavioral parity against production Starlight and Pagefind output.
import assert from 'node:assert/strict';
import {chromium} from 'playwright';
import {mkdir, readFile, readdir} from 'node:fs/promises';
import path from 'node:path';
import {serve} from './serve.mjs';

const [directory = 'dist/site', base = '/', executablePath, liveOrigin] = process.argv.slice(2);
if (liveOrigin && new URL(liveOrigin).origin !== liveOrigin) throw new Error('Live origin must be an origin without a trailing slash or path');
const server = liveOrigin ? {origin: liveOrigin, close() {}} : await serve(directory, base);
const browser = await chromium.launch({headless: true, ...(executablePath ? {executablePath} : {channel: 'msedge'})});
const artifacts = 'temp/site-browser';
await mkdir(artifacts, {recursive: true});
const errors = [];
function observe(page) {
  page.on('pageerror', error => errors.push(error.message));
  page.on('response', response => { if (response.status() >= 400) errors.push(`HTTP ${response.status()}: ${response.url()}`); });
  page.on('request', request => { if (!request.url().startsWith(server.origin) && !request.url().startsWith('data:')) errors.push('External runtime request: ' + request.url()); });
}
const context = await browser.newContext({viewport: {width: 1440, height: 1000}, colorScheme: 'dark', permissions: ['clipboard-read', 'clipboard-write']});
const page = await context.newPage(); observe(page);
const go = route => page.goto(server.origin + base + route, {waitUntil: 'networkidle'});
const theme = () => page.locator('.project-header starlight-theme-select select');
const screenshot = name => page.screenshot({path: `${artifacts}/${name}.png`, fullPage: true});
async function checkSocialIcons(container) {
  const follow = page.locator(container).getByRole('link', {name: 'Follow @irsdl on X', exact: true});
  assert.ok(await follow.isVisible());
  assert.equal(await follow.getAttribute('title'), 'Follow @irsdl on X');
  assert.equal(await follow.getAttribute('href'), 'https://x.com/irsdl');
  assert.equal(await follow.locator('svg').count(), 1);
  assert.equal(await follow.evaluate(link => link.previousElementSibling?.getAttribute('href')), 'https://github.com/irsdl/ysonet');
  await follow.hover();
}
try {
  if (liveOrigin) {
    const expected = JSON.parse(await readFile(path.join(directory, 'revision.json')));
    const response = await context.request.get(server.origin + base + 'revision.json');
    assert.equal(response.status(), 200);
    assert.deepEqual(await response.json(), expected, 'Live deployment matches the tested checkout');
  }
  await go('');
  await checkSocialIcons('.project-header');
  assert.equal(await page.locator('html').getAttribute('data-theme'), 'dark');
  await theme().selectOption('light');
  assert.equal(await page.locator('html').getAttribute('data-theme'), 'light');
  await screenshot('desktop-light');
  await theme().selectOption('dark'); await go('getting-started/');
  assert.equal(await page.locator('html').getAttribute('data-theme'), 'dark', 'Theme persists');
  await screenshot('desktop-guide');
  await go(''); await screenshot('desktop-dark');
  await page.locator('.expressive-code .copy button').first().click();
  await page.waitForFunction(() => navigator.clipboard.readText().then(text => text === '.\\ysonet.exe -i'));
  assert.equal(await page.evaluate(() => navigator.clipboard.readText()), '.\\ysonet.exe -i');
  await page.keyboard.press('/'); await page.waitForURL('**/search/');
  await page.keyboard.press('/');
  assert.equal(await page.evaluate(() => document.activeElement.id), 'search-query');
  const catalog = JSON.parse(await readFile(path.join(directory, 'catalog/catalog.json')));
  const releases = (await readdir(path.join(directory, 'releases'))).filter(name => /^v\d/.test(name));
  for (const [query, target] of [['installation', 'getting-started/'], ['ObjectDataProvider', 'catalog/gadget/objectdataprovider/'], [releases.at(-1), `releases/${releases.at(-1)}/`]]) {
    await go('search/?q=' + encodeURIComponent(query));
    await page.waitForFunction(() => document.querySelectorAll('#search-results li').length > 0);
    assert.ok(await page.locator(`#search-results a[href$="/${target}"]`).count(), `Pagefind finds ${target}`);
  }
  await page.locator('#search-query').fill('zzzz-no-result-xyz');
  await page.locator('#search-form button').click();
  await page.waitForFunction(() => document.querySelector('#search-status').textContent.startsWith('No results'));
  await page.keyboard.press('Control+k');
  await page.locator('dialog[open] input').fill('ViewState');
  await page.locator('dialog[open] .pagefind-ui__result-link').first().waitFor();
  await page.keyboard.press('Escape');
  assert.equal(await page.locator('dialog[open]').count(), 0);
  await go('catalog/'); await screenshot('desktop-catalog');
  await go('catalog/?q=ObjectDataProvider&type=gadget&formatter=Json.Net');
  assert.ok(await page.locator('.module-card:not([hidden])').count() < catalog.gadgets.length + catalog.plugins.length);
  assert.ok(await page.locator('.module-card:not([hidden]) h2').allTextContents().then(names => names.includes('ObjectDataProvider')));
  await page.reload({waitUntil: 'networkidle'});
  assert.equal(await page.locator('#catalog-query').inputValue(), 'ObjectDataProvider');
  assert.equal(await page.locator('#catalog-kind').inputValue(), 'gadget');
  assert.equal(await page.locator('#catalog-formatter').inputValue(), 'Json.NET');
  await page.locator('#catalog-query').fill('zzzz-no-result-xyz');
  assert.ok(await page.locator('#catalog-empty').isVisible());
  assert.ok(page.url().includes('zzzz-no-result-xyz'));
  await page.goBack();
  assert.equal(await page.locator('#catalog-query').inputValue(), 'ObjectDataProvider');
  await page.goForward();
  assert.ok(await page.locator('#catalog-empty').isVisible());
  await go('catalog/plugin/viewstate/'); assert.equal(await page.locator('main h1').textContent(), 'ViewState');
  await page.setViewportSize({width: 390, height: 1000});
  await go(''); await screenshot('mobile-dark');
  const menu = page.locator('starlight-menu-button');
  assert.notEqual(await menu.getAttribute('aria-expanded'), 'true');
  await menu.locator('button').click(); assert.equal(await menu.getAttribute('aria-expanded'), 'true');
  await checkSocialIcons('.mobile-preferences');
  await page.keyboard.press('Escape'); assert.equal(await menu.getAttribute('aria-expanded'), 'false');
  for (const route of ['catalog/gadget/objectdataprovider/', 'getting-started/']) {
    await go(route);
    assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), 'Mobile page overflows');
    await screenshot(route.startsWith('catalog') ? 'mobile-module' : 'mobile-guide');
  }
  const toc = page.locator('#starlight__mobile-toc');
  assert.equal(await toc.getAttribute('open'), null);
  await toc.locator('summary').click(); assert.notEqual(await toc.getAttribute('open'), null);
  const blocked = await browser.newContext({colorScheme: 'dark', viewport: {width: 1440, height: 1000}});
  await blocked.addInitScript(() => Object.defineProperty(window, 'localStorage', {get() { throw new Error('blocked'); }}));
  const denied = await blocked.newPage(); observe(denied);
  await denied.goto(server.origin + base, {waitUntil: 'networkidle'});
  assert.equal(await denied.locator('html').getAttribute('data-theme'), 'dark');
  await denied.locator('.project-header starlight-theme-select select').selectOption('light');
  assert.equal(await denied.locator('html').getAttribute('data-theme'), 'light');
  await blocked.close();
  await page.emulateMedia({reducedMotion: 'no-preference'});
  await go('logo/');
  const logoLoaded = extension => page.waitForFunction(extension => {
    const image = document.querySelector('.logo-animation img');
    return image?.src.endsWith(extension) && image.complete && image.naturalWidth > 0;
  }, extension);
  await logoLoaded('.gif');
  await page.getByRole('button', {name: 'Pause logo animation', exact: true}).click();
  await logoLoaded('.svg');
  await page.getByRole('button', {name: 'Play logo animation', exact: true}).click();
  await logoLoaded('.gif');
  await page.emulateMedia({reducedMotion: 'reduce'});
  await logoLoaded('.svg');
  await go('logo/');
  await logoLoaded('.svg');
  assert.ok(await page.getByRole('button', {name: 'Play logo animation', exact: true}).isVisible());
  await page.emulateMedia({reducedMotion: 'no-preference'});
  // A successful HTTP response can still contain an unsupported/corrupt image.
  await page.route('**/assets/ysonet-symbol.gif', route => route.fulfill({status: 200, contentType: 'image/gif', body: 'invalid GIF'}));
  await go('logo/');
  await logoLoaded('.svg');
  assert.equal(await page.locator('.logo-animation button').count(), 0);
  await page.unroute('**/assets/ysonet-symbol.gif');
  const plain = await browser.newContext({javaScriptEnabled: false, viewport: {width: 390, height: 1000}});
  const nojs = await plain.newPage(); observe(nojs);
  await nojs.goto(server.origin + base + 'catalog/');
  assert.equal(await nojs.locator('.module-card:not([hidden])').count(), catalog.gadgets.length + catalog.plugins.length);
  assert.ok(await nojs.locator('noscript').innerText().then(text => text.includes('Find')));
  assert.ok(await nojs.locator('.sidebar-pane').isVisible());
  assert.equal(await nojs.locator('starlight-theme-select:visible').count(), 0);
  await nojs.goto(server.origin + base + 'catalog/gadget/objectdataprovider/');
  assert.ok(await nojs.locator('main').innerText().then(text => text.includes('Declared metadata')));
  await nojs.goto(server.origin + base + 'logo/');
  assert.ok((await nojs.locator('.logo-animation img').getAttribute('src')).endsWith('.svg'));
  assert.ok(await nojs.locator('.logo-animation img').evaluate(image => image.complete && image.naturalWidth > 0));
  assert.equal(await nojs.locator('.logo-animation button').count(), 0);
  await plain.close();
  assert.deepEqual(errors, [], 'Browser errors or external runtime requests');
  console.log('PASS: themes, persistence, blocked storage, exact copy, keyboard/modal/guide/module/release search, empty states, catalog query/reload/back/forward, mobile menus/TOC, logo animation/pause/reduced-motion/error fallback, no-JavaScript reading; no browser errors or external runtime requests.');
} finally { await browser.close(); server.close(); }
