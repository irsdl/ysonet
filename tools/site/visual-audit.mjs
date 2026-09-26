// Playwright visual and layout audit. Screenshots are review artifacts, not a proof of design quality.
import {chromium, firefox, webkit} from 'playwright';
import {createServer} from 'node:http';
import {readFile, writeFile, mkdir, readdir} from 'node:fs/promises';
import path from 'node:path';

const args = {};
for (let i = 2; i < process.argv.length; i += 2) args[process.argv[i].replace(/^--/, '')] = process.argv[i + 1];
const site = path.resolve(args.site || 'dist/site');
const base = args.base || '/ysonet/';
const report = path.resolve(args.report || 'temp/site-visual');
const engine = args.engine || 'chromium';
const widths = (args.widths || '320,390,768,1440').split(',').map(Number);
const themes = (args.themes || 'light,dark').split(',');
const failures = [], results = [];
const routes = [];
async function discover(folder) {
  for (const entry of await readdir(folder, {withFileTypes: true})) {
    const file = path.join(folder, entry.name);
    if (entry.isDirectory()) await discover(file);
    else if (entry.name.endsWith('.html')) {
      let route = path.relative(site, file).replaceAll(path.sep, '/');
      if (route.endsWith('index.html')) route = route.slice(0, -10);
      routes.push(route);
    }
  }
}
await discover(site);
routes.sort();
if (args.routes) {
  const selected = args.routes.split(',');
  const matches = routes.filter(route => selected.includes(route));
  if (matches.length !== selected.length) throw new Error('Unknown route in --routes');
  routes.splice(0, routes.length, ...matches);
}
await mkdir(report, {recursive: true});
const mime = {'.html': 'text/html; charset=utf-8', '.css': 'text/css', '.js': 'text/javascript', '.json': 'application/json', '.svg': 'image/svg+xml', '.xml': 'application/xml'};
const server = createServer(async (request, response) => {
  try {
    const url = new URL(request.url, 'http://localhost');
    if (!url.pathname.startsWith(base)) throw new Error('Outside site');
    let relative = decodeURIComponent(url.pathname.slice(base.length));
    if (!relative || relative.endsWith('/')) relative += 'index.html';
    const file = path.resolve(site, relative);
    if (!file.startsWith(site + path.sep)) throw new Error('Outside site');
    response.setHeader('Content-Type', mime[path.extname(file)] || 'application/octet-stream');
    response.end(await readFile(file));
  } catch { response.writeHead(404); response.end('Not found'); }
});
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
const origin = `http://127.0.0.1:${server.address().port}`;
const measure = () => {
  const issues = [];
  const visible = el => el.getClientRects().length > 0 && getComputedStyle(el).visibility !== 'hidden';
  const label = el => el.tagName.toLowerCase() + (el.id ? '#' + el.id : '.' + [...el.classList].join('.')) + ': ' + (el.textContent || '').trim().slice(0, 75);
  const parse = color => (color.match(/[\d.]+/g) || []).map(Number);
  const luminance = rgb => rgb.slice(0, 3).map(c => c / 255).map(c => c <= .04045 ? c / 12.92 : ((c + .055) / 1.055) ** 2.4).reduce((sum, c, i) => sum + c * [.2126, .7152, .0722][i], 0);
  const background = el => {
    for (let parent = el; parent; parent = parent.parentElement) {
      const rgba = parse(getComputedStyle(parent).backgroundColor);
      if (rgba.length === 3 || rgba[3] === 1) return rgba;
    }
    return [255, 255, 255];
  };
  if (document.documentElement.scrollWidth > innerWidth + 1) issues.push(`Page overflows: ${document.documentElement.scrollWidth}px > ${innerWidth}px`);
  const h1s = [...document.querySelectorAll('h1')].filter(visible);
  if (h1s.length !== 1) issues.push(`Expected one visible page heading, got ${h1s.length}`);
  for (const container of ['.site-header', '.site-footer']) {
    const links = [...document.querySelectorAll(container + ' a[href="https://x.com/irsdl"]')].filter(visible);
    if (links.length !== 1) issues.push(`Missing visible X follow link in ${container}`);
  }
  let minimumFont = Infinity, minimumContrast = Infinity;
  for (const el of document.querySelectorAll('h1,h2,h3,p,li,a,button,label,summary,small,span,td,th,code,input,select')) {
    if (!visible(el) || !([...el.childNodes].some(n => n.nodeType === 3 && n.textContent.trim()) || el.matches('input,select'))) continue;
    const css = getComputedStyle(el);
    const size = parseFloat(css.fontSize);
    minimumFont = Math.min(minimumFont, size);
    if (size < 12 - .01) issues.push(`Small text (${size.toFixed(1)}px): ${label(el)}`);
    const fg = parse(css.color), bg = background(el);
    if (fg.length < 3) continue;
    const [light, dark] = [luminance(fg), luminance(bg)].sort((a, b) => b - a);
    const ratio = (light + .05) / (dark + .05);
    minimumContrast = Math.min(minimumContrast, ratio);
    const threshold = size >= 24 || (size >= 18.66 && parseFloat(css.fontWeight) >= 700) ? 3 : 4.5;
    if (ratio + .01 < threshold) issues.push(`Text contrast ${ratio.toFixed(2)}:1: ${label(el)}`);
  }
  const controls = [...document.querySelectorAll('.site-header a,.site-header button,.navigation a,.site-footer a')].filter(visible);
  for (let i = 0; i < controls.length; i++) {
    const a = controls[i].getBoundingClientRect();
    if (a.width < 24 || a.height < 24) issues.push(`Small navigation target: ${label(controls[i])}`);
    for (const other of controls.slice(i + 1)) {
      const b = other.getBoundingClientRect();
      if (Math.min(a.right, b.right) - Math.max(a.left, b.left) > 2 && Math.min(a.bottom, b.bottom) - Math.max(a.top, b.top) > 2)
        issues.push(`Overlapping controls: ${label(controls[i])} / ${label(other)}`);
    }
  }
  return {issues: [...new Set(issues)], minimumFont, minimumContrast, height: document.documentElement.scrollHeight,
    title: document.querySelector('h1')?.textContent, bodyFont: getComputedStyle(document.body).fontFamily};
};
const jobs = widths.flatMap(width => themes.map(theme => ({width, theme})));
let done = 0;
const browser = await ({chromium, firefox, webkit}[engine]).launch({headless: true, ...(args.channel ? {channel: args.channel} : {})});
try {
  async function worker() {
    while (jobs.length) {
      const {width, theme} = jobs.shift();
      const height = width < 600 ? 900 : 1050;
      const context = await browser.newContext({viewport: {width, height}, colorScheme: theme, deviceScaleFactor: 1, reducedMotion: 'reduce'});
      const page = await context.newPage();
      const folder = `${engine}-${width}-${theme}`;
      await mkdir(path.join(report, folder), {recursive: true});
      let network = [];
      page.on('pageerror', error => network.push('Script error: ' + error.message));
      page.on('response', response => { if (response.status() >= 400) network.push(`HTTP ${response.status()}: ${response.url()}`); });
      for (const route of routes) {
        network = [];
        const result = {engine, width, theme, route};
        try {
          await page.goto(origin + base + route, {waitUntil: 'networkidle', timeout: 15000});
          await page.evaluate(() => document.fonts.ready);
          Object.assign(result, await page.evaluate(measure));
          const name = (route || 'home').replaceAll('/', '_').replaceAll('.html', '');
          result.screenshot = `${folder}/${name}.png`;
          // Full page captures cover content below the first viewport as well.
          // Firefox and WebKit cap bitmap dimensions at 32767px. Tile long documents.
          if (result.height <= 30000) {
            await page.screenshot({path: path.join(report, result.screenshot), fullPage: true, animations: 'disabled'});
          } else {
            result.tiles = [];
            await page.setViewportSize({width, height: 16000});
            for (let y = 0; y < result.height; y += 16000) {
              const tile = `${folder}/${name}-${y}.png`;
              await page.evaluate(y => scrollTo(0, y), y);
              await page.screenshot({path: path.join(report, tile), animations: 'disabled'});
              result.tiles.push(tile);
            }
            result.screenshot = result.tiles[0];
            await page.setViewportSize({width, height});
            await page.evaluate(() => scrollTo(0, 0));
          }
          // Hidden variant/options tables must also fit when the reader opens them.
          await page.locator('.page-content details').evaluateAll(nodes => nodes.forEach(node => { node.open = true; }));
          const expanded = await page.evaluate(measure);
          result.issues = [...new Set([...result.issues, ...expanded.issues, ...network])];
          if (result.issues.length) failures.push(result);
        } catch (error) { result.issues = [error.message]; failures.push(result); }
        if (result.issues.length) console.log(JSON.stringify({route, width, theme, issues: result.issues}));
        results.push(result);
        done++;
        if (done % 25 === 0) console.log(`${engine}: ${done}/${routes.length * widths.length * themes.length} page/theme/viewport checks; ${failures.length} cases with findings`);
      }
      await context.close();
    }
  }
  await Promise.all([worker(), worker()]);
} finally { await browser.close(); server.closeAllConnections(); server.close(); }
const escape = value => String(value).replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('"', '&quot;');
await writeFile(path.join(report, 'audit.json'), JSON.stringify({engine, browserVersion: browser.version(), routes: routes.length, cases: results.length, failures, results}, null, 2));
const figures = results.map(result => `<article><h2>${escape(result.route || '/')}</h2><p>${result.width}px / ${result.theme} / ${result.issues.length ? result.issues.length + ' findings' : 'checks passed'}</p><a href="${escape(result.screenshot || '')}"><img loading="lazy" src="${escape(result.screenshot || '')}" alt="${escape(result.route || 'Home')} screenshot"></a>${(result.tiles || []).map(tile => `<a href="${escape(tile)}">Page segment</a> `).join('')}${result.issues.length ? '<pre>' + escape(result.issues.join('\n')) + '</pre>' : ''}</article>`).join('');
await writeFile(path.join(report, 'index.html'), `<!doctype html><html lang="en"><meta charset="utf-8"><title>YSoNet visual audit</title><style>body{font:14px system-ui;margin:30px;background:#eee;color:#111}section{display:grid;grid-template-columns:repeat(auto-fill,minmax(270px,1fr));gap:20px}article{background:white;padding:15px;min-width:0}h2{font-size:14px;overflow-wrap:anywhere}img{width:100%;height:400px;object-fit:cover;object-position:top}pre{white-space:pre-wrap;font-size:11px}</style><h1>YSoNet visual audit</h1><p>${results.length} cases / ${failures.length} with findings. Open a screenshot to inspect the full page. Automated checks complement visual review.</p><section>${figures}</section></html>`);
console.log(`VISUAL AUDIT: ${routes.length} pages, ${results.length} cases, ${failures.length} cases with findings. Report: ${report}`);
process.exitCode = failures.length ? 1 : 0;
