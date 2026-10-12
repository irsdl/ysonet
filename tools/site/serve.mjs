import {createServer} from 'node:http';
import {readFile} from 'node:fs/promises';
import path from 'node:path';

export async function serve(directory, base = '/') {
  const root = path.resolve(directory);
  const mime = {'.html': 'text/html; charset=utf-8', '.css': 'text/css', '.js': 'text/javascript',
    '.json': 'application/json', '.svg': 'image/svg+xml', '.xml': 'application/xml', '.wasm': 'application/wasm'};
  const server = createServer(async (request, response) => {
    try {
      const url = new URL(request.url, 'http://localhost');
      if (!url.pathname.startsWith(base)) throw new Error('Outside base');
      let relative = decodeURIComponent(url.pathname.slice(base.length));
      if (!relative || relative.endsWith('/')) relative += 'index.html';
      const file = path.resolve(root, relative);
      if (!file.startsWith(root + path.sep)) throw new Error('Outside output');
      response.setHeader('Content-Type', mime[path.extname(file)] || 'application/octet-stream');
      response.end(await readFile(file));
    } catch { response.writeHead(404); response.end('Not found'); }
  });
  // Chromium blocks some ports even on loopback (including 10080, which an
  // ephemeral bind can receive on this test host). Use a small known-safe range
  // and move to the next port when another local check already owns one.
  let listening = false;
  for (let port = 18080; port < 18180; port++) {
    try {
      await new Promise((resolve, reject) => {
        const failed = error => reject(error);
        server.once('error', failed);
        server.listen(port, '127.0.0.1', () => {
          server.off('error', failed);
          resolve();
        });
      });
      listening = true;
      break;
    } catch (error) {
      if (error.code !== 'EADDRINUSE') throw error;
    }
  }
  if (!listening) throw new Error('No local preview port is available.');
  return {origin: `http://127.0.0.1:${server.address().port}`, close() { server.closeAllConnections(); server.close(); }};
}
