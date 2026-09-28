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
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  return {origin: `http://127.0.0.1:${server.address().port}`, close() { server.closeAllConnections(); server.close(); }};
}
