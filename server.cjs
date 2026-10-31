const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const root = path.join(__dirname, process.argv[2]);
const port = Number(process.argv[3]);
if (!['studio', 'planner'].includes(process.argv[2]) || !port) throw new Error('Usage: node server.cjs studio|planner PORT');
http.createServer((req, res) => {
  const url = new URL(req.url, 'http://localhost');
  const send = (type, body, status = 200) => { res.writeHead(status, { 'Content-Type': type + '; charset=utf-8' }); res.end(body); };
  if (url.pathname === '/robots.txt') return send('text/plain', 'User-agent: *\nAllow: /\nSitemap: /sitemap.xml\n');
  if (url.pathname === '/sitemap.xml') {
    const host = /^[a-zA-Z0-9.\-]+(?::\d+)?$/.test(req.headers.host || '') ? req.headers.host : `localhost:${port}`;
    const origin = `http://${host}`;
    return send('application/xml', '<?xml version="1.0"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">' + ['/', '/inputs', '/search', '/contact', '/preferences'].map(route => `<url><loc>${origin}${route}</loc></url>`).join('') + '</urlset>');
  }
  if (url.pathname === '/inputs') return send('text/html', fs.readFileSync(path.join(__dirname, 'crawl-inputs.html'), 'utf8'));
  if (['/search', '/contact', '/preferences'].includes(url.pathname)) {
    if (!['GET', 'POST'].includes(req.method)) return send('text/plain', 'Method not allowed', 405);
    // Consume demo submissions without storing or reflecting user input.
    let size = 0;
    req.on('data', chunk => { size += chunk.length; if (size > 65536) req.destroy(); });
    req.on('end', () => send('text/html', '<!doctype html><html lang="en"><meta charset="utf-8"><title>Demo endpoint</title><h1>Demo request received</h1><p>No data was stored.</p><a href="/inputs">Back to input examples</a> · <a href="/">Home</a></html>'));
    return;
  }
  if (url.pathname !== '/' && url.pathname !== '/index.html') return send('text/plain', 'Not found', 404);
  const html = fs.readFileSync(path.join(root, 'index.html'), 'utf8');
  send('text/html', html.replace('</body>', '<p style="padding:20px;text-align:center"><a href="/inputs">Explore demo forms and inputs ↗</a></p></body>'));
}).listen(port, '0.0.0.0', () => console.log(`${process.argv[2]} listening on 0.0.0.0:${port}`));
