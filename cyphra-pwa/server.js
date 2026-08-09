/**
 * server.js — Simple static server for the Cyphra PWA
 * Serves on 0.0.0.0:3002 so iPhone can access via LAN IP.
 *
 * Usage: node server.js
 */

const http  = require('http');
const fs    = require('fs');
const path  = require('path');

const PORT = 3002;
const ROOT = __dirname;

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js':   'application/javascript; charset=utf-8',
  '.css':  'text/css; charset=utf-8',
  '.json': 'application/json',
  '.png':  'image/png',
  '.ico':  'image/x-icon',
  '.webp': 'image/webp',
};

const server = http.createServer((req, res) => {
  let urlPath = req.url.split('?')[0];
  if (urlPath === '/') urlPath = '/index.html';

  const filePath = path.join(ROOT, urlPath);
  const ext = path.extname(filePath);

  fs.readFile(filePath, (err, data) => {
    if (err) {
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      res.end('Not found: ' + urlPath);
      return;
    }
    res.writeHead(200, {
      'Content-Type': MIME[ext] || 'application/octet-stream',
      // Allow service worker scope
      'Service-Worker-Allowed': '/',
      // Required for standalone PWA installs from HTTP (LAN only)
      'Cache-Control': 'no-cache',
    });
    res.end(data);
  });

  console.log(`${req.method} ${urlPath}`);
});

// Detect LAN IP to show to user
const os = require('os');
function getLanIp() {
  const interfaces = os.networkInterfaces();
  for (const name of Object.keys(interfaces)) {
    for (const iface of interfaces[name]) {
      if (iface.family === 'IPv4' && !iface.internal) return iface.address;
    }
  }
  return 'localhost';
}

server.listen(PORT, '0.0.0.0', () => {
  const lan = getLanIp();
  console.log('\n╔══════════════════════════════════════════╗');
  console.log('║        CYPHRA PWA SERVER RUNNING         ║');
  console.log('╠══════════════════════════════════════════╣');
  console.log(`║  Local:   http://localhost:${PORT}          ║`);
  console.log(`║  iPhone:  http://${lan}:${PORT}      ║`);
  console.log('╠══════════════════════════════════════════╣');
  console.log('║  On iPhone: open Safari → visit URL above║');
  console.log('║  then tap Share → Add to Home Screen     ║');
  console.log('╚══════════════════════════════════════════╝\n');
});
