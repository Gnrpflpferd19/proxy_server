// Restricted URL-fetch backend for the Chat Proxy demo.
// This is intentionally NOT an unrestricted/open proxy.
const http = require('node:http');
const https = require('node:https');
const dns = require('node:dns').promises;
const { URL } = require('node:url');

const PORT = Number(process.env.PORT || 8787);
const ALLOWED_HOSTS = new Set(
  (process.env.ALLOWED_HOSTS || 'example.com,www.example.com,httpbin.org').split(',')
    .map((s) => s.trim().toLowerCase()).filter(Boolean)
);
const MAX_BYTES = 1_000_000;
const TIMEOUT_MS = 8000;

function send(res, status, data, extraHeaders = {}) {
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'access-control-allow-origin': process.env.FRONTEND_ORIGIN || '*',
    'access-control-allow-methods': 'GET, OPTIONS',
    'access-control-allow-headers': 'content-type',
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff',
    ...extraHeaders,
  });
  res.end(JSON.stringify(data));
}

function isPrivateIPv4(ip) {
  const p = ip.split('.').map(Number);
  if (p.length !== 4 || p.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return true;
  return p[0] === 10 || p[0] === 127 || p[0] === 0 ||
    (p[0] === 169 && p[1] === 254) || (p[0] === 172 && p[1] >= 16 && p[1] <= 31) ||
    (p[0] === 192 && p[1] === 168) || p[0] >= 224;
}

async function validateTarget(raw) {
  let u;
  try { u = new URL(raw); } catch { throw new Error('Bitte eine gültige URL eingeben.'); }
  if (u.protocol !== 'https:') throw new Error('Nur HTTPS-Ziele sind erlaubt.');
  if (u.username || u.password) throw new Error('URLs mit eingebetteten Zugangsdaten sind nicht erlaubt.');
  const host = u.hostname.toLowerCase().replace(/\.$/, '');
  if (!ALLOWED_HOSTS.has(host)) throw new Error(`Diese Domain ist nicht freigegeben: ${host}`);
  const records = await dns.lookup(host, { all: true, verbatim: true });
  if (!records.length || records.some((r) => r.family === 4 && isPrivateIPv4(r.address)) ||
      records.some((r) => r.family === 6 && (r.address === '::1' || r.address.startsWith('fc') || r.address.startsWith('fd') || r.address.startsWith('fe80:')))) {
    throw new Error('Das Ziel ist nicht erlaubt.');
  }
  return u;
}

async function fetchAllowed(raw, redirects = 0) {
  if (redirects > 3) throw new Error('Zu viele Weiterleitungen.');
  const u = await validateTarget(raw);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  try {
    const response = await fetch(u, {
      method: 'GET', redirect: 'manual', signal: controller.signal,
      headers: { 'user-agent': 'ChatProxy-Restricted-Demo/1.0', accept: 'text/html,text/plain,application/json;q=0.8' },
    });
    if ([301, 302, 303, 307, 308].includes(response.status)) {
      const location = response.headers.get('location');
      if (!location) throw new Error('Weiterleitung ohne Ziel.');
      return fetchAllowed(new URL(location, u).toString(), redirects + 1);
    }
    const type = (response.headers.get('content-type') || '').toLowerCase();
    if (!response.ok) throw new Error(`Zielwebsite antwortete mit HTTP ${response.status}.`);
    if (!(type.includes('text/html') || type.includes('text/plain') || type.includes('application/json'))) {
      throw new Error('Dieser Dateityp wird nicht angezeigt.');
    }
    const reader = response.body.getReader();
    const chunks = [];
    let total = 0;
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > MAX_BYTES) { await reader.cancel(); throw new Error('Die Antwort ist zu gross (Limit: 1 MB).'); }
      chunks.push(value);
    }
    const body = Buffer.concat(chunks).toString('utf8');
    return { url: u.toString(), status: response.status, contentType: type.split(';')[0], body };
  } finally { clearTimeout(timer); }
}

const server = http.createServer(async (req, res) => {
  if (req.method === 'OPTIONS') {
    res.writeHead(204, {
      'access-control-allow-origin': process.env.FRONTEND_ORIGIN || '*',
      'access-control-allow-methods': 'GET, OPTIONS',
      'access-control-allow-headers': 'content-type',
    });
    return res.end();
  }
  const pathname = new URL(req.url, `http://${req.headers.host || 'localhost'}`).pathname;
  if (pathname === '/health') return send(res, 200, { ok: true, service: 'chat-proxy-restricted', allowedHosts: [...ALLOWED_HOSTS] });
  if (pathname !== '/api/fetch') return send(res, 404, { error: 'Not found' });
  if (req.method !== 'GET') return send(res, 405, { error: 'Only GET is supported.' });
  const query = new URL(req.url, `http://${req.headers.host || 'localhost'}`).searchParams;
  const target = query.get('url');
  if (!target || target.length > 2048) return send(res, 400, { error: 'URL fehlt oder ist zu lang.' });
  try {
    const result = await fetchAllowed(target);
    return send(res, 200, result);
  } catch (err) {
    const message = err.name === 'AbortError' ? 'Zeitüberschreitung beim Abruf.' : (err.message || 'Abruf fehlgeschlagen.');
    return send(res, 400, { error: message });
  }
});
server.listen(PORT, '0.0.0.0', () => console.log(`Restricted proxy backend listening on ${PORT}`));
