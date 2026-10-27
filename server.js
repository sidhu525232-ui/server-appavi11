// ====================================================================
// APPAVI KEY SERVER  -  licence keys: 7 days / 15 days / 30 days / lifetime
//  * one key = one device (bound on first activation)
//  * admin website: generate keys, expire / restore, reset device, extend, delete
//  * zero npm dependencies (plain Node 18+)
//
//  Run:   ADMIN_PASSWORD="your-strong-password" node server.js
//  Port:  PORT=8787 (default)
// ====================================================================
'use strict';
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = parseInt(process.env.PORT || '8787', 10);
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const DB_FILE = path.join(DATA_DIR, 'keys.json');
const SECRET_FILE = path.join(DATA_DIR, 'secret.key');
const PW_FILE = path.join(DATA_DIR, 'admin-password.txt');
const DAY = 86400000;
const PLANS = { '7': 7, '15': 15, '30': 30, 'lifetime': null };

fs.mkdirSync(DATA_DIR, { recursive: true });

// ---------- secrets ----------
function readOrCreate(file, make) {
  if (fs.existsSync(file)) return fs.readFileSync(file, 'utf8').trim();
  const v = make(); fs.writeFileSync(file, v + '\n', { mode: 0o600 }); return v;
}
const SECRET = readOrCreate(SECRET_FILE, () => crypto.randomBytes(32).toString('hex'));
let ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
if (!ADMIN_PASSWORD) {
  const existed = fs.existsSync(PW_FILE);
  ADMIN_PASSWORD = readOrCreate(PW_FILE, () => crypto.randomBytes(9).toString('base64url'));
  console.log(existed ? `[admin] password is in ${PW_FILE}` : `[admin] generated admin password: ${ADMIN_PASSWORD}   (saved in ${PW_FILE})`);
}

// ---------- tiny JSON database ----------
let db = { keys: [] };
if (fs.existsSync(DB_FILE)) { try { db = JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); } catch (e) { console.error('keys.json unreadable', e); process.exit(1); } }
function save() {
  const tmp = DB_FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(db, null, 2));
  fs.renameSync(tmp, DB_FILE);
}

// ---------- helpers ----------
const ALPHABET = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';   // no 0/O/1/I/L
function genKey() {
  const grp = () => Array.from(crypto.randomBytes(5), (b) => ALPHABET[b % ALPHABET.length]).join('');
  return `APPAVI-${grp()}-${grp()}-${grp()}`;
}
function sameStr(a, b) {
  const A = Buffer.from(String(a)), B = Buffer.from(String(b));
  return A.length === B.length && crypto.timingSafeEqual(A, B);
}
function status(k, now = Date.now()) {
  if (k.revoked) return 'revoked';
  if (k.expiresAt && now >= k.expiresAt) return 'expired';
  if (k.deviceId) return 'active';
  return k.activatedAt ? 'unbound' : 'unused';      // unbound = admin reset the device, waiting for a new one
}
function publicKey(k) {
  return Object.assign({}, k, { status: status(k) });
}
function signToken(ttlMs) {
  const body = Buffer.from(JSON.stringify({ exp: Date.now() + ttlMs })).toString('base64url');
  const sig = crypto.createHmac('sha256', SECRET).update(body).digest('base64url');
  return `${body}.${sig}`;
}
function checkToken(tok) {
  if (!tok) return false;
  const [body, sig] = String(tok).split('.');
  if (!body || !sig) return false;
  const good = crypto.createHmac('sha256', SECRET).update(body).digest('base64url');
  if (!sameStr(sig, good)) return false;
  try { return JSON.parse(Buffer.from(body, 'base64url').toString()).exp > Date.now(); } catch (e) { return false; }
}

// ---------- rate limiting (in memory) ----------
const fails = new Map();
function limited(bucket, ip, max, windowMs) {
  const k = bucket + ip, now = Date.now();
  const arr = (fails.get(k) || []).filter((t) => now - t < windowMs);
  fails.set(k, arr);
  return arr.length >= max;
}
function noteFail(bucket, ip) { const k = bucket + ip; (fails.get(k) || fails.set(k, []).get(k)).push(Date.now()); }
setInterval(() => { const now = Date.now(); for (const [k, v] of fails) { const a = v.filter((t) => now - t < 3600000); a.length ? fails.set(k, a) : fails.delete(k); } }, 600000).unref();

// ---------- http plumbing ----------
function send(res, code, obj, extra) {
  const body = JSON.stringify(obj);
  res.writeHead(code, Object.assign({
    'Content-Type': 'application/json; charset=utf-8',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
    'Cache-Control': 'no-store'
  }, extra));
  res.end(body);
}
function readBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0; const chunks = [];
    req.on('data', (c) => { size += c.length; if (size > 20000) { reject(new Error('too large')); req.destroy(); } else chunks.push(c); });
    req.on('end', () => { try { resolve(chunks.length ? JSON.parse(Buffer.concat(chunks).toString()) : {}); } catch (e) { reject(new Error('bad json')); } });
    req.on('error', reject);
  });
}
function clientIp(req) { return (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || req.socket.remoteAddress || '?'; }
function isAdmin(req) { const h = req.headers.authorization || ''; return h.startsWith('Bearer ') && checkToken(h.slice(7)); }

function findKey(raw) {
  const key = String(raw || '').trim().toUpperCase();
  return db.keys.find((k) => sameStr(k.key, key));
}

// ---------- licence API (called by the extension) ----------
function evaluate(k, deviceId, bindIfFree) {
  const now = Date.now();
  if (!k) return { ok: false, message: 'INVALID KEY' };
  if (k.revoked) return { ok: false, message: 'KEY EXPIRED BY ADMIN' };
  if (k.expiresAt && now >= k.expiresAt) return { ok: false, message: 'KEY EXPIRED' };
  if (!k.deviceId) {
    if (!bindIfFree) return { ok: false, message: 'KEY NOT ACTIVATED ON THIS DEVICE' };
    k.deviceId = deviceId;
    if (!k.activatedAt) { k.activatedAt = now; k.expiresAt = k.days ? now + k.days * DAY : null; }   // clock starts ONCE
  } else if (!sameStr(k.deviceId, deviceId)) {
    return { ok: false, message: 'KEY ALREADY USED ON ANOTHER DEVICE' };
  }
  k.lastSeen = now;
  return { ok: true, plan: k.plan, expiresAt: k.expiresAt || null };
}

async function handleApi(req, res, url) {
  const ip = clientIp(req);
  if (req.method === 'OPTIONS') return send(res, 204, {});

  // ----- extension endpoints -----
  if (req.method === 'POST' && (url.pathname === '/api/activate' || url.pathname === '/api/verify')) {
    if (limited('act', ip, 25, 10 * 60000)) return send(res, 429, { ok: false, message: 'TOO MANY TRIES - WAIT 10 MIN' });
    const b = await readBody(req);
    const deviceId = String(b.deviceId || '');
    if (!/^[a-f0-9]{64}$/.test(deviceId)) return send(res, 400, { ok: false, message: 'BAD DEVICE ID' });
    const k = findKey(b.key);
    const r = evaluate(k, deviceId, url.pathname === '/api/activate');
    if (!r.ok) { if (!k || url.pathname === '/api/activate') noteFail('act', ip); return send(res, 200, r); }
    save();
    return send(res, 200, r);
  }

  // ----- admin login -----
  if (req.method === 'POST' && url.pathname === '/api/admin/login') {
    if (limited('login', ip, 6, 15 * 60000)) return send(res, 429, { ok: false, message: 'TOO MANY ATTEMPTS - WAIT 15 MIN' });
    const b = await readBody(req);
    if (!sameStr(b.password || '', ADMIN_PASSWORD)) { noteFail('login', ip); return send(res, 401, { ok: false, message: 'WRONG PASSWORD' }); }
    return send(res, 200, { ok: true, token: signToken(12 * 3600000) });
  }

  // ----- admin endpoints -----
  if (url.pathname.startsWith('/api/admin/')) {
    if (!isAdmin(req)) return send(res, 401, { ok: false, message: 'LOGIN REQUIRED' });

    if (req.method === 'GET' && url.pathname === '/api/admin/keys') {
      return send(res, 200, { ok: true, now: Date.now(), keys: db.keys.map(publicKey).sort((a, b) => b.createdAt - a.createdAt) });
    }
    if (req.method === 'POST' && url.pathname === '/api/admin/keys') {
      const b = await readBody(req);
      const plan = String(b.plan);
      if (!(plan in PLANS)) return send(res, 400, { ok: false, message: 'plan must be 7, 15, 30 or lifetime' });
      const count = Math.min(200, Math.max(1, parseInt(b.count || 1, 10)));
      const note = String(b.note || '').slice(0, 120);
      const out = [];
      for (let i = 0; i < count; i++) {
        let key; do { key = genKey(); } while (db.keys.some((k) => k.key === key));
        const rec = { id: crypto.randomUUID(), key, plan, days: PLANS[plan], note, createdAt: Date.now(),
                      revoked: false, deviceId: null, activatedAt: null, expiresAt: null, lastSeen: null };
        db.keys.push(rec); out.push(publicKey(rec));
      }
      save();
      return send(res, 200, { ok: true, keys: out });
    }
    const m = url.pathname.match(/^\/api\/admin\/keys\/([0-9a-f-]{36})(?:\/(revoke|restore|reset-device|extend|note))?$/);
    if (m) {
      const k = db.keys.find((x) => x.id === m[1]);
      if (!k) return send(res, 404, { ok: false, message: 'NOT FOUND' });
      if (req.method === 'DELETE' && !m[2]) { db.keys = db.keys.filter((x) => x !== k); save(); return send(res, 200, { ok: true }); }
      if (req.method === 'POST') {
        if (m[2] === 'revoke') k.revoked = true;
        else if (m[2] === 'restore') k.revoked = false;
        else if (m[2] === 'reset-device') { k.deviceId = null; }      // expiry date is kept
        else if (m[2] === 'extend') {
          const b = await readBody(req); const d = parseInt(b.days, 10);
          if (!(d > 0 && d <= 3650)) return send(res, 400, { ok: false, message: 'days 1-3650' });
          if (k.plan === 'lifetime') return send(res, 400, { ok: false, message: 'lifetime keys never expire' });
          if (k.expiresAt) k.expiresAt += d * DAY; else k.days += d;      // not activated yet: lengthen the plan
        } else if (m[2] === 'note') { const b = await readBody(req); k.note = String(b.note || '').slice(0, 120); }
        else return send(res, 400, { ok: false, message: 'bad action' });
        save();
        return send(res, 200, { ok: true, key: publicKey(k) });
      }
    }
  }
  return send(res, 404, { ok: false, message: 'NOT FOUND' });
}

// ---------- static admin page ----------
const PUBLIC = path.join(__dirname, 'public');
const MIME = { '.html': 'text/html; charset=utf-8', '.gif': 'image/gif', '.png': 'image/png', '.js': 'text/javascript' };
function serveStatic(req, res, url) {
  let p = url.pathname === '/' ? '/admin.html' : url.pathname;
  const file = path.normalize(path.join(PUBLIC, p));
  if (!file.startsWith(PUBLIC + path.sep) || !fs.existsSync(file) || fs.statSync(file).isDirectory()) { res.writeHead(404); return res.end('Not found'); }
  res.writeHead(200, {
    'Content-Type': MIME[path.extname(file)] || 'application/octet-stream',
    'X-Frame-Options': 'DENY', 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer'
  });
  fs.createReadStream(file).pipe(res);
}

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, 'http://x');
    if (url.pathname.startsWith('/api/')) return await handleApi(req, res, url);
    return serveStatic(req, res, url);
  } catch (e) {
    send(res, 400, { ok: false, message: e.message || 'ERROR' });
  }
});
server.listen(PORT, () => console.log(`[appavi-keys] listening on http://localhost:${PORT}   data: ${DATA_DIR}`));
module.exports = server;
