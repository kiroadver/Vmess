// KANCIL_VPN backend: VLESS + Trojan over WebSocket, siap jalan di Railway
const http = require('http'), fs = require('fs'), path = require('path');
const net = require('net'), dgram = require('dgram'), dns = require('dns'), crypto = require('crypto');
const { WebSocketServer } = require('ws');

const PORT = process.env.PORT || 3000;
const ADMIN_KEY = process.env.ADMIN_KEY || '';
const DB = path.join(__dirname, 'users.json');
const users = new Map(); // uuid -> waktu kedaluwarsa (ms), 0 = tanpa batas

try { for (const [k, v] of Object.entries(JSON.parse(fs.readFileSync(DB, 'utf8')))) users.set(k, v); } catch {}
(process.env.UUIDS || '').split(',').map(s => s.trim().toLowerCase()).filter(Boolean).forEach(u => users.set(u, 0));

const save = () => fs.writeFile(DB, JSON.stringify(Object.fromEntries(users)), () => {});
const valid = u => { const e = users.get(u); return e !== undefined && (e === 0 || e > Date.now()); };
const hash = (alg, s) => crypto.createHash(alg).update(s).digest();
const isAdmin = k => !!ADMIN_KEY && crypto.timingSafeEqual(hash('sha256', String(k || '')), hash('sha256', ADMIN_KEY));

// blokir tujuan internal/loopback supaya server tidak bisa dipakai menembus jaringan privat
const PRIVATE = /^(localhost|127\.|10\.|0\.|169\.254\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|::1?$|f[cd][0-9a-f]{2}:|fe80:)|\.internal$/i;
const safeLookup = (host, o, cb) => dns.lookup(host, o, (e, a, f) => {
  const l = Array.isArray(a) ? a.map(x => x.address) : [a];
  e || !l.some(x => PRIVATE.test(x)) ? cb(e, a, f) : cb(new Error('blocked'));
});

// ---------- HTTP: status, registrasi UUID, halaman ----------
const json = (res, obj, code = 200) => { res.writeHead(code, { 'content-type': 'application/json' }); res.end(JSON.stringify(obj)); };

const server = http.createServer((req, res) => {
  res.setHeader('access-control-allow-origin', '*');
  res.setHeader('access-control-allow-headers', 'content-type, x-admin-key');
  if (req.method === 'OPTIONS') return res.writeHead(204).end();
  const p = req.url.split('?')[0];

  if (p === '/api/status') {
    return json(res, { uptime: Math.floor(process.uptime()), ram: Math.round(process.memoryUsage().rss / 1048576), udp: true });
  }
  if (p === '/api/register' && req.method === 'POST') {
    let body = '';
    req.on('data', c => { body += c; if (body.length > 1e4) req.destroy(); });
    req.on('end', () => {
      if (!isAdmin(req.headers['x-admin-key'])) return json(res, { error: 'unauthorized' }, 401);
      try {
        const { uuid, days } = JSON.parse(body);
        if (!/^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i.test(uuid)) throw 0;
        users.set(uuid.toLowerCase(), days > 0 ? Date.now() + days * 864e5 : 0);
        save(); json(res, { ok: true });
      } catch { json(res, { error: 'bad request' }, 400); }
    });
    return;
  }
  if (p === '/' || p === '/index.html') {
    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
    return fs.createReadStream(path.join(__dirname, 'index.html')).on('error', () => res.end('index.html tidak ditemukan')).pipe(res);
  }
  res.writeHead(404).end('Not found');
});

// ---------- parser protokol ----------
// alamat: t = tipe; dom = kode tipe domain; v6 = kode tipe IPv6 (beda antara VLESS dan Trojan)
function addr(b, o, t, dom, v6) {
  if (t === 1) return [[...b.subarray(o, o + 4)].join('.'), o + 4];
  if (t === dom) { const l = b[o]; return [b.toString('utf8', o + 1, o + 1 + l), o + 1 + l]; }
  if (t === v6) return [Array.from({ length: 8 }, (_, i) => b.readUInt16BE(o + i * 2).toString(16)).join(':'), o + 16];
}

function vless(b) {
  if (b.length < 24) return;
  const hex = b.toString('hex', 1, 17);
  const id = hex.replace(/(.{8})(.{4})(.{4})(.{4})(.{12})/, '$1-$2-$3-$4-$5');
  if (!valid(id)) return;
  let o = 18 + b[17];
  const cmd = b[o++], port = b.readUInt16BE(o); o += 2;
  const a = addr(b, o + 1, b[o], 2, 3); if (!a) return;
  return { udp: cmd === 2, host: a[0], port, payload: b.subarray(a[1]), reply: Buffer.from([b[0], 0]) };
}

function trojan(b) {
  if (b.length < 62 || b[58] !== 1) return; // hanya TCP CONNECT
  const h = b.toString('ascii', 0, 56);
  if (![...users.keys()].some(u => valid(u) && hash('sha224', u).toString('hex') === h)) return;
  const a = addr(b, 60, b[59], 3, 4); if (!a) return;
  const port = b.readUInt16BE(a[1]);
  return { udp: false, host: a[0], port, payload: b.subarray(a[1] + 4), reply: Buffer.alloc(0) };
}

// ---------- relay ----------
function udpRelay(ws, h) { // UDP VLESS: paket berformat [panjang 2 byte][data]
  const sock = dgram.createSocket({ type: 'udp4', lookup: safeLookup });
  let buf = Buffer.alloc(0), first = true;
  sock.on('message', m => {
    const l = Buffer.alloc(2); l.writeUInt16BE(m.length);
    if (ws.readyState === 1) ws.send(Buffer.concat([first ? h.reply : Buffer.alloc(0), l, m]));
    first = false;
  });
  const feed = d => {
    buf = Buffer.concat([buf, d]);
    while (buf.length >= 2) {
      const n = buf.readUInt16BE(0);
      if (buf.length < 2 + n) break;
      sock.send(buf.subarray(2, 2 + n), h.port, h.host, () => {});
      buf = buf.subarray(2 + n);
    }
  };
  feed(h.payload);
  ws.on('message', feed);
  ws.on('close', () => sock.close());
  sock.on('error', () => ws.close());
}

const wss = new WebSocketServer({ server }); // path apa pun diterima
wss.on('connection', ws => {
  ws.on('error', () => {});
  ws.once('message', b => {
    let h;
    try { h = (b[56] === 13 && b[57] === 10) ? trojan(b) : vless(b); } catch {}
    if (!h || PRIVATE.test(h.host)) return ws.close();
    if (h.udp) return udpRelay(ws, h);

    const sock = net.connect({ host: h.host, port: h.port, lookup: safeLookup });
    if (h.payload.length) sock.write(h.payload);
    let first = true;
    sock.on('data', d => {
      if (ws.readyState !== 1) return;
      ws.send(first ? Buffer.concat([h.reply, d]) : d); first = false;
    });
    ws.on('message', d => sock.write(d));
    ws.on('close', () => sock.destroy());
    sock.on('close', () => ws.close());
    sock.on('error', () => ws.close());
  });
});

server.listen(PORT, () => console.log(`KANCIL_VPN aktif di port ${PORT}`));
