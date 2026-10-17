// scripts/tools.mjs  —  usage:  node scripts/tools.mjs register | scan
// Node 20+, zero dependencies.
import crypto from 'node:crypto';
import dgram from 'node:dgram';
import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

// ───────────────────────── settings ─────────────────────────
const DATA_DIR = 'data';
const ACCOUNTS_FILE = path.join(DATA_DIR, 'accounts.json');
const ENDPOINTS_FILE = path.join(DATA_DIR, 'endpoints.txt');
const MAX_POOL = Number(process.env.MAX_POOL || 150); // accounts kept in the pool
const COUNT = Number(process.env.COUNT || 30);        // new accounts per register run
const SAMPLE = Number(process.env.SAMPLE || 3000);    // endpoints probed per scan
const CONCURRENCY = Number(process.env.CONCURRENCY || 120);
const TIMEOUT_MS = Number(process.env.TIMEOUT_MS || 1800);
const MIN_ALIVE_TO_SAVE = 5;
const MAX_ENDPOINTS_SAVED = 500;

export const WARP_PEER_PUB = 'bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=';

// candidate WARP anycast ranges (the scanner keeps only the ones that answer)
export const CIDRS = [
  '162.159.192.0/24', '162.159.193.0/24', '162.159.195.0/24',
  '188.114.96.0/24', '188.114.97.0/24', '188.114.98.0/24', '188.114.99.0/24',
  '8.6.112.0/24', '8.34.70.0/24', '8.34.146.0/24', '8.35.211.0/24',
  '8.39.125.0/24', '8.39.204.0/24', '8.39.213.0/24', '8.47.69.0/24',
];
export const PORTS = [
  2408, 500, 1701, 4500, 854, 859, 864, 878, 880, 890, 891, 894, 903, 908, 928, 934, 939, 942,
  943, 945, 946, 955, 968, 987, 988, 1002, 1010, 1014, 1018, 1070, 1074, 1180, 1387, 1843, 2371,
  2506, 3138, 3476, 3581, 3854, 4177, 4198, 4233, 5279, 5956, 7103, 7152, 7156, 7281, 7559, 8319,
  8742, 8854, 8886,
];

// registration API variants (tried in order)
const API_VARIANTS = [
  { path: 'v0a1922', ver: 'a-6.3-1922' },
  { path: 'v0a2158', ver: 'a-6.30-2158' },
];

// ───────────────────────── X25519 helpers ─────────────────────────
const PKCS8_PREFIX = Buffer.from('302e020100300506032b656e04220420', 'hex');
const SPKI_PREFIX = Buffer.from('302a300506032b656e032100', 'hex');

export function x25519Keypair() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('x25519');
  const priv = Buffer.from(privateKey.export({ type: 'pkcs8', format: 'der' }).subarray(-32));
  const pub = Buffer.from(publicKey.export({ type: 'spki', format: 'der' }).subarray(-32));
  // clamp like `wg genkey` (does not change DH results)
  priv[0] &= 248; priv[31] &= 127; priv[31] |= 64;
  return { priv, pub };
}
export function dh(priv, pub) {
  const privateKey = crypto.createPrivateKey({ key: Buffer.concat([PKCS8_PREFIX, priv]), format: 'der', type: 'pkcs8' });
  const publicKey = crypto.createPublicKey({ key: Buffer.concat([SPKI_PREFIX, pub]), format: 'der', type: 'spki' });
  return crypto.diffieHellman({ privateKey, publicKey });
}

// ───────────────────────── BLAKE2s (RFC 7693, with key support) ─────────────────────────
const IV = Uint32Array.from([0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]);
const SIGMA = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15], [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
  [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4], [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
  [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13], [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
  [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11], [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
  [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5], [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
];
const rotr = (x, n) => ((x >>> n) | (x << (32 - n))) >>> 0;

function compress(h, block, t, last) {
  const m = new Uint32Array(16);
  for (let i = 0; i < 16; i++) m[i] = block.readUInt32LE(i * 4);
  const v = new Uint32Array(16);
  v.set(h, 0); v.set(IV, 8);
  v[12] ^= t >>> 0; v[13] ^= Math.floor(t / 0x100000000);
  if (last) v[14] ^= 0xffffffff;
  const G = (a, b, c, d, x, y) => {
    v[a] = v[a] + v[b] + x; v[d] = rotr(v[d] ^ v[a], 16);
    v[c] = v[c] + v[d]; v[b] = rotr(v[b] ^ v[c], 12);
    v[a] = v[a] + v[b] + y; v[d] = rotr(v[d] ^ v[a], 8);
    v[c] = v[c] + v[d]; v[b] = rotr(v[b] ^ v[c], 7);
  };
  for (let r = 0; r < 10; r++) {
    const s = SIGMA[r];
    G(0, 4, 8, 12, m[s[0]], m[s[1]]); G(1, 5, 9, 13, m[s[2]], m[s[3]]);
    G(2, 6, 10, 14, m[s[4]], m[s[5]]); G(3, 7, 11, 15, m[s[6]], m[s[7]]);
    G(0, 5, 10, 15, m[s[8]], m[s[9]]); G(1, 6, 11, 12, m[s[10]], m[s[11]]);
    G(2, 7, 8, 13, m[s[12]], m[s[13]]); G(3, 4, 9, 14, m[s[14]], m[s[15]]);
  }
  for (let i = 0; i < 8; i++) h[i] ^= v[i] ^ v[i + 8];
}

export function blake2s(data, outLen = 32, key = Buffer.alloc(0)) {
  data = Buffer.from(data);
  const h = Uint32Array.from(IV);
  h[0] ^= 0x01010000 ^ (key.length << 8) ^ outLen;
  const input = key.length ? Buffer.concat([key, Buffer.alloc(64 - key.length), data]) : data;
  const total = input.length;
  let t = 0;
  if (total === 0) {
    compress(h, Buffer.alloc(64), 0, true);
  } else {
    let off = 0;
    while (total - off > 64) {
      t += 64;
      compress(h, input.subarray(off, off + 64), t, false);
      off += 64;
    }
    const rest = Buffer.alloc(64);
    input.copy(rest, 0, off);
    t += total - off;
    compress(h, rest, t, true);
  }
  const out = Buffer.alloc(32);
  for (let i = 0; i < 8; i++) out.writeUInt32LE(h[i], i * 4);
  return out.subarray(0, outLen);
}
const hash = (b) => blake2s(b, 32);
export function hmac(key, data) {
  let k = Buffer.from(key);
  if (k.length > 64) k = hash(k);
  const kp = Buffer.alloc(64); k.copy(kp);
  const ipad = Buffer.alloc(64), opad = Buffer.alloc(64);
  for (let i = 0; i < 64; i++) { ipad[i] = kp[i] ^ 0x36; opad[i] = kp[i] ^ 0x5c; }
  return hash(Buffer.concat([opad, hash(Buffer.concat([ipad, Buffer.from(data)]))]));
}

// ───────────────────────── WireGuard handshake initiation ─────────────────────────
const C0 = hash(Buffer.from('Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s'));
const H0 = hash(Buffer.concat([C0, Buffer.from('WireGuard v1 zx2c4 Jason@zx2c4.com')]));
const kdf1 = (key, input) => hmac(hmac(key, input), Buffer.from([1]));
function kdf2(key, input) {
  const t0 = hmac(key, input);
  const t1 = hmac(t0, Buffer.from([1]));
  const t2 = hmac(t0, Buffer.concat([t1, Buffer.from([2])]));
  return [t1, t2];
}
const ZERO_NONCE = Buffer.alloc(12);
export function aeadEncrypt(key, aad, plain) {
  const c = crypto.createCipheriv('chacha20-poly1305', key, ZERO_NONCE, { authTagLength: 16 });
  c.setAAD(aad, { plaintextLength: plain.length });
  const ct = Buffer.concat([c.update(plain), c.final()]);
  return Buffer.concat([ct, c.getAuthTag()]);
}
export function aeadDecrypt(key, aad, data) {
  const d = crypto.createDecipheriv('chacha20-poly1305', key, ZERO_NONCE, { authTagLength: 16 });
  d.setAAD(aad, { plaintextLength: data.length - 16 });
  d.setAuthTag(data.subarray(data.length - 16));
  return Buffer.concat([d.update(data.subarray(0, data.length - 16)), d.final()]);
}

let lastNs = 0n;
function tai64n() {
  let ns = BigInt(Date.now()) * 1000000n;
  if (ns <= lastNs) ns = lastNs + 1000n;
  lastNs = ns;
  const sec = ns / 1000000000n, nano = ns % 1000000000n;
  const b = Buffer.alloc(12);
  b.writeBigUInt64BE(0x400000000000000an + sec, 0);
  b.writeUInt32BE(Number(nano), 8);
  return b;
}

export function buildInitiation(spriv, spub, rpub, senderIndex) {
  let C = C0;
  let H = hash(Buffer.concat([H0, rpub]));
  const e = x25519Keypair();
  C = kdf1(C, e.pub);
  H = hash(Buffer.concat([H, e.pub]));
  let k;
  [C, k] = kdf2(C, dh(e.priv, rpub));
  const encStatic = aeadEncrypt(k, H, spub);
  H = hash(Buffer.concat([H, encStatic]));
  [C, k] = kdf2(C, dh(spriv, rpub));
  const encTs = aeadEncrypt(k, H, tai64n());
  const msg = Buffer.alloc(148);
  msg[0] = 1;
  msg.writeUInt32LE(senderIndex >>> 0, 4);
  e.pub.copy(msg, 8);
  encStatic.copy(msg, 40);
  encTs.copy(msg, 88);
  const mac1Key = hash(Buffer.concat([Buffer.from('mac1----'), rpub]));
  blake2s(msg.subarray(0, 116), 16, mac1Key).copy(msg, 116);
  return msg; // mac2 stays zero
}

export function probe(ip, port, acct, timeoutMs = TIMEOUT_MS) {
  return new Promise((resolve) => {
    const sock = dgram.createSocket('udp4');
    const idx = crypto.randomBytes(4).readUInt32LE(0);
    const msg = buildInitiation(
      Buffer.from(acct.pk, 'base64'), Buffer.from(acct.pub, 'base64'),
      Buffer.from(acct.peer || WARP_PEER_PUB, 'base64'), idx,
    );
    const t0 = Date.now();
    let done = false;
    const finish = (ok) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      try { sock.close(); } catch {}
      resolve(ok ? Date.now() - t0 : -1);
    };
    const timer = setTimeout(() => finish(false), timeoutMs);
    sock.on('message', (b) => {
      const resp = b.length === 92 && b[0] === 2 && b.readUInt32LE(8) === idx;
      const cookie = b.length === 64 && b[0] === 3 && b.readUInt32LE(4) === idx;
      if (resp || cookie) finish(true);
    });
    sock.on('error', () => finish(false));
    sock.send(msg, port, ip, (err) => { if (err) finish(false); });
  });
}

// ───────────────────────── utils ─────────────────────────
function readAccounts() {
  try { const a = JSON.parse(fs.readFileSync(ACCOUNTS_FILE, 'utf8')); return Array.isArray(a) ? a : []; }
  catch { return []; }
}
function writeAccounts(list) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  fs.writeFileSync(ACCOUNTS_FILE, JSON.stringify(list));
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const ipRange = (cidr) => {
  const [base, bits] = cidr.split('/');
  const p = base.split('.').map(Number);
  const start = ((p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3]) >>> 0;
  const size = 2 ** (32 - Number(bits));
  const out = [];
  for (let i = 1; i < size - 1; i++) { // skip network & broadcast
    const n = (start + i) >>> 0;
    out.push(`${n >>> 24}.${(n >>> 16) & 255}.${(n >>> 8) & 255}.${n & 255}`);
  }
  return out;
};

// ───────────────────────── register ─────────────────────────
async function registerOne() {
  const { priv, pub } = x25519Keypair();
  const body = JSON.stringify({
    key: pub.toString('base64'), install_id: '', fcm_token: '',
    tos: new Date().toISOString(), type: 'Android', model: 'PC', locale: 'en_US',
  });
  let lastErr = 'unknown';
  for (const v of API_VARIANTS) {
    try {
      const r = await fetch(`https://api.cloudflareclient.com/${v.path}/reg`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'User-Agent': 'okhttp/3.12.1', 'CF-Client-Version': v.ver },
        body,
        signal: AbortSignal.timeout(20000),
      });
      if (r.status === 429) return { rateLimited: true };
      if (!r.ok) { lastErr = `${v.path}: HTTP ${r.status}`; continue; }
      const j = await r.json();
      const peer = j?.config?.peers?.[0]?.public_key;
      const v4 = j?.config?.interface?.addresses?.v4;
      if (!peer || !v4) { lastErr = `${v.path}: unexpected response`; continue; }
      return { acct: { pk: priv.toString('base64'), pub: pub.toString('base64'), peer, v4, ts: Date.now() } };
    } catch (e) { lastErr = `${v.path}: ${e.message}`; }
  }
  return { error: lastErr };
}

async function cmdRegister() {
  const pool = readAccounts();
  console.log(`pool before: ${pool.length}, registering up to ${COUNT}`);
  let ok = 0, fail = 0;
  for (let i = 0; i < COUNT; i++) {
    const r = await registerOne();
    if (r.rateLimited) { console.log('rate limited (429) — stopping early'); break; }
    if (r.acct) { pool.push(r.acct); ok++; console.log(`#${i + 1} registered`); }
    else {
      fail++; console.log(`#${i + 1} failed: ${r.error}`);
      if (fail >= 5 && ok === 0) { console.log('5 failures in a row, stopping'); break; }
    }
    await sleep(1500);
  }
  const trimmed = pool.slice(-MAX_POOL);
  writeAccounts(trimmed);
  console.log(`registered ${ok}, failed ${fail}, pool now ${trimmed.length}`);
  if (trimmed.length === 0) process.exit(1);
}

// ───────────────────────── scan ─────────────────────────
async function cmdScan() {
  const accounts = readAccounts();
  if (!accounts.length) { console.log('no accounts yet — run the Accounts workflow first'); process.exit(1); }
  const ips = CIDRS.flatMap(ipRange);
  const seen = new Set(), targets = [];
  const total = ips.length * PORTS.length;
  const want = Math.min(SAMPLE, total);
  while (targets.length < want) {
    const ip = ips[crypto.randomInt(ips.length)];
    const port = PORTS[crypto.randomInt(PORTS.length)];
    const key = `${ip}:${port}`;
    if (seen.has(key)) continue;
    seen.add(key); targets.push({ ip, port, key });
  }
  console.log(`probing ${targets.length} endpoints with ${accounts.length} accounts`);
  const alive = [];
  let next = 0, done = 0;
  async function worker() {
    while (next < targets.length) {
      const i = next++;
      const t = targets[i];
      const ms = await probe(t.ip, t.port, accounts[i % accounts.length]);
      if (ms >= 0) alive.push({ key: t.key, ms });
      if (++done % 500 === 0) console.log(`  ${done}/${targets.length}, alive ${alive.length}`);
    }
  }
  await Promise.all(Array.from({ length: CONCURRENCY }, worker));
  console.log(`alive: ${alive.length}/${targets.length}`);
  if (alive.length < MIN_ALIVE_TO_SAVE) {
    console.log('too few answers — keeping the previous endpoints.txt (worker falls back to the random pool)');
    return;
  }
  alive.sort((a, b) => a.ms - b.ms);
  const out = alive.slice(0, MAX_ENDPOINTS_SAVED).map((a) => a.key);
  fs.mkdirSync(DATA_DIR, { recursive: true });
  fs.writeFileSync(ENDPOINTS_FILE, out.join('\n') + '\n');
  console.log(`saved ${out.length} endpoints`);
}

// ───────────────────────── main ─────────────────────────
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const cmd = process.argv[2];
  if (cmd === 'register') await cmdRegister();
  else if (cmd === 'scan') await cmdScan();
  else { console.log('usage: node scripts/tools.mjs register|scan'); process.exit(2); }
}
