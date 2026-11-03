/* lib/supabase.js - helper server Vercel, tanpa dependency */
const crypto = require('crypto');
const URL_RE = /^https:\/\/[a-z0-9]{10,30}\.supabase\.co$/;
const tokenCache = new Map();

function httpError(status, message) {
  const err = new Error(message);
  err.status = status;
  return err;
}

function getEnv() {
  return {
    url: String(process.env.SUPABASE_URL || '').trim().replace(/\/+$/, ''),
    anonKey: String(process.env.SUPABASE_ANON_KEY || '').trim(),
    serviceKey: String(process.env.SUPABASE_SERVICE_ROLE_KEY || '').trim()
  };
}

/* kembalikan string kosong jika valid, atau pesan error */
function validateEnv(env, needServiceKey) {
  if (!URL_RE.test(env.url)) {
    return 'SUPABASE_URL tidak valid. Format: https://<project-ref>.supabase.co';
  }
  if (env.anonKey.length < 20 || env.anonKey.indexOf('YOUR_') === 0 ||
      !(env.anonKey.indexOf('sb_publishable_') === 0 || env.anonKey.indexOf('eyJ') === 0)) {
    return 'SUPABASE_ANON_KEY tidak valid (harus sb_publishable_... atau eyJ...).';
  }
  if (needServiceKey) {
    if (env.serviceKey.length < 20 || env.serviceKey.indexOf('YOUR_') === 0 ||
        !(env.serviceKey.indexOf('sb_secret_') === 0 || env.serviceKey.indexOf('eyJ') === 0)) {
      return 'SUPABASE_SERVICE_ROLE_KEY tidak valid (harus sb_secret_... atau eyJ...).';
    }
  }
  return '';
}

function sbHeaders(key, extra) {
  const h = { apikey: key, 'Content-Type': 'application/json' };
  if (key.indexOf('eyJ') === 0) {
    h.Authorization = 'Bearer ' + key;
  }
  return Object.assign(h, extra || {});
}

async function sbFetch(path, method, body, key, extra) {
  const env = getEnv();
  const res = await fetch(env.url + path, {
    method: method || 'GET',
    headers: sbHeaders(key, extra),
    body: body ? JSON.stringify(body) : undefined,
    signal: AbortSignal.timeout(8000)
  });
  const text = await res.text();
  let data = null;
  if (text) {
    try { data = JSON.parse(text); } catch (e) { data = { message: text }; }
  }
  if (res.status >= 300) {
    const msg = (data && (data.message || data.msg || data.error_description || data.error)) || 'Permintaan gagal';
    throw httpError(res.status, 'HTTP ' + res.status + ': ' + msg);
  }
  return data;
}

function getBearer(req) {
  const h = String((req.headers && req.headers.authorization) || '');
  return h.indexOf('Bearer ') === 0 ? h.slice(7).trim() : '';
}

async function verifyUser(token) {
  if (!token) { throw httpError(401, 'Token tidak ada'); }
  const env = getEnv();
  const hash = crypto.createHash('sha256').update(token).digest('hex');
  const hit = tokenCache.get(hash);
  if (hit && hit.exp > Date.now()) { return hit.uid; }
  const res = await fetch(env.url + '/auth/v1/user', {
    headers: { apikey: env.anonKey, Authorization: 'Bearer ' + token },
    signal: AbortSignal.timeout(8000)
  });
  if (!res.ok) { throw httpError(401, 'Sesi tidak valid'); }
  const user = await res.json();
  if (tokenCache.size > 500) { tokenCache.clear(); }
  tokenCache.set(hash, { uid: user.id, exp: Date.now() + 60000 });
  return user.id;
}

async function requireAdmin(token) {
  const uid = await verifyUser(token);
  const env = getEnv();
  const rows = await sbFetch('/rest/v1/profiles?id=eq.' + encodeURIComponent(uid) + '&select=role,aktif', 'GET', null, env.serviceKey);
  if (!rows || !rows[0] || rows[0].role !== 'admin' || rows[0].aktif !== true) {
    throw httpError(403, 'Akses ditolak');
  }
  return uid;
}

/* log audit tidak boleh menggagalkan aksi utama */
async function writeLog(adminUid, aksi, target, detail) {
  try {
    const env = getEnv();
    await sbFetch('/rest/v1/logs', 'POST', { aksi: aksi, target: target, detail: detail || {}, created_by: adminUid }, env.serviceKey, { Prefer: 'return=minimal' });
  } catch (e) {
    console.warn('Gagal menulis log audit:', e.message);
  }
}

function send(res, status, obj) {
  res.setHeader('Cache-Control', 'no-store');
  res.status(status).json(obj);
}

module.exports = { httpError, getEnv, validateEnv, sbFetch, getBearer, verifyUser, requireAdmin, writeLog, send };
