/* api/health.js - uji koneksi Supabase & verifikasi tabel */
const crypto = require('crypto');
const { httpError, getEnv, validateEnv, sbFetch, send } = require('../lib/supabase.js');

const TABLES = [
  'profiles',
  'produk',
  'transaksi',
  'detail_transaksi',
  'stok_mutasi',
  'biaya',
  'pajak',
  'akun',
  'buku_besar'
];

module.exports = async function handler(req, res) {
  try {
    if (req.method !== 'GET') {
      throw httpError(405, 'Method tidak diizinkan');
    }

    const healthSecret = String(process.env.HEALTH_KEY || '').trim();
    if (!healthSecret) {
      return send(res, 404, { success: false, message: 'Endpoint health nonaktif (HEALTH_KEY tidak disetel)' });
    }

    const clientKey = String((req.query && req.query.key) || '').trim();
    const bufA = Buffer.from(healthSecret);
    const bufB = Buffer.from(clientKey);
    if (bufA.length !== bufB.length || !crypto.timingSafeEqual(bufA, bufB)) {
      return send(res, 401, { success: false, message: 'Kunci kesehatan (HEALTH_KEY) tidak valid' });
    }

    const env = getEnv();
    const envErr = validateEnv(env, true);
    if (envErr) {
      return send(res, 500, { success: false, message: envErr });
    }

    /* 1. Tes Auth Settings */
    let authStatus = 0;
    try {
      const authRes = await fetch(env.url + '/auth/v1/settings', {
        headers: { apikey: env.anonKey },
        signal: AbortSignal.timeout(6000)
      });
      authStatus = authRes.status;
    } catch (e) {
      authStatus = 503;
    }

    /* 2. Tes Setiap Tabel dengan Service Key */
    const tableResults = [];
    for (const tbl of TABLES) {
      try {
        await sbFetch('/rest/v1/' + encodeURIComponent(tbl) + '?select=id&limit=1', 'GET', null, env.serviceKey);
        tableResults.push({ tabel: tbl, ok: true, pesan: 'Tabel ' + tbl + ' berhasil diverifikasi' });
      } catch (err) {
        tableResults.push({
          tabel: tbl,
          ok: false,
          pesan: 'Gagal verifikasi (' + (err.status || 500) + '): ' + err.message
        });
      }
    }

    const allOk = authStatus === 200 && tableResults.every(function (t) { return t.ok; });
    return send(res, 200, {
      success: allOk,
      auth: authStatus,
      tables: tableResults,
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    return send(res, err.status || 500, { success: false, message: String(err.message || err) });
  }
};
