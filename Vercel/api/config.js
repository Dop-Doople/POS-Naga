/* api/config.js - konfigurasi publik untuk klien, TIDAK PERNAH memuat secret key */
const { getEnv, validateEnv, send } = require('../lib/supabase.js');

module.exports = function handler(req, res) {
  const env = getEnv();
  if (validateEnv(env, false)) {
    return send(res, 200, { configured: false, url: '', anonKey: '' });
  }
  return send(res, 200, { configured: true, url: env.url, anonKey: env.anonKey });
};
