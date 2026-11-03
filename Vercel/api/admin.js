/* api/admin.js - gateway admin untuk operasi istimewa dengan secret key */
const { httpError, getEnv, validateEnv, sbFetch, getBearer, requireAdmin, writeLog, send } = require('../lib/supabase.js');

const ROLES = ['admin', 'kasir'];
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const UID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

module.exports = async function handler(req, res) {
  try {
    if (req.method !== 'POST') {
      throw httpError(405, 'Method tidak diizinkan');
    }
    const env = getEnv();
    const bad = validateEnv(env, true);
    if (bad) {
      throw httpError(500, bad);
    }

    const adminUid = await requireAdmin(getBearer(req));
    const body = (req.body && typeof req.body === 'object') ? req.body : {};

    switch (body.action) {
      case 'createUser': {
        const email = String(body.email || '').trim().toLowerCase();
        const password = String(body.password || '').trim();
        const nama = String(body.nama || '').trim();
        const role = String(body.role || '').trim().toLowerCase();

        if (!EMAIL_RE.test(email)) {
          throw httpError(400, 'Format email tidak valid');
        }
        if (password.length < 6) {
          throw httpError(400, 'Password minimal 6 karakter');
        }
        if (!ROLES.includes(role)) {
          throw httpError(400, 'Role tidak valid (pilih admin atau kasir)');
        }
        if (!nama) {
          throw httpError(400, 'Nama lengkap wajib diisi');
        }

        const newUser = await sbFetch('/auth/v1/admin/users', 'POST', {
          email: email,
          password: password,
          email_confirm: true,
          user_metadata: { nama: nama },
          app_metadata: { role: role }
        }, env.serviceKey);

        const newUid = newUser && newUser.id;
        if (!newUid) {
          throw httpError(500, 'Gagal membuat user auth');
        }

        /* Pastikan tabel profiles sinkron */
        await sbFetch('/rest/v1/profiles?id=eq.' + encodeURIComponent(newUid), 'PATCH', {
          nama: nama,
          role: role,
          aktif: true
        }, env.serviceKey, { Prefer: 'return=minimal' });

        await writeLog(adminUid, 'CREATE_USER', newUid, { email: email, role: role, nama: nama });
        return send(res, 200, { success: true, uid: newUid });
      }

      case 'listUsers': {
        const rows = await sbFetch(
          '/rest/v1/profiles?select=id,email,nama,role,aktif,created_at&order=created_at.desc',
          'GET',
          null,
          env.serviceKey
        );
        return send(res, 200, { success: true, users: rows || [] });
      }

      case 'updateUserRole': {
        const uid = String(body.uid || '').trim();
        const role = String(body.role || '').trim().toLowerCase();
        const nama = String(body.nama || '').trim();

        if (!UID_RE.test(uid)) {
          throw httpError(400, 'Format ID pengguna tidak valid');
        }
        if (!ROLES.includes(role)) {
          throw httpError(400, 'Role tidak valid');
        }

        /* Cegah admin menurunkan role dirinya sendiri jika satu-satunya admin aktif */
        if (uid === adminUid && role !== 'admin') {
          const admins = await sbFetch('/rest/v1/profiles?role=eq.admin&aktif=eq.true&select=id', 'GET', null, env.serviceKey);
          if (admins && admins.length <= 1) {
            throw httpError(400, 'Tidak dapat menurunkan role: Anda adalah satu-satunya admin aktif');
          }
        }

        await sbFetch('/auth/v1/admin/users/' + encodeURIComponent(uid), 'PUT', {
          app_metadata: { role: role },
          user_metadata: { nama: nama }
        }, env.serviceKey);

        const patchData = { role: role };
        if (nama) {
          patchData.nama = nama;
        }
        await sbFetch('/rest/v1/profiles?id=eq.' + encodeURIComponent(uid), 'PATCH', patchData, env.serviceKey, { Prefer: 'return=minimal' });

        await writeLog(adminUid, 'UPDATE_USER_ROLE', uid, { role: role, nama: nama });
        return send(res, 200, { success: true });
      }

      case 'setUserActive': {
        const uid = String(body.uid || '').trim();
        const aktif = Boolean(body.aktif);

        if (!UID_RE.test(uid)) {
          throw httpError(400, 'Format ID pengguna tidak valid');
        }
        if (uid === adminUid && !aktif) {
          throw httpError(400, 'Tidak dapat menonaktifkan akun sendiri');
        }

        await sbFetch('/auth/v1/admin/users/' + encodeURIComponent(uid), 'PUT', {
          ban_duration: aktif ? 'none' : '876000h'
        }, env.serviceKey);

        await sbFetch('/rest/v1/profiles?id=eq.' + encodeURIComponent(uid), 'PATCH', {
          aktif: aktif
        }, env.serviceKey, { Prefer: 'return=minimal' });

        await writeLog(adminUid, 'SET_USER_ACTIVE', uid, { aktif: aktif });
        return send(res, 200, { success: true });
      }

      case 'deleteUser': {
        const uid = String(body.uid || '').trim();
        if (!UID_RE.test(uid)) {
          throw httpError(400, 'Format ID pengguna tidak valid');
        }
        if (uid === adminUid) {
          throw httpError(400, 'Tidak dapat menghapus akun sendiri');
        }

        await sbFetch('/auth/v1/admin/users/' + encodeURIComponent(uid), 'DELETE', null, env.serviceKey);
        await writeLog(adminUid, 'DELETE_USER', uid, {});
        return send(res, 200, { success: true });
      }

      default:
        throw httpError(400, 'Action tidak dikenal');
    }
  } catch (err) {
    return send(res, err.status || 500, { success: false, message: String(err.message || err) });
  }
};
