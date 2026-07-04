// ============================================================
//  ROX CHEATS - NODE.JS AUTH SERVER
//  Deploy lên Render.com
// ============================================================
//  HƯỚNG DẪN:
//  1. Tạo Supabase project, chạy schema.sql
//  2. Push code lên GitHub
//  3. Render.com > New > Web Service > kết nối GitHub repo
//  4. Set environment variables:
//     SUPABASE_URL, SUPABASE_SERVICE_KEY, ADMIN_USER, ADMIN_PASS
//  5. Deploy
// ============================================================

const express = require('express');
const cors = require('cors');
const { createClient } = require('@supabase/supabase-js');

const app = express();
const PORT = process.env.PORT || 3000;

// ---- CORS ----
app.use(cors());
app.use(express.json());

// ---- Supabase client ----
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_SERVICE_KEY;
const supabase = createClient(supabaseUrl, supabaseKey);

// ---- Admin auth ----
const ADMIN_USER = process.env.ADMIN_USER || 'admin';
const ADMIN_PASS = process.env.ADMIN_PASS || 'admin123';

function requireAdmin(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Basic ')) {
    res.set('WWW-Authenticate', 'Basic realm="ROX AUTH"');
    return res.status(401).json({ success: false, message: 'Unauthorized' });
  }
  const decoded = Buffer.from(auth.slice(6), 'base64').toString();
  const [user, pass] = decoded.split(':');
  if (user !== ADMIN_USER || pass !== ADMIN_PASS) {
    return res.status(401).json({ success: false, message: 'Unauthorized' });
  }
  next();
}

// ---- Utility ----
function generateKey(length = 32) {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let key = '';
  const array = new Uint8Array(length);
  crypto.getRandomValues(array);
  for (let i = 0; i < length; i++) {
    key += chars[array[i] % chars.length];
  }
  return key.match(/.{4}/g).join('-');
}

// ======================== API ROUTES ========================

// ---- Verify Key (PUBLIC) ----
app.get('/api/verify', async (req, res) => {
  try {
    const { key, hwid } = req.query;
    if (!key || !hwid) {
      return res.json({ success: false, status: 'invalid', message: 'Thiếu tham số key hoặc hwid' });
    }

    const { data: keys, error } = await supabase
      .from('keys')
      .select('key, status, expires_at, hwid')
      .eq('key', key);

    if (error) throw error;

    if (!keys || keys.length === 0) {
      return res.json({ success: false, status: 'invalid', message: 'Key không tồn tại' });
    }

    const record = keys[0];

    if (record.status === 'banned') {
      return res.json({ success: false, status: 'banned', message: 'Key đã bị khóa' });
    }

    if (record.status === 'expired') {
      return res.json({ success: false, status: 'expired', message: 'Key đã hết hạn' });
    }

    // Check expiry
    const now = new Date();
    const expires = new Date(record.expires_at);
    if (now > expires) {
      await supabase.from('keys').update({ status: 'expired' }).eq('key', key);
      return res.json({ success: false, status: 'expired', message: 'Key đã hết hạn' });
    }

    // Check HWID
    if (record.hwid && record.hwid !== '' && record.hwid !== hwid) {
      return res.json({ success: false, status: 'hwid_mismatch', message: 'Key đã được sử dụng trên thiết bị khác' });
    }

    // Bind HWID on first use
    if (!record.hwid || record.hwid === '') {
      await supabase.from('keys').update({ hwid }).eq('key', key);
    }

    // Log
    await supabase.from('activity_log').insert({
      action: 'verify',
      key: key,
      detail: `Xác thực thành công từ HWID: ${hwid}`,
    });

    res.json({
      success: true,
      status: 'valid',
      message: 'Xác thực thành công',
      expires_at: record.expires_at,
    });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Lỗi server: ' + err.message });
  }
});

// ---- Create Key (ADMIN) ----
app.post('/api/keys', requireAdmin, async (req, res) => {
  try {
    const { days = 30, note = '', user = '' } = req.body;
    const newKey = generateKey(32);
    const now = new Date();
    const expires = new Date(now.getTime() + days * 24 * 60 * 60 * 1000);

    await supabase.from('keys').insert({
      key: newKey,
      status: 'active',
      created_at: now.toISOString(),
      expires_at: expires.toISOString(),
      hwid: '',
      user,
      note,
    });

    await supabase.from('activity_log').insert({
      action: 'create', key: newKey,
      detail: `Tạo key mới, hạn ${days} ngày. Ghi chú: ${note}`,
    });

    res.json({ success: true, message: 'Tạo key thành công', data: { key: newKey, days, expires_at: expires.toISOString() } });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// ---- List Keys (ADMIN) ----
app.get('/api/keys', requireAdmin, async (req, res) => {
  try {
    const { data: keys, error } = await supabase.from('keys').select('*').order('created_at', { ascending: false });
    if (error) throw error;
    res.json({ success: true, data: keys, total: keys.length });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// ---- Get Key (ADMIN) ----
app.get('/api/keys/:key', requireAdmin, async (req, res) => {
  try {
    const { data: keys, error } = await supabase.from('keys').select('*').eq('key', req.params.key);
    if (error) throw error;
    if (!keys || keys.length === 0) return res.status(404).json({ success: false, message: 'Key không tồn tại' });
    res.json({ success: true, data: keys[0] });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// ---- Delete Key (ADMIN) ----
app.delete('/api/keys/:key', requireAdmin, async (req, res) => {
  try {
    const { data: keys } = await supabase.from('keys').select('key').eq('key', req.params.key);
    if (!keys || keys.length === 0) return res.status(404).json({ success: false, message: 'Key không tồn tại' });

    await supabase.from('keys').delete().eq('key', req.params.key);
    await supabase.from('activity_log').insert({ action: 'delete', key: req.params.key, detail: 'Xóa key' });

    res.json({ success: true, message: 'Đã xóa key' });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// ---- Ban Key (ADMIN) ----
app.post('/api/keys/:key/ban', requireAdmin, async (req, res) => {
  try {
    const { data: keys } = await supabase.from('keys').select('key,status').eq('key', req.params.key);
    if (!keys || keys.length === 0) return res.status(404).json({ success: false, message: 'Key không tồn tại' });
    if (keys[0].status === 'banned') return res.json({ success: false, message: 'Key đã bị khóa trước đó' });

    await supabase.from('keys').update({ status: 'banned' }).eq('key', req.params.key);
    await supabase.from('activity_log').insert({ action: 'ban', key: req.params.key, detail: 'Khóa key' });

    res.json({ success: true, message: 'Đã khóa key' });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// ---- Unban Key (ADMIN) ----
app.post('/api/keys/:key/unban', requireAdmin, async (req, res) => {
  try {
    const { data: keys } = await supabase.from('keys').select('key,status').eq('key', req.params.key);
    if (!keys || keys.length === 0) return res.status(404).json({ success: false, message: 'Key không tồn tại' });
    if (keys[0].status !== 'banned') return res.json({ success: false, message: 'Key không ở trạng thái bị khóa' });

    await supabase.from('keys').update({ status: 'active' }).eq('key', req.params.key);
    await supabase.from('activity_log').insert({ action: 'unban', key: req.params.key, detail: 'Mở khóa key' });

    res.json({ success: true, message: 'Đã mở khóa key' });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// ---- Extend Key (ADMIN) ----
app.post('/api/keys/:key/extend', requireAdmin, async (req, res) => {
  try {
    const days = parseInt(req.body.days);
    if (!days || days < 1) return res.json({ success: false, message: 'Số ngày không hợp lệ' });

    const { data: keys } = await supabase.from('keys').select('key,expires_at').eq('key', req.params.key);
    if (!keys || keys.length === 0) return res.status(404).json({ success: false, message: 'Key không tồn tại' });

    const currentExpiry = new Date(keys[0].expires_at);
    const now = new Date();
    const baseDate = currentExpiry > now ? currentExpiry : now;
    const newExpiry = new Date(baseDate.getTime() + days * 24 * 60 * 60 * 1000);

    await supabase.from('keys').update({ expires_at: newExpiry.toISOString(), status: 'active' }).eq('key', req.params.key);
    await supabase.from('activity_log').insert({ action: 'extend', key: req.params.key, detail: `Gia hạn thêm ${days} ngày, hạn mới: ${newExpiry.toISOString()}` });

    res.json({ success: true, message: `Đã gia hạn key thêm ${days} ngày`, data: { new_expires_at: newExpiry.toISOString() } });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// ---- Stats (ADMIN) ----
app.get('/api/stats', requireAdmin, async (req, res) => {
  try {
    const { data: keys, error } = await supabase.from('keys').select('status');
    if (error) throw error;
    const total = keys.length;
    const active = keys.filter(k => k.status === 'active').length;
    const banned = keys.filter(k => k.status === 'banned').length;
    const expired = keys.filter(k => k.status === 'expired').length;
    res.json({ success: true, data: { total, active, banned, expired } });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// ---- Logs (ADMIN) ----
app.get('/api/logs', requireAdmin, async (req, res) => {
  try {
    const { data: logs, error } = await supabase.from('activity_log').select('*').order('created_at', { ascending: false });
    if (error) throw error;
    res.json({ success: true, data: logs });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// ======================== WEB UI ========================
const path = require('path');
app.use(express.static(path.join(__dirname, '..', 'web')));

app.get(['/', '/web'], (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'web', 'index.html'));
});

// ======================== START ========================
app.listen(PORT, () => {
  console.log(`ROX Auth Server running on port ${PORT}`);
  console.log(`Web UI: http://localhost:${PORT}/`);
  console.log(`API:   http://localhost:${PORT}/api/verify?key=xxx&hwid=xxx`);
});
