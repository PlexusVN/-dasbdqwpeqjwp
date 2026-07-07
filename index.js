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
if (!supabaseUrl || !supabaseKey) {
  console.error('❌ FATAL: Missing SUPABASE_URL or SUPABASE_SERVICE_KEY env vars');
  process.exit(1);
}
const supabase = createClient(supabaseUrl, supabaseKey);

// ---- Admin auth ----
const ADMIN_USER = process.env.ADMIN_USER || 'admin';
const ADMIN_PASS = process.env.ADMIN_PASS || 'admin123';

// ---- Startup info ----
console.log('Supabase:', supabaseUrl ? '✅ Connected' : '❌ Not set');
console.log('Admin user:', ADMIN_USER);
console.log('Auth endpoint:', `/api/verify?key=xxx&hwid=xxx`);

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

// ---- Health Check (PUBLIC) ----
app.get('/api/health', async (req, res) => {
  try {
    const { count, error } = await supabase.from('keys').select('*', { count: 'exact', head: true });
    if (error) throw error;
    res.json({ success: true, message: 'Server is running', admin: ADMIN_USER || 'admin', supabase: 'connected', keys_count: count || 0 });
  } catch (err) {
    res.json({ success: true, message: 'Server is running', admin: ADMIN_USER || 'admin', supabase: 'error: ' + err.message });
  }
});

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
      .select('key, status, expires_at, hwid, type, duration_days, max_devices')
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

    // Check expiry (skip if chưa kích hoạt lần đầu)
    const now = new Date();
    if (record.expires_at) {
      const expires = new Date(record.expires_at);
      if (now > expires) {
        await supabase.from('keys').update({ status: 'expired' }).eq('key', key);
        return res.json({ success: false, status: 'expired', message: 'Key đã hết hạn' });
      }
    }

    // Parse HWID list (JSON array)
    let hwidList = [];
    if (record.hwid && record.hwid !== '') {
      if (record.hwid.startsWith('[')) {
        try { hwidList = JSON.parse(record.hwid); } catch { hwidList = []; }
      } else {
        hwidList = [record.hwid]; // backward compat
      }
    }

    const maxDev = record.max_devices || 1;

    // Check if this HWID is already registered
    if (hwidList.includes(hwid)) {
      // Already registered, allow
    } else if (hwidList.length < maxDev) {
      // Register new HWID
      hwidList.push(hwid);
      const updateData = { hwid: JSON.stringify(hwidList) };
      if (!record.expires_at && record.duration_days) {
        const firstExpiry = new Date(now.getTime() + record.duration_days * 24 * 60 * 60 * 1000);
        updateData.expires_at = firstExpiry.toISOString();
      }
      await supabase.from('keys').update(updateData).eq('key', key);
      const { data: updated } = await supabase.from('keys').select('expires_at').eq('key', key);
      if (updated && updated.length > 0) record.expires_at = updated[0].expires_at;
    } else {
      return res.json({ success: false, status: 'max_devices', message: `Key đã đạt giới hạn ${maxDev} thiết bị` });
    }

    // Update last_seen
    await supabase.from('keys').update({ last_seen: new Date().toISOString() }).eq('key', key);

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
      server_time: new Date().toISOString(),
      type: record.type || 'basic',
    });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Lỗi server: ' + err.message });
  }
});

// ---- Create Key(s) (ADMIN) ----
app.post('/api/keys', requireAdmin, async (req, res) => {
  try {
    const { days = 30, note = '', user = '', prefix: rawPrefix = '', count = 1, suffixLength: rawSuffixLen, type: rawType = 'basic', max_devices = 1 } = req.body;
    const keyType = ['basic', 'pro', 'vip'].includes(rawType) ? rawType : 'basic';
    const num = Math.min(Math.max(parseInt(count) || 1, 1), 500);
    const now = new Date();
    const durationDays = parseInt(days) || 30;
    const usePrefix = rawPrefix && rawPrefix.trim();
    const suffixLen = parseInt(rawSuffixLen) || (usePrefix ? 12 : 32);

    const keys = [];
    for (let i = 0; i < num; i++) {
      const randomPart = generateKey(suffixLen);
      const newKey = usePrefix ? rawPrefix.trim().toUpperCase() + '-' + randomPart : randomPart;
      keys.push({ key: newKey, duration_days: durationDays, type: keyType });
    }

    const maxDevices = Math.min(Math.max(parseInt(max_devices) || 1, 1), 100);
    const inserts = keys.map(k => ({
      key: k.key,
      status: 'active',
      created_at: now.toISOString(),
      expires_at: null,
      duration_days: durationDays,
      hwid: '[]',
      max_devices: maxDevices,
      user: user || '',
      note: note || '',
      type: keyType,
    }));
    const { error: insertError } = await supabase.from('keys').insert(inserts);
    if (insertError) throw insertError;

    await supabase.from('activity_log').insert({
      action: 'create',
      key: num > 1 ? `${num} keys` : keys[0].key,
      detail: `Tạo ${num} key(s), hạn ${days} ngày. Ghi chú: ${note}`,
    });

    res.json({
      success: true,
      message: `Tạo ${num} key thành công`,
      data: num === 1 ? keys[0] : keys,
      count: num,
    });
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

// ---- Reset HWID (ADMIN) ----
app.post('/api/keys/:key/reset-hwid', requireAdmin, async (req, res) => {
  try {
    const { data: keys } = await supabase.from('keys').select('key,hwid').eq('key', req.params.key);
    if (!keys || keys.length === 0) return res.status(404).json({ success: false, message: 'Key không tồn tại' });

    const oldHwid = keys[0].hwid || '[]';
    await supabase.from('keys').update({ hwid: '[]', last_seen: null }).eq('key', req.params.key);
    await supabase.from('activity_log').insert({ action: 'reset_hwid', key: req.params.key, detail: `Reset HWID (cũ: ${oldHwid})` });

    res.json({ success: true, message: 'Đã reset HWID, key có thể dùng trên máy mới' });
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

// ---- Change Key Type (ADMIN) ----
app.post('/api/keys/:key/type', requireAdmin, async (req, res) => {
  try {
    const { type } = req.body;
    if (!['basic', 'pro', 'vip'].includes(type)) {
      return res.status(400).json({ success: false, message: 'Loại key không hợp lệ (basic, pro, vip)' });
    }
    const { data, error } = await supabase.from('keys').update({ type }).eq('key', req.params.key).select();
    if (error) throw error;
    if (!data || data.length === 0) return res.status(404).json({ success: false, message: 'Key không tồn tại' });
    await supabase.from('activity_log').insert({ action: 'CHANGE_TYPE', key: req.params.key, detail: 'Chuyển loại thành ' + type });
    res.json({ success: true, message: 'Đã đổi loại key thành ' + type });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// ---- Update Max Devices (ADMIN) ----
app.post('/api/keys/:key/max-devices', requireAdmin, async (req, res) => {
  try {
    const maxDevices = parseInt(req.body.max_devices);
    if (!maxDevices || maxDevices < 1 || maxDevices > 100) {
      return res.json({ success: false, message: 'Số thiết bị không hợp lệ (1-100)' });
    }
    const { data, error } = await supabase.from('keys').update({ max_devices: maxDevices }).eq('key', req.params.key).select();
    if (error) throw error;
    if (!data || data.length === 0) return res.status(404).json({ success: false, message: 'Key không tồn tại' });
    await supabase.from('activity_log').insert({ action: 'change_max_devices', key: req.params.key, detail: `Thay đổi số thiết bị tối đa thành ${maxDevices}` });
    res.json({ success: true, message: `Đã đổi số thiết bị tối đa thành ${maxDevices}` });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// ---- Stats (ADMIN) ----
app.get('/api/stats', requireAdmin, async (req, res) => {
  try {
    const { data: keys, error } = await supabase.from('keys').select('status,expires_at');
    if (error) throw error;
    const total = keys.length;
    const now = new Date().toISOString();
    const active = keys.filter(k => k.status === 'active' && (k.expires_at === null || k.expires_at > now)).length;
    const expired = keys.filter(k => k.status === 'expired' || (k.status === 'active' && k.expires_at !== null && k.expires_at <= now)).length;
    const banned = keys.filter(k => k.status === 'banned').length;
    res.json({ success: true, data: { total, active, banned, expired } });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// ---- Online Keys (ADMIN) ----
app.get('/api/online', requireAdmin, async (req, res) => {
  try {
    const cutoff = new Date(Date.now() - 60 * 1000).toISOString();
    const { data, error } = await supabase
      .from('keys')
      .select('key, hwid, last_seen, status, user, type, expires_at')
      .gte('last_seen', cutoff)
      .order('last_seen', { ascending: false });
    if (error) throw error;
    res.json({ success: true, data, count: data.length });
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
app.get(['/', '/web'], (req, res) => {
  res.send(`<!DOCTYPE html>
<html lang="vi">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>PLEXUS CHEAT - Quản Lý Key</title>
<style>
@keyframes fadeIn{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:translateY(0)}}
@keyframes slideUp{from{opacity:0;transform:translateY(20px)}to{opacity:1;transform:translateY(0)}}
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Segoe UI',sans-serif;background:#0a0a0f;color:#cdc8c8;min-height:100vh;background-image:linear-gradient(rgba(204,51,51,0.03) 1px,transparent 1px),linear-gradient(90deg,rgba(204,51,51,0.03) 1px,transparent 1px);background-size:40px 40px}
::-webkit-scrollbar{width:6px}::-webkit-scrollbar-track{background:#121216}::-webkit-scrollbar-thumb{background:#cc333366;border-radius:3px}
.header{background:linear-gradient(135deg,#120808,#1a0a0a);padding:20px 20px;text-align:center;border-bottom:1px solid #cc333355;position:relative}
.header h1{color:#cc3333;font-size:24px;text-shadow:0 0 12px #cc333344;letter-spacing:3px}
.header p{color:#aa7777;font-size:12px;margin-top:4px}
.container{max-width:1200px;margin:16px auto;padding:0 16px;animation:fadeIn 0.4s}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin-bottom:20px}
.stat-card{background:#121216;padding:16px;border-radius:8px;text-align:center;border:1px solid #cc333322;transition:0.2s}
.stat-card:hover{border-color:#cc333355}
.stat-card .num{font-size:28px;font-weight:700;color:#cc3333;text-shadow:0 0 8px #cc333344}
.stat-card .label{color:#aa7777;font-size:12px;margin-top:4px}
.tabs{display:flex;gap:4px;margin-bottom:16px;border-bottom:1px solid #cc333322;padding-bottom:0}
.tab{padding:10px 20px;border-radius:6px 6px 0 0;cursor:pointer;font-size:13px;font-weight:600;color:#886666;border:1px solid transparent;border-bottom:none;transition:0.2s;background:transparent;letter-spacing:0.3px}
.tab:hover{color:#cc7777;background:#1a0c0c}
.tab.active{color:#cc3333;background:#121216;border-color:#cc333322;position:relative}
.tab.active::after{content:'';position:absolute;bottom:-1px;left:0;right:0;height:1px;background:#121216}
.card{background:#121216;border-radius:8px;padding:20px;margin-bottom:16px;border:1px solid #cc333322;animation:slideUp 0.3s}
.card h3{color:#cc3333;margin-bottom:14px;font-size:15px;font-weight:600;letter-spacing:0.5px}
.form-row{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:10px;align-items:center}
.form-row input,.form-row select{flex:1;min-width:120px}
input,select,button{padding:9px 14px;border:1px solid #cc333322;border-radius:5px;background:#0d0d11;color:#cdc8c8;font-size:13px;transition:0.2s}
input:focus,select:focus{outline:none;border-color:#cc333388;background:#141418}
button{cursor:pointer;font-weight:600;letter-spacing:0.3px}
button:hover{filter:brightness(1.15)}
.btn-primary{background:linear-gradient(135deg,#cc3333,#991111);color:#fff;border:none}
.btn-danger{background:linear-gradient(135deg,#dd4444,#881111);color:#fff;border:none}
.btn-success{background:linear-gradient(135deg,#cc3333,#991111);color:#fff;border:none}
.btn-sm{padding:5px 10px;font-size:11px}
table{width:100%;border-collapse:collapse}
th,td{padding:10px;text-align:left;border-bottom:1px solid #cc333310;font-size:12px}
th{background:#0e0e12;color:#cc3333;font-weight:600;white-space:nowrap;font-size:11px;letter-spacing:0.5px}
tr:hover td{background:#18181e}
.status-active{color:#33cc33;font-weight:600}
.status-banned{color:#dd3333;font-weight:600}
.status-expired{color:#cc8833;font-weight:600}
.status-pending{color:#aa7777;font-weight:600}
.action-btn{padding:4px 10px;border-radius:4px;border:1px solid #cc333333;cursor:pointer;font-size:11px;margin:1px;background:transparent;color:#aa7777;transition:0.2s}
.action-btn:hover{background:#cc3333;color:#fff;border-color:#cc3333}
.toast{position:fixed;bottom:20px;right:20px;padding:12px 24px;border-radius:6px;color:#fff;font-size:13px;z-index:999;display:none;animation:fadeIn 0.3s;border:1px solid;max-width:400px}
.toast-success{background:#141418;border-color:#cc333388}
.toast-error{background:#141418;border-color:#dd444488}
.loading{text-align:center;padding:30px;color:#886666;font-size:13px}
.login-overlay{position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(5,5,10,0.93);display:flex;align-items:center;justify-content:center;z-index:1000}
.login-box{background:#121216;padding:36px;border-radius:10px;border:1px solid #cc333344;width:360px;animation:fadeIn 0.4s}
.login-box h2{color:#cc3333;margin-bottom:22px;text-align:center;font-size:20px;letter-spacing:1px}
.login-box input{width:100%;margin-bottom:12px;text-align:center}
.login-box button{width:100%;padding:11px;font-size:14px}
.copy-field{font-family:monospace;color:#cc3333;font-size:14px;display:block;margin-top:4px;word-break:break-all}
.tab-content{display:none}.tab-content.active{display:block}
.prefix-input{width:80px;flex:0 0 auto!important;text-align:center;text-transform:uppercase}
.hint{color:#886666;font-size:11px;margin-top:4px}
@media(max-width:768px){
.container{padding:0 10px;margin:10px auto}.stats{grid-template-columns:repeat(2,1fr);gap:8px}.stat-card{padding:12px}.stat-card .num{font-size:22px}.tabs{overflow-x:auto;white-space:nowrap;gap:2px}.tab{padding:10px 12px;font-size:12px;display:inline-block}.card{padding:14px}.card h3{font-size:13px}.form-row{gap:6px}.form-row input,.form-row select{min-width:80px;font-size:12px;padding:8px 10px}table{font-size:11px}th,td{padding:6px 4px;font-size:10px;white-space:nowrap}.action-btn{padding:3px 6px;font-size:10px}.login-box{width:90%;max-width:360px;padding:24px}.login-box h2{font-size:18px}.login-box input{padding:10px}.copy-field{font-size:12px}.toast{font-size:12px;padding:10px 16px;right:10px;bottom:10px;max-width:90%}
#tabCreate div[style*="grid-template-columns"]{grid-template-columns:1fr 1fr!important}#tabCreate div[style*="grid-template-columns"]>div:nth-child(1){grid-column:1/-1}#tabCreate div[style*="grid-template-columns"]>div:nth-child(4){grid-column:1}
}
.edit-overlay{position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(5,5,10,0.9);display:none;align-items:center;justify-content:center;z-index:999}
.edit-panel{background:#121216;border:1px solid #cc333355;border-radius:10px;padding:24px;max-width:460px;width:92%;max-height:90vh;overflow-y:auto}
.edit-panel h3{margin:0 0 16px 0;color:#cc3333;font-size:16px}
.edit-panel .row{display:flex;align-items:center;gap:10px;margin-bottom:10px;flex-wrap:wrap}
.edit-panel .row label{color:#aa7777;font-size:12px;min-width:80px}
.edit-panel .row input,.edit-panel .row select{flex:1;padding:8px 10px;min-width:0}
.edit-panel .key-display{font-family:monospace;font-size:13px;color:#cc6666;background:#0a0a0e;padding:10px 12px;border-radius:6px;margin-bottom:14px;word-break:break-all}
.edit-panel .actions{display:flex;gap:8px;flex-wrap:wrap;margin-top:14px;padding-top:14px;border-top:1px solid #222}
.edit-panel .actions .action-btn{flex:1;min-width:80px;text-align:center}
.edit-panel .close-btn{float:right;cursor:pointer;color:#886666;font-size:18px;line-height:1}
.edit-panel .close-btn:hover{color:#cc3333}

</style>
</head>
<body>
<div class="header"><h1>PLEXUS CHEAT</h1><p>Hệ thống quản lý key xác thực</p></div>
<div class="login-overlay" id="loginOverlay">
<div class="login-box">
<h2>ĐĂNG NHẬP</h2>
<input type="text" id="loginUser" placeholder="Tên đăng nhập">
<input type="password" id="loginPass" placeholder="Mật khẩu">
<button class="btn-primary" onclick="login()">ĐĂNG NHẬP</button>
<button onclick="checkHealth()" style="margin-top:8px;width:100%;background:transparent;border:1px solid #cc333344;font-size:12px;padding:8px">Kiểm tra kết nối</button>
</div>
</div>
<div class="container" id="mainContent" style="display:none">
<div class="stats" id="statsContainer"></div>
<div class="tabs">
<div class="tab active" onclick="switchTab('keys')" id="tabKeysBtn">Danh Sách Key</div>
<div class="tab" onclick="switchTab('create')" id="tabCreateBtn">Tạo Key</div>
<div class="tab" onclick="switchTab('online')" id="tabOnlineBtn">Trạng Thái Online</div>
<div class="tab" onclick="switchTab('logs')" id="tabLogsBtn">Nhật Ký</div>
</div>
<div class="tab-content active" id="tabKeys">
<div class="card">
<div class="form-row">
<input type="text" id="searchInput" placeholder="Tìm key..." oninput="renderTable()">
<select id="statusFilter" onchange="renderTable()">
<option value="all">Tất cả</option><option value="pending">Chưa kích hoạt</option><option value="active">Hoạt động</option><option value="banned">Bị khóa</option><option value="expired">Hết hạn</option>
</select>
<button class="btn-primary btn-sm" onclick="refreshData()">Làm Mới</button>
</div>
<div style="overflow-x:auto">
<table><thead><tr><th>STT</th><th>MÃ KEY</th><th>LOẠI</th><th>TRẠNG THÁI</th><th>NGÀY TẠO</th><th>HẾT HẠN</th><th>THIẾT BỊ</th><th>NGƯỜI DÙNG</th><th>GHI CHÚ</th><th>HÀNH ĐỘNG</th></tr></thead>
<tbody id="keyTableBody"><tr><td colspan="10" class="loading">Đang tải dữ liệu...</td></tr></tbody></table>
</div>
</div>
</div>
<div class="tab-content" id="tabCreate">
<div class="card">
<h3>Tạo Key Mới</h3>
<div style="display:grid;grid-template-columns:1fr 120px 80px 80px 1fr 1fr;gap:10px;margin-bottom:10px;align-items:start">
<div style="display:flex;flex-direction:column;gap:4px">
<label style="color:#aa7777;font-size:11px;font-weight:600;letter-spacing:0.3px">TIỀN TỐ + ĐỘ DÀI</label>
<div style="display:flex;align-items:center;gap:4px">
<input type="text" id="createPrefix" placeholder="PLX" maxlength="8" value="PLX" style="width:65px;flex:none;text-align:center;text-transform:uppercase;padding:9px 6px">
<span style="color:#886666;font-size:13px">-</span>
<select id="suffixGroups" style="flex:1;padding:9px 6px">
<option value="8">2 nhóm</option>
<option value="12" selected>3 nhóm</option>
<option value="16">4 nhóm</option>
<option value="20">5 nhóm</option>
<option value="24">6 nhóm</option>
</select>
</div>
</div>
<div style="display:flex;flex-direction:column;gap:4px">
<label style="color:#aa7777;font-size:11px;font-weight:600;letter-spacing:0.3px">NGÀY HẾT HẠN</label>
<input type="number" id="createDays" value="30" min="1" max="3650">
</div>
<div style="display:flex;flex-direction:column;gap:4px">
<label style="color:#aa7777;font-size:11px;font-weight:600;letter-spacing:0.3px">SỐ LƯỢNG</label>
<input type="number" id="createCount" value="1" min="1" max="500">
</div>
<div style="display:flex;flex-direction:column;gap:4px">
<label style="color:#aa7777;font-size:11px;font-weight:600;letter-spacing:0.3px">SỐ THIẾT BỊ</label>
<input type="number" id="createMaxDevices" value="1" min="1" max="100">
</div>
<div style="display:flex;flex-direction:column;gap:4px;max-width:100px">
<label style="color:#aa7777;font-size:11px;font-weight:600;letter-spacing:0.3px">LOẠI KEY</label>
<select id="createType" style="padding:9px 8px">
<option value="basic">Basic</option>
<option value="pro">Pro</option>
<option value="vip">VIP</option>
</select>
</div>
<div style="display:flex;flex-direction:column;gap:4px">
<label style="color:#aa7777;font-size:11px;font-weight:600;letter-spacing:0.3px">NGƯỜI DÙNG</label>
<input type="text" id="createUser" placeholder="Không bắt buộc">
</div>
<div style="display:flex;flex-direction:column;gap:4px">
<label style="color:#aa7777;font-size:11px;font-weight:600;letter-spacing:0.3px">GHI CHÚ</label>
<input type="text" id="createNote" placeholder="Không bắt buộc">
</div>
</div>
<div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap">
<button class="btn-success" onclick="createKey()" id="createBtn">Tạo Key</button>
<small style="color:#886666">Để trống tiền tố để tạo key random dài (32 ký tự).</small>
</div>
<div id="createResult"></div>
</div>
</div>
<div class="tab-content" id="tabOnline">
<div class="card">
<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:14px;flex-wrap:wrap;gap:8px">
<h3 style="margin:0">Trạng Thái Online</h3>
<div style="display:flex;align-items:center;gap:8px">
<small id="onlineCount" style="color:#33cc33;font-weight:600">0 key online</small>
<button class="btn-primary btn-sm" onclick="refreshOnline()">Làm Mới</button>
</div>
</div>
<div style="overflow-x:auto">
<table><thead><tr><th>STT</th><th>MÃ KEY</th><th>LOẠI</th><th>THIẾT BỊ</th><th>HWID</th><th>NGƯỜI DÙNG</th><th>LẦN CUỐI</th><th>TRẠNG THÁI</th></tr></thead>
<tbody id="onlineTableBody"><tr><td colspan="8" class="loading">Đang tải...</td></tr></tbody></table>
</div>
</div>
</div>
<div class="tab-content" id="tabLogs">
<div class="card">
<h3>Nhật Ký Hoạt Động</h3>
<div style="overflow-x:auto">
<table><thead><tr><th>ID</th><th>HÀNH ĐỘNG</th><th>KEY</th><th>CHI TIẾT</th><th>THỜI GIAN</th></tr></thead>
<tbody id="logTableBody"><tr><td colspan="5" class="loading">Đang tải...</td></tr></tbody></table>
</div>
</div>
</div>
</div>
<div class="edit-overlay" id="editOverlay" onclick="if(event.target===this)closeEditPanel()">
<div class="edit-panel" id="editPanel">
<span class="close-btn" onclick="closeEditPanel()">&times;</span>
<h3 id="editPanelTitle">Chỉnh Sửa Key</h3>
<div class="key-display" id="editKeyDisplay">-</div>
<div class="row"><label>Loại Key</label><select id="editKeyType"><option value="basic">Basic</option><option value="pro">Pro</option><option value="vip">VIP</option></select><button class="btn-primary btn-sm" onclick="saveKeyType()">Lưu</button></div>
<div class="row"><label>Trạng Thái</label><span id="editKeyStatus" style="font-weight:600"></span></div>
<div class="row"><label>Hạn Đến</label><span id="editKeyExpiry" style="color:#886666"></span></div>
<div class="row"><label>HWID</label><span id="editKeyHwid" style="font-family:monospace;font-size:11px;color:#cc6666"></span></div>
<div class="row"><label>Thiết Bị</label><span id="editKeyDevices" style="color:#886666"></span></div>
<div class="row"><label>Số TB Tối Đa</label><input type="number" id="editMaxDevices" value="1" min="1" max="100" style="max-width:80px"><button class="btn-primary btn-sm" onclick="saveMaxDevices()">Lưu</button></div>
<div class="row"><label>Người Dùng</label><span id="editKeyUser" style="color:#886666"></span></div>
<div class="row"><label>Ghi Chú</label><span id="editKeyNote" style="color:#886666"></span></div>
<div class="row" id="editExtendRow"><label>Gia Hạn (ngày)</label><input type="number" id="editExtendDays" value="30" min="1" max="3650" style="max-width:100px"><button class="btn-primary btn-sm" onclick="extendCurrentKey()">Gia Hạn</button></div>
<div class="actions">
<button class="action-btn" id="editBanBtn" onclick="toggleBanKey()">Khóa</button>
<button class="action-btn" onclick="resetHwidCurrent()">Reset HWID</button>
<button class="action-btn" onclick="deleteCurrentKey()">Xóa</button>
<button class="action-btn" onclick="copyCurrentKey()">Copy</button>
</div>
</div>
</div>
<div class="toast" id="toast"></div>
<script>
const BASE=window.location.origin;
let authToken='',allKeys=[],allLogs=[];
function login(){const u=document.getElementById('loginUser').value,p=document.getElementById('loginPass').value;if(!u||!p)return showToast('Nhập đầy đủ thông tin','error');authToken=btoa(u+':'+p);fetch(BASE+'/api/keys',{headers:{'Authorization':'Basic '+authToken}}).then(r=>{if(r.ok){document.getElementById('loginOverlay').style.display='none';document.getElementById('mainContent').style.display='block';refreshData()}else if(r.status===401){showToast('Sai thông tin đăng nhập','error');authToken=''}else{showToast('Lỗi server (HTTP '+r.status+')','error');authToken=''}}).catch(e=>{showToast('Lỗi kết nối: '+e.message,'error');authToken='';console.error('Login:',e)})}
function checkHealth(){fetch(BASE+'/api/health').then(r=>r.json()).then(d=>{showToast('Server OK | Admin: '+d.admin+' | Supabase: '+d.supabase+(d.keys_count!==undefined?' | Keys: '+d.keys_count:''),'success')}).catch(e=>{showToast('Server không phản hồi: '+e.message,'error');console.error('Health:',e)})}
function showToast(m,t){const e=document.getElementById('toast');e.textContent=m;e.className='toast toast-'+t;e.style.display='block';setTimeout(()=>e.style.display='none',3500)}
function api(p,o){o=o||{};o.headers=o.headers||{};o.headers['Authorization']='Basic '+authToken;return fetch(BASE+p,o).then(r=>r.json())}
function st(x){if(x.status==="banned")return{cls:"status-banned",txt:"Bị khóa"};if(x.status==="expired")return{cls:"status-expired",txt:"Hết hạn"};if(!x.expires_at)return{cls:"status-pending",txt:"Chưa kích hoạt"};var e=new Date(x.expires_at);if(e<=new Date())return{cls:"status-expired",txt:"Hết hạn"};return{cls:"status-active",txt:"Hoạt động"}}
function getDevInfo(hwid){if(!hwid||hwid===''||hwid==='[]')return{count:0,list:[]};try{if(hwid.startsWith('[')){var arr=JSON.parse(hwid);return{count:arr.length,list:arr}}return{count:1,list:[hwid]}}catch(e){return{count:0,list:[]}}}
let onlineTimer;function switchTab(t){document.querySelectorAll('.tab').forEach(x=>x.classList.remove('active'));document.querySelectorAll('.tab-content').forEach(x=>x.classList.remove('active'));const cap=t.charAt(0).toUpperCase()+t.slice(1);document.getElementById('tab'+cap+'Btn').classList.add('active');document.getElementById('tab'+cap).classList.add('active');if(onlineTimer)clearInterval(onlineTimer);if(t==='online'){refreshOnline();onlineTimer=setInterval(refreshOnline,5000)}}
function refreshData(){Promise.all([api('/api/keys').then(r=>allKeys=r.data||[]),api('/api/logs').then(r=>allLogs=r.data||[]),api('/api/stats').then(r=>{if(r.data)renderStats(r.data)})]).then(()=>{renderTable();renderLogs()}).catch(e=>{console.error('refreshData:',e);showToast('Lỗi tải dữ liệu','error')})}
function refreshOnline(){api('/api/online').then(r=>{renderOnline(r.data||[]);const e=document.getElementById('onlineCount');if(e)e.textContent=r.count+' key online'}).catch(()=>{})}
function renderOnline(d){const t=document.getElementById('onlineTableBody');if(!t)return;if(!d.length){t.innerHTML='<tr><td colspan="8" style="text-align:center;color:#886666">Không có key online</td></tr>';return}t.innerHTML=d.map((x,i)=>{var st_=st(x);var stxt='<span style="color:'+(st_.cls==='status-active'?'#33cc33':st_.cls==='status-pending'?'#aa7777':'#dd3333')+'">'+st_.txt+'</span>';const ls=x.last_seen?new Date(x.last_seen).toLocaleTimeString('vi-VN'):'-';const tp=x.type||'basic';var di=getDevInfo(x.hwid);var md=x.max_devices||1;return '<tr><td>'+(i+1)+'</td><td class="copy-field">'+x.key+'</td><td style="font-size:11px">'+(tp==='vip'?'<span style="color:#ffcc00;font-weight:600">VIP</span>':tp==='pro'?'<span style="color:#cc66ff;font-weight:600">Pro</span>':'<span style="color:#aa7777">Basic</span>')+'</td><td style="font-size:11px">'+(di.count>0?'<span title="'+di.list.join(', ')+'" style="cursor:help">'+di.count+'/'+md+' TB</span>':'<span style="color:#666">0/'+md+' TB</span>')+'</td><td style="font-family:monospace;font-size:11px;color:#cc6666">'+(x.hwid||'-')+'</td><td>'+(x.user||'-')+'</td><td>'+ls+'</td><td>'+stxt+'</td></tr>'}).join('')}
function renderStats(d){document.getElementById('statsContainer').innerHTML='<div class="stat-card"><div class="num">'+d.total+'</div><div class="label">Tổng Key</div></div><div class="stat-card"><div class="num">'+d.active+'</div><div class="label">Hoạt Động</div></div><div class="stat-card"><div class="num">'+d.banned+'</div><div class="label">Bị Khóa</div></div><div class="stat-card"><div class="num">'+d.expired+'</div><div class="label">Hết Hạn</div></div>'}
function renderTable(){const s=document.getElementById('searchInput').value.toLowerCase(),f=document.getElementById('statusFilter').value;let k=allKeys;if(s)k=k.filter(x=>x.key.toLowerCase().includes(s));if(f!=='all')k=k.filter(function(x){var s_=st(x);return s_.cls==='status-'+f||s_.txt.toLowerCase()===f});const t=document.getElementById('keyTableBody');if(!k.length){t.innerHTML='<tr><td colspan="10" style="text-align:center;color:#886666">Không có dữ liệu</td></tr>';return}t.innerHTML=k.map((x,i)=>{var s_=st(x);var c=s_.cls,stxt=s_.txt,tp=x.type||'basic';var di=getDevInfo(x.hwid);var md=x.max_devices||1;var devDisplay=di.count>0?'<span title="'+di.list.join(', ')+'" style="cursor:help">'+di.count+'/'+md+' TB</span>':'<span style="color:#666">0/'+md+' TB</span>';return '<tr><td>'+(i+1)+'</td><td class="copy-field">'+x.key+'</td><td style="font-size:11px">'+(tp==='vip'?'<span style="color:#ffcc00;font-weight:600">VIP</span>':tp==='pro'?'<span style="color:#cc66ff;font-weight:600">Pro</span>':'<span style="color:#aa7777">Basic</span>')+'</td><td class="'+c+'">'+stxt+'</td><td>'+new Date(x.created_at).toLocaleDateString('vi-VN')+'</td><td>'+(x.expires_at?new Date(x.expires_at).toLocaleDateString('vi-VN'):'<span style=color:#666>Chưa kích hoạt</span>')+'</td><td style="font-size:11px">'+devDisplay+'</td><td>'+(x.user||'-')+'</td><td>'+(x.note||'-')+'</td><td nowrap><button class="action-btn" onclick="showEditPanel(\\''+x.key.replace(/'/g,"\\'")+'\\')">Chỉnh sửa</button></td></tr>'}).join('')}
function renderLogs(){const t=document.getElementById('logTableBody');if(!allLogs.length){t.innerHTML='<tr><td colspan="5" style="text-align:center;color:#886666">Không có dữ liệu</td></tr>';return}t.innerHTML=allLogs.slice(0,50).map(x=>'<tr><td>'+x.id+'</td><td style="color:#cc3333;font-weight:600">'+x.action+'</td><td class="copy-field">'+x.key+'</td><td>'+x.detail+'</td><td>'+new Date(x.created_at).toLocaleString('vi-VN')+'</td></tr>').join('')}
function createKey(){const p=document.getElementById('createPrefix').value.trim(),d=document.getElementById('createDays').value,c=document.getElementById('createCount').value,g=parseInt(document.getElementById('suffixGroups').value),u=document.getElementById('createUser').value.trim(),n=document.getElementById('createNote').value.trim(),t=document.getElementById('createType').value,md=document.getElementById('createMaxDevices').value,btn=document.getElementById('createBtn');const body={days:parseInt(d),count:parseInt(c),type:t,max_devices:parseInt(md)||1};if(p){body.prefix=p;body.suffixLength=g}if(u)body.user=u;if(n)body.note=n;btn.disabled=true;btn.textContent='Đang tạo...';api('/api/keys',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)}).then(r=>{if(r.success){let html='<div style="background:#0e0e12;padding:14px;border-radius:6px;border:1px solid #cc333366;margin-top:10px">';const d=(Array.isArray(r.data)?r.data[0]:r.data);const exp=d.expires_at?new Date(d.expires_at).toLocaleDateString('vi-VN'):'Kích hoạt lần đầu ('+d.duration_days+' ngày)';if(r.count>1){html+='<div style="color:#cc3333;font-weight:600;margin-bottom:8px">Đã tạo '+r.count+' key (hạn: '+exp+'):</div><div style="max-height:300px;overflow-y:auto">';r.data.forEach((x,i)=>{html+='<div style="padding:6px 10px;margin:3px 0;background:#0d0d11;border-radius:4px;border:1px solid #cc333315;display:flex;align-items:center;gap:8px">'+(i+1)+'. <span class="copy-field" style="font-size:13px;margin:0;flex:1">'+x.key+'</span><button class="action-btn" onclick="copyKey(\\''+x.key+'\\')">Copy</button></div>'});html+='</div>'}else{html+='<div style="color:#cc3333;font-weight:600;margin-bottom:6px">Key mới đã tạo:</div><span class="copy-field">'+r.data.key+'</span><div style="color:#886666;font-size:12px;margin-top:6px">Hết hạn: '+exp+'</div>'}html+='</div>';document.getElementById('createResult').innerHTML=html;refreshData()}else showToast(r.message,'error')}).catch(()=>showToast('Lỗi tạo key','error')).finally(()=>{btn.disabled=false;btn.textContent='Tạo Key'})}
function copyKey(k){navigator.clipboard.writeText(k).then(()=>showToast('Đã copy: '+k,'success'))}
let editKeyData=null;
function showEditPanel(k){editKeyData=allKeys.find(x=>x.key===k);const x=editKeyData;if(!x)return showToast('Không tìm thấy key','error');document.getElementById('editPanelTitle').textContent='Chỉnh Sửa Key';document.getElementById('editKeyDisplay').textContent=x.key;document.getElementById('editKeyType').value=x.type||'basic';var es_=st(x);document.getElementById('editKeyStatus').textContent=es_.txt;document.getElementById('editKeyStatus').style.color=es_.cls==='status-active'?'#33cc33':es_.cls==='status-pending'?'#aa7777':'#dd3333';document.getElementById('editKeyExpiry').textContent=x.expires_at?new Date(x.expires_at).toLocaleString('vi-VN'):'Chưa kích hoạt';var di=getDevInfo(x.hwid);var md=x.max_devices||1;document.getElementById('editKeyHwid').textContent=di.count>0?di.list.join(', '):'Chưa có';document.getElementById('editKeyDevices').textContent=di.count+'/'+md+' thiết bị';document.getElementById('editMaxDevices').value=md;document.getElementById('editKeyUser').textContent=x.user||'-';document.getElementById('editKeyNote').textContent=x.note||'-';const banBtn=document.getElementById('editBanBtn');banBtn.textContent=x.status==='active'?'Khóa (Ban)':'Mở (Unban)';banBtn.style.background=x.status==='active'?'#cc3333':'#336633';document.getElementById('editOverlay').style.display='flex'}
function closeEditPanel(){document.getElementById('editOverlay').style.display='none';editKeyData=null}
function saveKeyType(){const x=editKeyData;if(!x)return;const t=document.getElementById('editKeyType').value;if(t===x.type)return showToast('Loại key không thay đổi','success');api('/api/keys/'+encodeURIComponent(x.key)+'/type',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({type:t})}).then(r=>{showToast(r.message,r.success?'success':'error');if(r.success){x.type=t;refreshData();closeEditPanel()}})}
function extendCurrentKey(){const x=editKeyData;if(!x)return;const d=document.getElementById('editExtendDays').value;if(!d||isNaN(d)||parseInt(d)<1)return;api('/api/keys/'+encodeURIComponent(x.key)+'/extend',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({days:parseInt(d)})}).then(r=>{showToast(r.message,r.success?'success':'error');if(r.success){refreshData();closeEditPanel()}})}
function toggleBanKey(){const x=editKeyData;if(!x)return;const isBan=x.status==='active',action=isBan?'ban':'unban',msg=isBan?'Khóa key '+x.key+'?':'Mở key '+x.key+'?';if(!confirm(msg))return;api('/api/keys/'+encodeURIComponent(x.key)+'/'+action,{method:'POST'}).then(r=>{showToast(r.message,r.success?'success':'error');if(r.success){refreshData();closeEditPanel()}})}
function resetHwidCurrent(){const x=editKeyData;if(!x)return;if(!confirm('Reset HWID cho key '+x.key+'?'))return;api('/api/keys/'+encodeURIComponent(x.key)+'/reset-hwid',{method:'POST'}).then(r=>{showToast(r.message,r.success?'success':'error');if(r.success){refreshData();closeEditPanel()}})}
function deleteCurrentKey(){const x=editKeyData;if(!x)return;if(!confirm('Xóa key '+x.key+'?'))return;api('/api/keys/'+encodeURIComponent(x.key),{method:'DELETE'}).then(r=>{showToast(r.message,r.success?'success':'error');if(r.success){refreshData();closeEditPanel()}})}
function copyCurrentKey(){const x=editKeyData;if(!x)return;navigator.clipboard.writeText(x.key).then(()=>showToast('Đã copy: '+x.key,'success'))}
function saveMaxDevices(){const x=editKeyData;if(!x)return;const md=parseInt(document.getElementById('editMaxDevices').value);if(!md||md<1||md>100)return showToast('Số thiết bị không hợp lệ (1-100)','error');api('/api/keys/'+encodeURIComponent(x.key)+'/max-devices',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({max_devices:md})}).then(r=>{showToast(r.message,r.success?'success':'error');if(r.success){x.max_devices=md;refreshData();closeEditPanel()}})}
</script>
</body>
</html>`);
});

// ======================== START ========================
app.listen(PORT, () => {
  console.log(`ROX Auth Server running on port ${PORT}`);
  console.log(`Web UI: http://localhost:${PORT}/`);
  console.log(`API:   http://localhost:${PORT}/api/verify?key=xxx&hwid=xxx`);
});
