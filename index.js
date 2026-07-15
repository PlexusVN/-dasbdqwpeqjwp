// ============================================================
//  ROX CHEATS - NODE.JS AUTH SERVER (Multi-Product)
//  Deploy lên Render.com, Supabase làm database
//  UptimeRobot gọi GET /api/health mỗi 5 phút để giữ server
// ============================================================
//  HƯỚNG DẪN:
//  1. Tạo Supabase project, chạy schema.sql (AUTH/sql/schema.sql)
//  2. Push code lên GitHub
//  3. Render.com > New > Web Service > kết nối GitHub repo
//  4. Set environment variables:
//     SUPABASE_URL, SUPABASE_SERVICE_KEY, ADMIN_USER, ADMIN_PASS
//  5. UptimeRobot > New Monitor > HTTP(s) >
//     URL: https://ten-render-project.onrender.com/api/health
//     Interval: 5 minutes
//  6. Deploy
// ============================================================

const express = require('express');
const cors = require('cors');
const { createClient } = require('@supabase/supabase-js');

const app = express();
const PORT = process.env.PORT || 3000;

// ---- CORS (mặc định same-origin; set env CORS_ORIGIN=* nếu cần) ----
const corsOrigin = process.env.CORS_ORIGIN || false;
app.use(cors({ origin: corsOrigin, methods: ['GET', 'POST', 'DELETE', 'OPTIONS'] }));
app.use(express.json());
app.set('trust proxy', true);           // lấy IP thật từ Render LB

// ---- Supabase client ----
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_SERVICE_KEY;
if (!supabaseUrl || !supabaseKey) {
  console.error('FATAL: Missing SUPABASE_URL or SUPABASE_SERVICE_KEY env vars');
  process.exit(1);
}
const supabase = createClient(supabaseUrl, supabaseKey);

// ---- Admin auth ----
const ADMIN_USER = process.env.ADMIN_USER;
const ADMIN_PASS = process.env.ADMIN_PASS;
if (!ADMIN_USER || !ADMIN_PASS) {
  console.error('FATAL: ADMIN_USER and ADMIN_PASS environment variables must be set');
  process.exit(1);
}

// ---- Startup info ----
console.log('Supabase:', supabaseUrl ? 'Connected' : 'Not set');
console.log('Admin user:', ADMIN_USER);
console.log('Auth endpoint:', '/api/verify?key=xxx&hwid=xxx&secret=xxx');

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

// ---- Helper: resolve product from secret ----
async function resolveProduct(secret) {
  if (!secret) return null;
  const { data } = await supabase.from('products').select('id, name').eq('secret', secret).maybeSingle();
  return data || null;
}

// ---- Health Check (PUBLIC - minimal; full detail if admin auth) ----
app.get('/api/health', async (req, res) => {
  try {
    // If admin auth provided, return full details
    const auth = req.headers.authorization;
    let isAdmin = false;
    if (auth && auth.startsWith('Basic ')) {
      const decoded = Buffer.from(auth.slice(6), 'base64').toString();
      const [user, pass] = decoded.split(':');
      if (user === ADMIN_USER && pass === ADMIN_PASS) isAdmin = true;
    }

    if (!isAdmin) {
      return res.json({ success: true, message: 'Server is running' });
    }

    const { count, error } = await supabase.from('keys').select('*', { count: 'exact', head: true });
    const { data: products } = await supabase.from('products').select('name');
    if (error) throw error;
    res.json({
      success: true, message: 'Server is running',
      supabase: 'connected',
      keys_count: count || 0,
      products: products ? products.map(p => p.name) : []
    });
  } catch (err) {
    res.json({
      success: true, message: 'Server is running',
      supabase: 'error'
    });
  }
});

// ---- Utility ----
function generateKey(length = 32) {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  const maxValid = 256 - (256 % chars.length);
  let key = '';
  const buffer = new Uint8Array(256);
  while (key.length < length) {
    crypto.getRandomValues(buffer);
    for (let i = 0; i < 256 && key.length < length; i++) {
      if (buffer[i] < maxValid) {
        key += chars[buffer[i] % chars.length];
      }
    }
  }
  return key.match(/.{4}/g).join('-');
}

// ======================== API ROUTES ========================

// ---- Rate limiter (in-memory, cho verify) ----
const rateLimitMap = new Map();
function checkRateLimit(ip, maxReqs = 5, windowMs = 1000) {
  const now = Date.now();
  if (!rateLimitMap.has(ip)) rateLimitMap.set(ip, []);
  const timestamps = rateLimitMap.get(ip).filter(t => now - t < windowMs);
  if (timestamps.length >= maxReqs) return false;
  timestamps.push(now);
  rateLimitMap.set(ip, timestamps);
  return true;
}

// ---- Verify Key (PUBLIC) ----
app.get('/api/verify', async (req, res) => {
  try {
    const { key, hwid, secret } = req.query;
    if (!key || !hwid) {
      return res.json({ success: false, status: 'invalid', message: 'Authentication failed' });
    }

    // Rate limit: tối đa 5 request/giây từ 1 IP
    if (!checkRateLimit(req.ip, 5, 1000)) {
      return res.json({ success: false, status: 'invalid', message: 'Authentication failed' });
    }

    // 1. Resolve product từ secret
    let product = null;
    if (secret) {
      product = await resolveProduct(secret);
      if (!product) {
        // Không phân biệt secret sai → dùng chung status 'invalid'
        return res.json({ success: false, status: 'invalid', message: 'Authentication failed' });
      }
    }

    // 2. Atomic: toàn bộ check (status, expiry, HWID) trong 1 RPC lock
    const { data: rpc, error: rpcErr } = await supabase.rpc('register_hwid', {
      p_key: key,
      p_hwid: hwid,
    });
    if (rpcErr) throw rpcErr;

    // 3. Kiểm tra product match
    if (product && rpc.product_id !== product.id) {
      return res.json({ success: false, status: 'invalid', message: 'Authentication failed' });
    }

    // 4. Nếu RPC trả về không valid → luôn trả generic error
    if (rpc.status !== 'valid') {
      return res.json({ success: false, status: 'invalid', message: 'Authentication failed' });
    }

    // 5. Log
    await supabase.from('activity_log').insert({
      action: 'verify',
      key: key,
      detail: `Verified from HWID: ${hwid}${product ? ' | Product: ' + product.name : ''} | IP: ${req.ip}`,
      ip: req.ip,
    });

    res.json({
      success: true,
      status: 'valid',
      message: 'Authentication successful',
      expires_at: rpc.expires_at,
      server_time: new Date().toISOString(),
      type: rpc.type || 'basic',
    });
  } catch (err) {
    // Luôn trả generic, không leak internal error
    res.json({ success: false, status: 'invalid', message: 'Authentication failed' });
  }
});

// ---- Create Key(s) (ADMIN) ----
app.post('/api/keys', requireAdmin, async (req, res) => {
  try {
    const { days = 30, note = '', user = '', prefix: rawPrefix = '', count = 1,
            suffixLength: rawSuffixLen, type: rawType = 'basic', max_devices = 1,
            product_id = 1, custom_key } = req.body;

    // Validate product_id
    const { data: product } = await supabase.from('products').select('id').eq('id', product_id).maybeSingle();
    if (!product) return res.json({ success: false, message: 'Invalid product_id' });

    const keyType = ['basic', 'pro', 'vip'].includes(rawType) ? rawType : 'basic';
    const now = new Date();
    const durationDays = parseInt(days) || 30;
    const maxDevices = Math.min(Math.max(parseInt(max_devices) || 1, 1), 100);

    // Handle custom key (manual input mode)
    if (custom_key) {
      const trimmedKey = custom_key.trim();
      if (!trimmedKey) return res.json({ success: false, message: 'Custom key is empty' });
      if (trimmedKey.length < 4) return res.json({ success: false, message: 'Custom key too short (min 4)' });
      // Check duplicate
      const { data: exist } = await supabase.from('keys').select('id').eq('key', trimmedKey).maybeSingle();
      if (exist) return res.json({ success: false, message: 'Key already exists' });

      const { error: insertError } = await supabase.from('keys').insert({
        key: trimmedKey, product_id, status: 'active', created_at: now.toISOString(),
        expires_at: null, duration_days: durationDays, hwid: '[]', max_devices: maxDevices,
        user: user || '', note: note || '', type: keyType,
      });
      if (insertError) {
        if (insertError.code === '23505') return res.json({ success: false, message: 'Key already exists' });
        throw insertError;
      }

      await supabase.from('activity_log').insert({
        action: 'create', key: trimmedKey, detail: `Created key manually, ${days} days, product_id: ${product_id} | IP: ${req.ip}`, ip: req.ip,
      });

      return res.json({
        success: true, message: 'Key created',
        data: { key: trimmedKey, duration_days: durationDays, type: keyType },
        count: 1,
      });
    }

    // Auto-generate keys
    const num = Math.min(Math.max(parseInt(count) || 1, 1), 500);
    const usePrefix = rawPrefix && rawPrefix.trim();
    const suffixLen = parseInt(rawSuffixLen) || (usePrefix ? 12 : 32);

    const keys = [];
    for (let i = 0; i < num; i++) {
      const randomPart = generateKey(suffixLen);
      const newKey = usePrefix ? rawPrefix.trim().toUpperCase() + '-' + randomPart : randomPart;
      keys.push({ key: newKey, duration_days: durationDays, type: keyType });
    }

    const inserts = keys.map(k => ({
      key: k.key, product_id: product_id, status: 'active', created_at: now.toISOString(),
      expires_at: null, duration_days: durationDays, hwid: '[]', max_devices: maxDevices,
      user: user || '', note: note || '', type: keyType,
    }));

    const { error: insertError } = await supabase.from('keys').insert(inserts);
    if (insertError) throw insertError;

    await supabase.from('activity_log').insert({
      action: 'create', key: num > 1 ? `${num} keys` : keys[0].key,
      detail: `Created ${num} key(s), ${days} days, product_id: ${product_id}. Note: ${note} | IP: ${req.ip}`, ip: req.ip,
    });

    res.json({
      success: true,
      message: `Created ${num} key(s) successfully`,
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
    const { product_id, status } = req.query;
    let query = supabase.from('keys').select('*').order('created_at', { ascending: false });
    if (product_id) query = query.eq('product_id', parseInt(product_id));
    if (status) query = query.eq('status', status);
    const { data: keys, error } = await query;
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
    if (!keys || keys.length === 0) return res.status(404).json({ success: false, message: 'Key not found' });
    // Resolve product name
    const { data: product } = await supabase.from('products').select('name').eq('id', keys[0].product_id).maybeSingle();
    keys[0].product_name = product ? product.name : 'unknown';
    res.json({ success: true, data: keys[0] });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// ---- Delete Key (ADMIN) ----
app.delete('/api/keys/:key', requireAdmin, async (req, res) => {
  try {
    const { data: keys } = await supabase.from('keys').select('key').eq('key', req.params.key);
    if (!keys || keys.length === 0) return res.status(404).json({ success: false, message: 'Key not found' });

    await supabase.from('keys').delete().eq('key', req.params.key);
    await supabase.from('activity_log').insert({ action: 'delete', key: req.params.key, detail: `Deleted key | IP: ${req.ip}`, ip: req.ip });

    res.json({ success: true, message: 'Key deleted' });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// ---- Ban Key (ADMIN) ----
app.post('/api/keys/:key/ban', requireAdmin, async (req, res) => {
  try {
    const { data: keys } = await supabase.from('keys').select('key,status').eq('key', req.params.key);
    if (!keys || keys.length === 0) return res.status(404).json({ success: false, message: 'Key not found' });
    if (keys[0].status === 'banned') return res.json({ success: false, message: 'Key already banned' });

    await supabase.from('keys').update({ status: 'banned' }).eq('key', req.params.key);
    await supabase.from('activity_log').insert({ action: 'ban', key: req.params.key, detail: `Banned key | IP: ${req.ip}`, ip: req.ip });

    res.json({ success: true, message: 'Key banned' });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// ---- Unban Key (ADMIN) ----
app.post('/api/keys/:key/unban', requireAdmin, async (req, res) => {
  try {
    const { data: keys } = await supabase.from('keys').select('key,status').eq('key', req.params.key);
    if (!keys || keys.length === 0) return res.status(404).json({ success: false, message: 'Key not found' });
    if (keys[0].status !== 'banned') return res.json({ success: false, message: 'Key is not banned' });

    await supabase.from('keys').update({ status: 'active' }).eq('key', req.params.key);
    await supabase.from('activity_log').insert({ action: 'unban', key: req.params.key, detail: `Unbanned key | IP: ${req.ip}`, ip: req.ip });

    res.json({ success: true, message: 'Key unbanned' });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// ---- Reset HWID (ADMIN) ----
app.post('/api/keys/:key/reset-hwid', requireAdmin, async (req, res) => {
  try {
    const { data: keys } = await supabase.from('keys').select('key,hwid').eq('key', req.params.key);
    if (!keys || keys.length === 0) return res.status(404).json({ success: false, message: 'Key not found' });

    const oldHwid = keys[0].hwid || '[]';
    await supabase.from('keys').update({ hwid: '[]' }).eq('key', req.params.key);
    await supabase.from('activity_log').insert({ action: 'reset_hwid', key: req.params.key, detail: `Reset HWID (old: ${oldHwid}) | IP: ${req.ip}`, ip: req.ip });

    res.json({ success: true, message: 'HWID reset' });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// ---- Extend Key (ADMIN) ----
app.post('/api/keys/:key/extend', requireAdmin, async (req, res) => {
  try {
    const days = parseInt(req.body.days);
    if (!days || days < 1) return res.json({ success: false, message: 'Invalid days' });

    const { data: keys } = await supabase.from('keys').select('key,expires_at').eq('key', req.params.key);
    if (!keys || keys.length === 0) return res.status(404).json({ success: false, message: 'Key not found' });

    const currentExpiry = new Date(keys[0].expires_at);
    const now = new Date();
    const baseDate = currentExpiry > now ? currentExpiry : now;
    const newExpiry = new Date(baseDate.getTime() + days * 24 * 60 * 60 * 1000);

    await supabase.from('keys').update({ expires_at: newExpiry.toISOString(), status: 'active' }).eq('key', req.params.key);
    await supabase.from('activity_log').insert({ action: 'extend', key: req.params.key, detail: `Extended ${days} days, new expiry: ${newExpiry.toISOString()} | IP: ${req.ip}`, ip: req.ip });

    res.json({ success: true, message: `Extended ${days} days`, data: { new_expires_at: newExpiry.toISOString() } });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// ---- Change Key Type (ADMIN) ----
app.post('/api/keys/:key/type', requireAdmin, async (req, res) => {
  try {
    const { type } = req.body;
    if (!['basic', 'pro', 'vip'].includes(type)) {
      return res.json({ success: false, message: 'Invalid type (basic, pro, vip)' });
    }
    const { data, error } = await supabase.from('keys').update({ type }).eq('key', req.params.key).select();
    if (error) throw error;
    if (!data || data.length === 0) return res.status(404).json({ success: false, message: 'Key not found' });
    await supabase.from('activity_log').insert({ action: 'change_type', key: req.params.key, detail: `Changed type to ${type} | IP: ${req.ip}`, ip: req.ip });
    res.json({ success: true, message: `Changed type to ${type}` });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// ---- Update Max Devices (ADMIN) ----
app.post('/api/keys/:key/max-devices', requireAdmin, async (req, res) => {
  try {
    const maxDevices = parseInt(req.body.max_devices);
    if (!maxDevices || maxDevices < 1 || maxDevices > 100) {
      return res.json({ success: false, message: 'Invalid max devices (1-100)' });
    }
    const { data, error } = await supabase.from('keys').update({ max_devices: maxDevices }).eq('key', req.params.key).select();
    if (error) throw error;
    if (!data || data.length === 0) return res.status(404).json({ success: false, message: 'Key not found' });
    await supabase.from('activity_log').insert({ action: 'change_max_devices', key: req.params.key, detail: `Changed max devices to ${maxDevices} | IP: ${req.ip}`, ip: req.ip });
    res.json({ success: true, message: `Changed max devices to ${maxDevices}` });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// ---- Stats (ADMIN) ----
app.get('/api/stats', requireAdmin, async (req, res) => {
  try {
    const { product_id } = req.query;
    let query = supabase.from('keys').select('status,expires_at,product_id');
    if (product_id) query = query.eq('product_id', parseInt(product_id));
    const { data: keys, error } = await query;
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
    let query = supabase
      .from('keys')
      .select('key, hwid, last_seen, status, user, type, expires_at, product_id')
      .gte('last_seen', cutoff)
      .order('last_seen', { ascending: false });

    const { product_id } = req.query;
    if (product_id) query = query.eq('product_id', parseInt(product_id));

    const { data, error } = await query;
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

// ======================== PRODUCT ROUTES ========================

// ---- List Products (ADMIN) ----
app.get('/api/products', requireAdmin, async (req, res) => {
  try {
    const { data, error } = await supabase.from('products').select('id, name, secret, created_at').order('id');
    if (error) throw error;
    res.json({ success: true, data });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// ---- Check Product Password (ADMIN) ----
app.post('/api/products/check-password', requireAdmin, async (req, res) => {
  try {
    const { id, password } = req.body;
    if (!id || !password) return res.json({ success: false, message: 'id and password required' });
    const { data } = await supabase.from('products').select('id, name, password').eq('id', parseInt(id)).maybeSingle();
    if (!data) return res.json({ success: false, message: 'Product not found' });
    if (data.password !== password) return res.json({ success: false, message: 'Sai mat khau product' });
    res.json({ success: true, message: 'Password correct' });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// ---- Create Product (ADMIN) ----
app.post('/api/products', requireAdmin, async (req, res) => {
  try {
    const { name, secret, password } = req.body;
    if (!name || !secret) return res.json({ success: false, message: 'name and secret required' });
    if (!password) return res.json({ success: false, message: 'password required' });

    const { data, error } = await supabase.from('products').insert({ name, secret, password }).select();
    if (error) {
      if (error.message?.includes('unique'))
        return res.json({ success: false, message: 'Product name or secret already exists' });
      throw error;
    }

    await supabase.from('activity_log').insert({ action: 'create_product', key: name, detail: `Created product: ${name} | IP: ${req.ip}`, ip: req.ip });
    res.json({ success: true, data: { id: data[0].id, name: data[0].name, secret: data[0].secret }, message: `Product '${name}' created` });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// ---- Delete Product (ADMIN) ----
app.delete('/api/products/:id', requireAdmin, async (req, res) => {
  try {
    const id = parseInt(req.params.id);
    const { password } = req.body;
    if (!password) return res.json({ success: false, message: 'password required' });

    // Fetch product with password
    const { data: product } = await supabase.from('products').select('id, name, password').eq('id', id).maybeSingle();
    if (!product) return res.status(404).json({ success: false, message: 'Product not found' });
    if (product.password !== password) return res.json({ success: false, message: 'Sai mat khau product' });

    // Check if keys exist for this product
    const { count } = await supabase.from('keys').select('*', { count: 'exact', head: true }).eq('product_id', id);
    if (count > 0) {
      return res.json({ success: false, message: `Cannot delete: ${count} key(s) still use this product` });
    }

    const { data, error } = await supabase.from('products').delete().eq('id', id).select();
    if (error) throw error;
    if (!data || data.length === 0) return res.status(404).json({ success: false, message: 'Product not found' });

    await supabase.from('activity_log').insert({ action: 'delete_product', key: data[0].name, detail: `Deleted product: ${data[0].name} | IP: ${req.ip}`, ip: req.ip });
    res.json({ success: true, message: `Product '${data[0].name}' deleted` });
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
.product-badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:10px;font-weight:600;letter-spacing:0.3px}
.product-internal{background:#1a0a0a;color:#cc3333;border:1px solid #cc333355}
.product-external{background:#0a1a0a;color:#33cc33;border:1px solid #33cc3355}
.product-mobile{background:#0a0a1a;color:#6666ff;border:1px solid #6666ff55}
@media(max-width:768px){
.container{padding:0 10px;margin:10px auto}.stats{grid-template-columns:repeat(2,1fr);gap:8px}.stat-card{padding:12px}.stat-card .num{font-size:22px}.tabs{overflow-x:auto;white-space:nowrap;gap:2px}.tab{padding:10px 12px;font-size:12px;display:inline-block}.card{padding:14px}.card h3{font-size:13px}.form-row{gap:6px}.form-row input,.form-row select{min-width:80px;font-size:12px;padding:8px 10px}table{font-size:11px}th,td{padding:6px 4px;font-size:10px;white-space:nowrap}.action-btn{padding:3px 6px;font-size:10px}.login-box{width:90%;max-width:360px;padding:24px}.login-box h2{font-size:18px}.login-box input{padding:10px}.copy-field{font-size:12px}.toast{font-size:12px;padding:10px 16px;right:10px;bottom:10px;max-width:90%}
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
<div class="header"><h1>PLEXUS CHEAT</h1><p>Multi-Product Auth System</p></div>
<div class="login-overlay" id="loginOverlay">
<div class="login-box">
<h2>DANG NHAP</h2>
<input type="text" id="loginUser" placeholder="Ten dang nhap">
<input type="password" id="loginPass" placeholder="Mat khau">
<button class="btn-primary" onclick="login()">DANG NHAP</button>
<button onclick="checkHealth()" style="margin-top:8px;width:100%;background:transparent;border:1px solid #cc333344;font-size:12px;padding:8px">Kiem tra ket noi</button>
</div>
</div>
<div class="container" id="mainContent" style="display:none">
<div class="stats" id="statsContainer"></div>
<div class="tabs">
<div class="tab active" onclick="switchTab('keys')" id="tabKeysBtn">Danh Sach Key</div>
<div class="tab" onclick="switchTab('create')" id="tabCreateBtn">Tao Key</div>
<div class="tab" onclick="switchTab('online')" id="tabOnlineBtn">Trang Thai Online</div>
<div class="tab" onclick="switchTab('logs')" id="tabLogsBtn">Nhat Ky</div>
<div class="tab" onclick="switchTab('products')" id="tabProductsBtn">Quan Ly Product</div>
</div>
<div class="tab-content active" id="tabKeys">
<div class="card">
<div class="form-row">
<input type="text" id="searchInput" placeholder="Tim key..." oninput="renderTable()">
<select id="productFilter" onchange="renderTable()"></select>
<select id="statusFilter" onchange="renderTable()">
<option value="all">Tat ca</option><option value="pending">Chua kich hoat</option><option value="active">Hoat dong</option><option value="banned">Bi khoa</option><option value="expired">Het han</option>
</select>
<button class="btn-primary btn-sm" onclick="refreshData()">Lam Moi</button>
</div>
<div style="overflow-x:auto">
<table><thead><tr><th>STT</th><th>MA KEY</th><th>PRODUCT</th><th>LOAI</th><th>TRANG THAI</th><th>NGAY TAO</th><th>HET HAN</th><th>THIET BI</th><th>HWID</th><th>NGUOI DUNG</th><th>GHI CHU</th><th>HANH DONG</th></tr></thead>
<tbody id="keyTableBody"><tr><td colspan="12" class="loading">Dang tai du lieu...</td></tr></tbody></table>
</div>
</div>
</div>
<div class="tab-content" id="tabCreate">
<div class="card">
<h3>Tao Key Moi</h3>
<div style="display:flex;gap:16px;margin-bottom:14px;padding:10px 14px;background:#0e0e12;border-radius:6px;border:1px solid #cc333322">
<label style="font-size:13px;display:flex;align-items:center;gap:6px;cursor:pointer"><input type="radio" name="keyMode" value="auto" checked onchange="toggleKeyMode()"> Tu dong (tien to + random)</label>
<label style="font-size:13px;display:flex;align-items:center;gap:6px;cursor:pointer"><input type="radio" name="keyMode" value="manual" onchange="toggleKeyMode()"> Nhap tay</label>
</div>
<div id="autoKeyFields" style="display:grid;grid-template-columns:1fr 120px 80px 80px 1fr 1fr;gap:10px;margin-bottom:10px;align-items:start">
<div style="display:flex;flex-direction:column;gap:4px">
<label style="color:#aa7777;font-size:11px;font-weight:600;letter-spacing:0.3px">PRODUCT</label>
<select id="createProductId" style="padding:9px 8px"></select>
</div>
<div style="display:flex;flex-direction:column;gap:4px">
<label style="color:#aa7777;font-size:11px;font-weight:600;letter-spacing:0.3px">PREFIX + LENGTH</label>
<div style="display:flex;align-items:center;gap:4px">
<input type="text" id="createPrefix" placeholder="PLX" maxlength="8" value="PLX" style="width:65px;flex:none;text-align:center;text-transform:uppercase;padding:9px 6px">
<span style="color:#886666;font-size:13px">-</span>
<select id="suffixGroups" style="flex:1;padding:9px 6px">
<option value="8">2 nhom</option>
<option value="12" selected>3 nhom</option>
<option value="16">4 nhom</option>
<option value="20">5 nhom</option>
<option value="24">6 nhom</option>
</select>
</div>
</div>
<div style="display:flex;flex-direction:column;gap:4px">
<label style="color:#aa7777;font-size:11px;font-weight:600;letter-spacing:0.3px">NGAY HET HAN</label>
<input type="number" id="createDays" value="30" min="1" max="3650">
</div>
<div style="display:flex;flex-direction:column;gap:4px">
<label style="color:#aa7777;font-size:11px;font-weight:600;letter-spacing:0.3px">SO LUONG</label>
<input type="number" id="createCount" value="1" min="1" max="500">
</div>
<div style="display:flex;flex-direction:column;gap:4px">
<label style="color:#aa7777;font-size:11px;font-weight:600;letter-spacing:0.3px">SO THIET BI</label>
<input type="number" id="createMaxDevices" value="1" min="1" max="100">
</div>
<div style="display:flex;flex-direction:column;gap:4px;max-width:100px">
<label style="color:#aa7777;font-size:11px;font-weight:600;letter-spacing:0.3px">LOAI KEY</label>
<select id="createType" style="padding:9px 8px">
<option value="basic">Basic</option>
<option value="pro">Pro</option>
<option value="vip">VIP</option>
</select>
</div>
<div style="display:flex;flex-direction:column;gap:4px">
<label style="color:#aa7777;font-size:11px;font-weight:600;letter-spacing:0.3px">NGUOI DUNG</label>
<input type="text" id="createUser" placeholder="Khong bat buoc">
</div>
<div style="display:flex;flex-direction:column;gap:4px">
<label style="color:#aa7777;font-size:11px;font-weight:600;letter-spacing:0.3px">GHI CHU</label>
<input type="text" id="createNote" placeholder="Khong bat buoc">
</div>
</div>
<div id="manualKeyFields" style="display:none;margin-bottom:10px">
<div style="display:grid;grid-template-columns:1fr 120px 80px 80px 1fr;gap:10px;align-items:start">
<div style="display:flex;flex-direction:column;gap:4px">
<label style="color:#aa7777;font-size:11px;font-weight:600;letter-spacing:0.3px">PRODUCT</label>
<select id="createProductIdManual" style="padding:9px 8px"></select>
</div>
<div style="display:flex;flex-direction:column;gap:4px;grid-column:span 2">
<label style="color:#aa7777;font-size:11px;font-weight:600;letter-spacing:0.3px">NHAP KEY</label>
<input type="text" id="createManualKey" placeholder="Nhap ma key..." style="width:100%;font-family:monospace;padding:9px 8px">
<div style="font-size:11px;color:#886666;margin-top:2px">Tuy chon: <input type="number" id="createManualDays" value="30" min="1" max="3650" style="width:70px;padding:4px 6px;font-size:11px"> ngay | <input type="number" id="createManualMaxDevices" value="1" min="1" max="100" style="width:60px;padding:4px 6px;font-size:11px"> thiet bi</div>
</div>
<div style="display:flex;flex-direction:column;gap:4px">
<label style="color:#aa7777;font-size:11px;font-weight:600;letter-spacing:0.3px">LOAI KEY</label>
<select id="createManualType" style="padding:9px 8px">
<option value="basic">Basic</option>
<option value="pro">Pro</option>
<option value="vip">VIP</option>
</select>
</div>
<div style="display:flex;flex-direction:column;gap:4px">
<label style="color:#aa7777;font-size:11px;font-weight:600;letter-spacing:0.3px">NGUOI DUNG</label>
<input type="text" id="createManualUser" placeholder="Khong bat buoc" style="width:100%">
</div>
</div>
</div>
<div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap">
<button class="btn-success" onclick="createKey()" id="createBtn">Tao Key</button>
<small id="createModeHint" style="color:#886666">De trong tien de tao key random dai (32 ky tu).</small>
</div>
<div id="createResult"></div>
</div>
</div>
<div class="tab-content" id="tabOnline">
<div class="card">
<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:14px;flex-wrap:wrap;gap:8px">
<h3 style="margin:0">Trang Thai Online</h3>
<div style="display:flex;align-items:center;gap:8px">
<small id="onlineCount" style="color:#33cc33;font-weight:600">0 key online</small>
<button class="btn-primary btn-sm" onclick="refreshOnline()">Lam Moi</button>
</div>
</div>
<div style="overflow-x:auto">
<table><thead><tr><th>STT</th><th>MA KEY</th><th>PRODUCT</th><th>LOAI</th><th>THIET BI</th><th>HWID</th><th>NGUOI DUNG</th><th>LAN CUOI</th><th>TRANG THAI</th></tr></thead>
<tbody id="onlineTableBody"><tr><td colspan="9" class="loading">Dang tai...</td></tr></tbody></table>
</div>
</div>
</div>
<div class="tab-content" id="tabLogs">
<div class="card">
<h3>Nhat Ky Hoat Dong</h3>
<div style="overflow-x:auto">
<table><thead><tr><th>ID</th><th>HANH DONG</th><th>KEY</th><th>CHI TIET</th><th>THOI GIAN</th></tr></thead>
<tbody id="logTableBody"><tr><td colspan="5" class="loading">Dang tai...</td></tr></tbody></table>
</div>
</div>
</div>
<div class="tab-content" id="tabProducts">
<div class="card">
<div class="form-row" style="justify-content:space-between;flex-wrap:wrap">
<h3 style="margin:0">Danh Sach Product</h3>
<div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
<input type="text" id="newProductName" placeholder="Ten product" style="min-width:120px">
<input type="text" id="newProductSecret" placeholder="Secret key" style="min-width:160px;font-family:monospace">
<input type="password" id="newProductPassword" placeholder="Mat khau product" style="min-width:140px">
<button class="btn-success btn-sm" onclick="createProduct()">Them Product</button>
</div>
</div>
<div style="overflow-x:auto">
<table><thead><tr><th>ID</th><th>NAME</th><th>SECRET</th><th>MAT KHAU</th><th>CREATED</th><th>ACTION</th></tr></thead>
<tbody id="productTableBody"><tr><td colspan="6" class="loading">Dang tai...</td></tr></tbody></table>
</div>
</div>
</div>
</div>
<div class="edit-overlay" id="editOverlay" onclick="if(event.target===this)closeEditPanel()">
<div class="edit-panel" id="editPanel">
<span class="close-btn" onclick="closeEditPanel()">&times;</span>
<h3 id="editPanelTitle">Chinh Sua Key</h3>
<div class="key-display" id="editKeyDisplay">-</div>
<div class="row"><label>Loai Key</label><select id="editKeyType"><option value="basic">Basic</option><option value="pro">Pro</option><option value="vip">VIP</option></select><button class="btn-primary btn-sm" onclick="saveKeyType()">Luu</button></div>
<div class="row"><label>Trang Thai</label><span id="editKeyStatus" style="font-weight:600"></span></div>
<div class="row"><label>Product</label><span id="editKeyProduct" style="color:#886666"></span></div>
<div class="row"><label>Han Den</label><span id="editKeyExpiry" style="color:#886666"></span></div>
<div class="row"><label>HWID</label><span id="editKeyHwid" style="font-family:monospace;font-size:11px;color:#cc6666"></span></div>
<div class="row"><label>Thiet Bi</label><span id="editKeyDevices" style="color:#886666"></span></div>
<div class="row"><label>So TB Toi Da</label><input type="number" id="editMaxDevices" value="1" min="1" max="100" style="max-width:80px"><button class="btn-primary btn-sm" onclick="saveMaxDevices()">Luu</button></div>
<div class="row"><label>Nguoi Dung</label><span id="editKeyUser" style="color:#886666"></span></div>
<div class="row"><label>Ghi Chu</label><span id="editKeyNote" style="color:#886666"></span></div>
<div class="row" id="editExtendRow"><label>Gia Han (ngay)</label><input type="number" id="editExtendDays" value="30" min="1" max="3650" style="max-width:100px"><button class="btn-primary btn-sm" onclick="extendCurrentKey()">Gia Han</button></div>
<div class="actions">
<button class="action-btn" id="editBanBtn" onclick="toggleBanKey()">Khoa</button>
<button class="action-btn" onclick="resetHwidCurrent()">Reset HWID</button>
<button class="action-btn" onclick="deleteCurrentKey()">Xoa</button>
<button class="action-btn" onclick="copyCurrentKey()">Copy</button>
</div>
</div>
</div>
<div class="edit-overlay" id="deleteProductOverlay" style="display:none" onclick="if(event.target===this)closeDeleteProductModal()">
<div class="edit-panel" style="max-width:380px">
<span class="close-btn" onclick="closeDeleteProductModal()">&times;</span>
<h3>Xac Nhan Xoa Product</h3>
<p style="font-size:13px;color:#aa7777;margin-bottom:12px" id="deleteProductInfo">Nhap mat khau de xoa product</p>
<input type="password" id="deleteProductPassword" placeholder="Mat khau product..." style="width:100%;padding:10px;margin-bottom:4px">
<div id="deleteProductError" style="color:#dd3333;font-size:12px;margin:8px 0;display:none"></div>
<div style="display:flex;gap:8px;margin-top:12px">
<button class="btn-danger" onclick="confirmDeleteProduct()" id="deleteProductBtn">Xac Nhan Xoa</button>
<button onclick="closeDeleteProductModal()" style="background:#1a1a22;color:#aa7777;border:1px solid #cc333344;padding:9px 14px;border-radius:5px;cursor:pointer">Huy</button>
</div>
</div>
</div>
<div class="toast" id="toast"></div>
<script>
const BASE=window.location.origin;
let authToken='',allKeys=[],allLogs=[],allProducts=[];
function login(){const u=document.getElementById('loginUser').value,p=document.getElementById('loginPass').value;if(!u||!p)return showToast('Nhap day du thong tin','error');authToken=btoa(u+':'+p);fetch(BASE+'/api/keys',{headers:{'Authorization':'Basic '+authToken}}).then(r=>{if(r.ok){document.getElementById('loginOverlay').style.display='none';document.getElementById('mainContent').style.display='block';refreshData()}else if(r.status===401){showToast('Sai thong tin dang nhap','error');authToken=''}else{showToast('Loi server (HTTP '+r.status+')','error');authToken=''}}).catch(e=>{showToast('Loi ket noi: '+e.message,'error');authToken=''})}
function checkHealth(){fetch(BASE+'/api/health').then(r=>r.json()).then(d=>{showToast('Server OK | Admin: '+d.admin+' | Supabase: '+d.supabase+' | Keys: '+d.keys_count+(d.products?' | Products: '+d.products.join(', '):''),'success')}).catch(e=>{showToast('Server khong phan hoi','error')})}
function showToast(m,t){const e=document.getElementById('toast');e.textContent=m;e.className='toast toast-'+t;e.style.display='block';setTimeout(()=>e.style.display='none',3500)}
function api(p,o){o=o||{};o.headers=o.headers||{};o.headers['Authorization']='Basic '+authToken;return fetch(BASE+p,o).then(r=>r.json())}
function st(x){if(x.status==='banned')return{cls:'status-banned',txt:'Bi khoa'};if(x.status==='expired')return{cls:'status-expired',txt:'Het han'};if(!x.expires_at)return{cls:'status-pending',txt:'Chua kich hoat'};var e=new Date(x.expires_at);if(e<=new Date())return{cls:'status-expired',txt:'Het han'};return{cls:'status-active',txt:'Hoat dong'}}
function getDevInfo(hwid){if(!hwid||hwid===''||hwid==='[]')return{count:0,list:[]};try{if(hwid.startsWith('[')){var arr=JSON.parse(hwid);return{count:arr.length,list:arr}}return{count:1,list:[hwid]}}catch(e){return{count:0,list:[]}}}
function getProductName(id){const p=allProducts.find(x=>x.id===id);return p?p.name:'unknown'}
function getProductClass(id){const n=getProductName(id);if(n==='internal')return'product-internal';if(n==='external')return'product-external';if(n==='mobile')return'product-mobile';return''}
function loadProductFilter(){const s=document.getElementById('productFilter');if(!s)return;const cur=s.value;s.innerHTML='<option value="">Tat ca Product</option>'+allProducts.map(p=>'<option value="'+p.id+'">'+p.name+'</option>').join('');s.value=cur}
function loadCreateProductSelect(){const s=document.getElementById('createProductId');if(!s)return;const cur=s.value;s.innerHTML=allProducts.map(p=>'<option value="'+p.id+'">'+p.name+'</option>').join('');if(!cur&&allProducts.length>0)s.value=allProducts[0].id;else s.value=cur;const sm=document.getElementById('createProductIdManual');if(sm){const cur2=sm.value;sm.innerHTML=allProducts.map(p=>'<option value="'+p.id+'">'+p.name+'</option>').join('');if(!cur2&&allProducts.length>0)sm.value=allProducts[0].id;else if(cur2)sm.value=cur2}}
let onlineTimer;function switchTab(t){document.querySelectorAll('.tab').forEach(x=>x.classList.remove('active'));document.querySelectorAll('.tab-content').forEach(x=>x.classList.remove('active'));const cap=t.charAt(0).toUpperCase()+t.slice(1)+'Btn';const e=document.getElementById('tab'+cap)||document.getElementById(cap);if(e)e.classList.add('active');document.getElementById('tab'+t).classList.add('active');if(onlineTimer)clearInterval(onlineTimer);if(t==='online'){refreshOnline();onlineTimer=setInterval(refreshOnline,5000)}}
function refreshData(){Promise.all([api('/api/products').then(r=>{allProducts=r.data||[];loadProductFilter();loadCreateProductSelect()}),api('/api/keys?'+new URLSearchParams({product_id:document.getElementById('productFilter').value||'',status:document.getElementById('statusFilter').value||''})).then(r=>allKeys=r.data||[]),api('/api/logs').then(r=>allLogs=r.data||[]),api('/api/stats').then(r=>{if(r.data)renderStats(r.data)})]).then(()=>{renderTable();renderLogs();refreshProductTable()}).catch(e=>{console.error(e);showToast('Loi tai du lieu','error')})}
function refreshOnline(){const pid=document.getElementById('productFilter').value;api('/api/online?'+(pid?'product_id='+pid:'')).then(r=>{renderOnline(r.data||[]);const e=document.getElementById('onlineCount');if(e)e.textContent=r.count+' key online'}).catch(()=>{})}
function renderOnline(d){const t=document.getElementById('onlineTableBody');if(!t)return;if(!d.length){t.innerHTML='<tr><td colspan="9" style="text-align:center;color:#886666">Khong co key online</td></tr>';return}t.innerHTML=d.map((x,i)=>{var s_=st(x);var stxt='<span style="color:'+(s_.cls==='status-active'?'#33cc33':s_.cls==='status-pending'?'#aa7777':'#dd3333')+'">'+s_.txt+'</span>';const ls=x.last_seen?new Date(x.last_seen).toLocaleTimeString('vi-VN'):'-';const tp=x.type||'basic';var di=getDevInfo(x.hwid);var md=x.max_devices||1;var pn=getProductName(x.product_id);var pc=getProductClass(x.product_id);return '<tr><td>'+(i+1)+'</td><td class="copy-field">'+x.key+'</td><td><span class="product-badge '+pc+'">'+pn+'</span></td><td style="font-size:11px">'+(tp==='vip'?'<span style="color:#ffcc00;font-weight:600">VIP</span>':tp==='pro'?'<span style="color:#cc66ff;font-weight:600">Pro</span>':'<span style="color:#aa7777">Basic</span>')+'</td><td style="font-size:11px">'+(di.count>0?'<span title="'+di.list.join(', ')+'" style="cursor:help">'+di.count+'/'+md+' TB</span>':'<span style="color:#666">0/'+md+' TB</span>')+'</td><td style="font-family:monospace;font-size:11px;color:#cc6666">'+(x.hwid||'-')+'</td><td>'+(x.user||'-')+'</td><td>'+ls+'</td><td>'+stxt+'</td></tr>'}).join('')}
function renderStats(d){document.getElementById('statsContainer').innerHTML='<div class="stat-card"><div class="num">'+d.total+'</div><div class="label">Tong Key</div></div><div class="stat-card"><div class="num">'+d.active+'</div><div class="label">Hoat Dong</div></div><div class="stat-card"><div class="num">'+d.banned+'</div><div class="label">Bi Khoa</div></div><div class="stat-card"><div class="num">'+d.expired+'</div><div class="label">Het Han</div></div>'}
function renderTable(){const s=document.getElementById('searchInput').value.toLowerCase(),f=document.getElementById('statusFilter').value,pid=document.getElementById('productFilter').value;let k=allKeys;if(s)k=k.filter(x=>x.key.toLowerCase().includes(s));if(f!=='all')k=k.filter(function(x){var s_=st(x);return s_.cls==='status-'+f||s_.txt.toLowerCase()===f});const t=document.getElementById('keyTableBody');if(!k.length){t.innerHTML='<tr><td colspan="12" style="text-align:center;color:#886666">Khong co du lieu</td></tr>';return}t.innerHTML=k.map((x,i)=>{var s_=st(x);var c=s_.cls,stxt=s_.txt,tp=x.type||'basic';var di=getDevInfo(x.hwid);var md=x.max_devices||1;var devDisplay=di.count>0?'<span title="'+di.list.join(', ')+'" style="cursor:help">'+di.count+'/'+md+' TB</span>':'<span style="color:#666">0/'+md+' TB</span>';var hwidDisplay=di.count>0?'<span style="font-family:monospace;font-size:11px;color:#cc6666" title="'+di.list.join(', ')+'">'+di.list.join(', ')+'</span>':'-';var pn=getProductName(x.product_id);var pc=getProductClass(x.product_id);return '<tr><td>'+(i+1)+'</td><td class="copy-field">'+x.key+'</td><td><span class="product-badge '+pc+'">'+pn+'</span></td><td style="font-size:11px">'+(tp==='vip'?'<span style="color:#ffcc00;font-weight:600">VIP</span>':tp==='pro'?'<span style="color:#cc66ff;font-weight:600">Pro</span>':'<span style="color:#aa7777">Basic</span>')+'</td><td class="'+c+'">'+stxt+'</td><td>'+new Date(x.created_at).toLocaleDateString('vi-VN')+'</td><td>'+(x.expires_at?new Date(x.expires_at).toLocaleDateString('vi-VN'):'<span style=color:#666>Chua kich hoat</span>')+'</td><td style="font-size:11px">'+devDisplay+'</td><td style="font-family:monospace;font-size:11px;color:#cc6666">'+hwidDisplay+'</td><td>'+(x.user||'-')+'</td><td>'+(x.note||'-')+'</td><td nowrap><button class="action-btn" onclick="showEditPanel(\\''+x.key.replace(/'/g,"\\'")+'\\')">Chinh sua</button></td></tr>'}).join('')}
function renderLogs(){const t=document.getElementById('logTableBody');if(!allLogs.length){t.innerHTML='<tr><td colspan="5" style="text-align:center;color:#886666">Khong co du lieu</td></tr>';return}t.innerHTML=allLogs.slice(0,50).map(x=>'<tr><td>'+x.id+'</td><td style="color:#cc3333;font-weight:600">'+x.action+'</td><td class="copy-field">'+x.key+'</td><td>'+x.detail+'</td><td>'+new Date(x.created_at).toLocaleString('vi-VN')+'</td></tr>').join('')}
function renderProductTable(){const t=document.getElementById('productTableBody');if(!allProducts.length){t.innerHTML='<tr><td colspan="6" style="text-align:center;color:#886666">Khong co product</td></tr>';return}t.innerHTML=allProducts.map(p=>'<tr><td>'+p.id+'</td><td style="font-weight:600">'+p.name+'</td><td class="copy-field" style="font-size:12px">'+p.secret+'</td><td style="color:#886666;font-size:12px">********</td><td>'+new Date(p.created_at).toLocaleDateString('vi-VN')+'</td><td><button class="action-btn" onclick="showDeleteProductModal('+p.id+',\\''+p.name+'\\')">Xoa</button></td></tr>').join('')}
function refreshProductTable(){renderProductTable()}
function toggleKeyMode(){const m=document.querySelector('input[name=keyMode]:checked').value;document.getElementById('autoKeyFields').style.display=m==='auto'?'grid':'none';document.getElementById('manualKeyFields').style.display=m==='manual'?'block':'none';document.getElementById('createModeHint').textContent=m==='auto'?'De trong tien to de tao key random dai (32 ky tu).':'Chi tao duoc 1 key o che do nhap tay.'}
function createKey(){const mode=document.querySelector('input[name=keyMode]:checked').value,btn=document.getElementById('createBtn'),hint=document.getElementById('createModeHint');if(mode==='auto'){const p=document.getElementById('createProductId').value,d=document.getElementById('createDays').value,c=document.getElementById('createCount').value,g=parseInt(document.getElementById('suffixGroups').value),u=document.getElementById('createUser').value.trim(),n=document.getElementById('createNote').value.trim(),t=document.getElementById('createType').value,md=document.getElementById('createMaxDevices').value,pre=document.getElementById('createPrefix').value.trim();if(!p)return showToast('Chua chon product','error');const body={product_id:parseInt(p),days:parseInt(d),count:parseInt(c),type:t,max_devices:parseInt(md)||1};if(pre){body.prefix=pre;body.suffixLength=g}if(u)body.user=u;if(n)body.note=n;btn.disabled=true;btn.textContent='Dang tao...';hint.textContent='Dang tao key...';api('/api/keys',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)}).then(r=>{if(r.success){let html='<div style="background:#0e0e12;padding:14px;border-radius:6px;border:1px solid #cc333366;margin-top:10px">';const d_=(Array.isArray(r.data)?r.data[0]:r.data);const exp=d_.expires_at?new Date(d_.expires_at).toLocaleDateString('vi-VN'):'Kich hoat lan dau ('+d_.duration_days+' ngay)';if(r.count>1){html+='<div style="color:#cc3333;font-weight:600;margin-bottom:8px">Da tao '+r.count+' key:</div><div style="max-height:300px;overflow-y:auto">';r.data.forEach((x,i)=>{html+='<div style="padding:6px 10px;margin:3px 0;background:#0d0d11;border-radius:4px;border:1px solid #cc333315;display:flex;align-items:center;gap:8px">'+(i+1)+'. <span class="copy-field" style="font-size:13px;margin:0;flex:1">'+x.key+'</span><button class="action-btn" onclick="copyKey(\\''+x.key+'\\')">Copy</button></div>'});html+='</div>'}else{html+='<div style="color:#cc3333;font-weight:600;margin-bottom:6px">Key moi da tao:</div><span class="copy-field">'+r.data.key+'</span><div style="color:#886666;font-size:12px;margin-top:6px">Het han: '+exp+'</div>'}
if(r.count>1)html+='<button class="action-btn" onclick="copyAllKeys()" style="margin-top:10px">Copy Tat Ca</button>';html+='</div>';document.getElementById('createResult').innerHTML=html;refreshData();btn.disabled=false;btn.textContent='Tao Key';hint.textContent='De trong tien to de tao key random dai (32 ky tu).'}else{showToast(r.message,'error');btn.disabled=false;btn.textContent='Tao Key';hint.textContent='De trong tien to de tao key random dai (32 ky tu).'}}).catch(()=>{showToast('Loi tao key','error');btn.disabled=false;btn.textContent='Tao Key';hint.textContent='De trong tien to de tao key random dai (32 ky tu).'})}else{const p=document.getElementById('createProductIdManual').value,mk=document.getElementById('createManualKey').value.trim(),d=document.getElementById('createManualDays').value,md=document.getElementById('createManualMaxDevices').value,t=document.getElementById('createManualType').value,u=document.getElementById('createManualUser').value.trim();if(!p)return showToast('Chua chon product','error');if(!mk)return showToast('Nhap key','error');btn.disabled=true;btn.textContent='Dang tao...';hint.textContent='Dang tao key...';const body={product_id:parseInt(p),custom_key:mk,days:parseInt(d)||30,max_devices:parseInt(md)||1,type:t};if(u)body.user=u;api('/api/keys',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)}).then(r=>{if(r.success){document.getElementById('createResult').innerHTML='<div style="background:#0e0e12;padding:14px;border-radius:6px;border:1px solid #cc333366;margin-top:10px"><div style="color:#cc3333;font-weight:600;margin-bottom:6px">Key moi da tao:</div><span class="copy-field">'+r.data.key+'</span></div>';refreshData();btn.disabled=false;btn.textContent='Tao Key';hint.textContent='Chi tao duoc 1 key o che do nhap tay.'}else{showToast(r.message,'error');btn.disabled=false;btn.textContent='Tao Key';hint.textContent='Chi tao duoc 1 key o che do nhap tay.'}}).catch(()=>{showToast('Loi tao key','error');btn.disabled=false;btn.textContent='Tao Key';hint.textContent='Chi tao duoc 1 key o che do nhap tay.'})}}
function copyKey(k){navigator.clipboard.writeText(k).then(()=>showToast('Da copy: '+k,'success'))}
function copyAllKeys(){const r=document.querySelectorAll('#createResult .copy-field');const t=Array.from(r).map(e=>e.textContent).join('\\n');navigator.clipboard.writeText(t).then(()=>showToast('Da copy tat ca key','success'))}
let editKeyData=null;
function showEditPanel(k){editKeyData=allKeys.find(x=>x.key===k);const x=editKeyData;if(!x)return showToast('Khong tim thay key','error');document.getElementById('editPanelTitle').textContent='Chinh Sua Key';document.getElementById('editKeyDisplay').textContent=x.key;document.getElementById('editKeyType').value=x.type||'basic';var es_=st(x);document.getElementById('editKeyStatus').textContent=es_.txt;document.getElementById('editKeyStatus').style.color=es_.cls==='status-active'?'#33cc33':es_.cls==='status-pending'?'#aa7777':'#dd3333';document.getElementById('editKeyProduct').textContent=getProductName(x.product_id);document.getElementById('editKeyExpiry').textContent=x.expires_at?new Date(x.expires_at).toLocaleString('vi-VN'):'Chua kich hoat';var di=getDevInfo(x.hwid);var md=x.max_devices||1;document.getElementById('editKeyHwid').textContent=di.count>0?di.list.join(', '):'Chua co';document.getElementById('editKeyDevices').textContent=di.count+'/'+md+' thiet bi';document.getElementById('editMaxDevices').value=md;document.getElementById('editKeyUser').textContent=x.user||'-';document.getElementById('editKeyNote').textContent=x.note||'-';const banBtn=document.getElementById('editBanBtn');banBtn.textContent=x.status==='active'?'Khoa (Ban)':'Mo (Unban)';banBtn.style.background=x.status==='active'?'#cc3333':'#336633';document.getElementById('editOverlay').style.display='flex'}
function closeEditPanel(){document.getElementById('editOverlay').style.display='none';editKeyData=null}
function saveKeyType(){const x=editKeyData;if(!x)return;const t=document.getElementById('editKeyType').value;if(t===x.type)return showToast('Loai key khong thay doi','success');api('/api/keys/'+encodeURIComponent(x.key)+'/type',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({type:t})}).then(r=>{showToast(r.message,r.success?'success':'error');if(r.success){x.type=t;refreshData();closeEditPanel()}})}
function extendCurrentKey(){const x=editKeyData;if(!x)return;const d=document.getElementById('editExtendDays').value;if(!d||isNaN(d)||parseInt(d)<1)return;api('/api/keys/'+encodeURIComponent(x.key)+'/extend',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({days:parseInt(d)})}).then(r=>{showToast(r.message,r.success?'success':'error');if(r.success){refreshData();closeEditPanel()}})}
function toggleBanKey(){const x=editKeyData;if(!x)return;const isBan=x.status==='active',action=isBan?'ban':'unban',msg=isBan?'Khoa key '+x.key+'?':'Mo key '+x.key+'?';if(!confirm(msg))return;api('/api/keys/'+encodeURIComponent(x.key)+'/'+action,{method:'POST'}).then(r=>{showToast(r.message,r.success?'success':'error');if(r.success){refreshData();closeEditPanel()}})}
function resetHwidCurrent(){const x=editKeyData;if(!x)return;if(!confirm('Reset HWID cho key '+x.key+'?'))return;api('/api/keys/'+encodeURIComponent(x.key)+'/reset-hwid',{method:'POST'}).then(r=>{showToast(r.message,r.success?'success':'error');if(r.success){refreshData();closeEditPanel()}})}
function deleteCurrentKey(){const x=editKeyData;if(!x)return;if(!confirm('Xoa key '+x.key+'?'))return;api('/api/keys/'+encodeURIComponent(x.key),{method:'DELETE'}).then(r=>{showToast(r.message,r.success?'success':'error');if(r.success){refreshData();closeEditPanel()}})}
function copyCurrentKey(){const x=editKeyData;if(!x)return;navigator.clipboard.writeText(x.key).then(()=>showToast('Da copy: '+x.key,'success'))}
function saveMaxDevices(){const x=editKeyData;if(!x)return;const md=parseInt(document.getElementById('editMaxDevices').value);if(!md||md<1||md>100)return showToast('So thiet bi khong hop le (1-100)','error');api('/api/keys/'+encodeURIComponent(x.key)+'/max-devices',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({max_devices:md})}).then(r=>{showToast(r.message,r.success?'success':'error');if(r.success){x.max_devices=md;refreshData();closeEditPanel()}})}
function createProduct(){const name=document.getElementById('newProductName').value.trim();const secret=document.getElementById('newProductSecret').value.trim();const password=document.getElementById('newProductPassword').value;if(!name||!secret)return showToast('Nhap ten va secret','error');if(!password)return showToast('Nhap mat khau cho product','error');api('/api/products',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name,secret,password})}).then(r=>{if(r.success){showToast('Da tao product: '+r.data.name,'success');document.getElementById('newProductName').value='';document.getElementById('newProductSecret').value='';document.getElementById('newProductPassword').value='';refreshData()}else showToast(r.message,'error')})}
let delProdId=null,delProdName='';
function showDeleteProductModal(id,name){delProdId=id;delProdName=name;document.getElementById('deleteProductInfo').textContent='Nhap mat khau de xoa product "'+name+'"';document.getElementById('deleteProductPassword').value='';document.getElementById('deleteProductError').style.display='none';document.getElementById('deleteProductOverlay').style.display='flex'}
function closeDeleteProductModal(){document.getElementById('deleteProductOverlay').style.display='none';delProdId=null;delProdName=''}
function confirmDeleteProduct(){const pw=document.getElementById('deleteProductPassword').value;if(!pw){document.getElementById('deleteProductError').textContent='Vui long nhap mat khau';document.getElementById('deleteProductError').style.display='block';return}const btn=document.getElementById('deleteProductBtn');btn.disabled=true;btn.textContent='Dang xoa...';api('/api/products/'+delProdId,{method:'DELETE',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:pw})}).then(r=>{if(r.success){closeDeleteProductModal();showToast('Da xoa product "'+delProdName+'"','success');refreshData()}else{document.getElementById('deleteProductError').textContent=r.message;document.getElementById('deleteProductError').style.display='block';btn.disabled=false;btn.textContent='Xac Nhan Xoa'}}).catch(()=>{document.getElementById('deleteProductError').textContent='Loi ket noi';document.getElementById('deleteProductError').style.display='block';btn.disabled=false;btn.textContent='Xac Nhan Xoa'})}
document.getElementById('productFilter').addEventListener('change',function(){refreshData()})
</script>
</body>
</html>`);
});

// ======================== START ========================
app.listen(PORT, () => {
  console.log(`ROX Auth Server running on port ${PORT}`);
  console.log(`Web UI: http://localhost:${PORT}/`);
  console.log(`API:   http://localhost:${PORT}/api/verify?key=xxx&hwid=xxx&secret=xxx`);
});
