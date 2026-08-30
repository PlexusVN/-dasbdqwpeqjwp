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

// ---- CORS (cho phép web PWA gọi cross-origin; có thể set env CORS_ORIGIN để giới hạn domain) ----
const corsOrigin = process.env.CORS_ORIGIN || '*';
app.use(cors({ origin: corsOrigin, methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'] }));
app.use(express.json());
app.set('trust proxy', true);           // lấy IP thật từ Render LB

const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

// Bật Helmet để thêm các Security Headers bảo vệ server (tắt CSP để tránh block JS/CSS inline trên giao diện UI)
app.use(helmet({
  contentSecurityPolicy: false
}));

// Global Rate Limiter: 200 requests / 5 phút (cho toàn bộ endpoints)
const globalLimiter = rateLimit({
  windowMs: 5 * 60 * 1000, // 5 phút
  max: 200,
  message: { success: false, message: 'Too many requests from this IP, please try again after 5 minutes' },
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(globalLimiter);

// Strict API Limiter: 30 requests / 1 phút (cho các API nhạy cảm)
const apiLimiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 phút
  max: 30,
  message: { success: false, message: 'Quá nhiều yêu cầu, vui lòng thử lại sau' },
  standardHeaders: true,
  legacyHeaders: false,
});

app.get('/favicon.ico', (req, res) => res.status(204).end()); // Bỏ qua lỗi 404 favicon

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

async function requireAdmin(req, res, next) {
  try {
    const auth = req.headers.authorization;
    if (!auth || !auth.startsWith('Basic ')) {
      return res.status(401).json({ success: false, message: 'Unauthorized' });
    }
    const decoded = Buffer.from(auth.slice(6), 'base64').toString();
    const [user, pass] = decoded.split(':');
    
    if (user === ADMIN_USER && pass === ADMIN_PASS) {
      req.adminRole = 'master';
      req.adminUser = user;
      return next();
    }
    
    const { data } = await supabase.from('sub_admins').select('password, allowed_products').eq('username', user).maybeSingle();
    if (data && data.password === pass) {
      req.adminRole = 'subadmin';
      req.adminUser = user;
      req.allowedProducts = data.allowed_products || [];
      return next();
    }
    
    return res.status(401).json({ success: false, message: 'Unauthorized' });
  } catch (err) {
    return res.status(500).json({ success: false, message: 'Server error during auth' });
  }
}

async function checkKeyOwnership(req, res, next) {
  if (req.adminRole === 'master') return next();
  try {
    const { data } = await supabase.from('keys').select('user, product_id').eq('key', req.params.key).maybeSingle();
    if (!data) return res.status(404).json({ success: false, message: 'Key not found' });
    if (data.user !== req.adminUser) return res.status(403).json({ success: false, message: 'Bạn không có quyền thao tác trên key này' });
    
    next();
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
}

// ---- Helper: resolve product from secret ----
async function resolveProduct(secret) {
  if (!secret) return null;
  const { data } = await supabase.from('products').select('id, name').eq('secret', secret).maybeSingle();
  return data || null;
}

// ---- Helper: attach device info (from key_devices) into key rows ----
// Thêm mảng devices + device_count vào từng key. Không làm hỏng luồng
// chính nếu bảng key_devices chưa tồn tại (fallback về hwid text).
async function attachDeviceInfo(keys) {
  if (!keys || keys.length === 0) return keys;
  const ids = keys.map(k => k.id);
  let by = {};
  try {
    const { data, error } = await supabase.from('key_devices').select('key_id, hwid').in('key_id', ids);
    if (!error && data) {
      data.forEach(d => {
        if (!by[d.key_id]) by[d.key_id] = [];
        by[d.key_id].push(d.hwid);
      });
    }
  } catch (e) { /* bảng chưa tồn tại: bỏ qua */ }

  keys.forEach(k => {
    let devs = by[k.id] || [];
    if (devs.length === 0 && k.hwid && k.hwid !== '[]' && k.hwid !== '') {
        try {
            devs = k.hwid.startsWith('[') ? JSON.parse(k.hwid) : [k.hwid];
        } catch(e) {}
    }
    k.devices = devs;
    k.device_count = devs.length;
  });
  return keys;
}

// ---- Health Check (PUBLIC - minimal; full detail if admin auth) ----
app.get('/api/health', async (req, res) => {
  try {
    // If admin auth provided, return full details
    const auth = req.headers.authorization;
    let isAdmin = false;
    let role = '';
    let adminUser = '';
    if (auth && auth.startsWith('Basic ')) {
      const decoded = Buffer.from(auth.slice(6), 'base64').toString();
      const [user, pass] = decoded.split(':');
      if (user === ADMIN_USER && pass === ADMIN_PASS) {
        isAdmin = true;
        role = 'master';
        adminUser = user;
      } else {
        const { data } = await supabase.from('sub_admins').select('password').eq('username', user).maybeSingle();
        if (data && data.password === pass) {
          isAdmin = true;
          role = 'subadmin';
          adminUser = user;
        }
      }
    }

    if (auth && !isAdmin) {
      return res.status(401).json({ success: false, message: 'Unauthorized' });
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
      products: products ? products.map(p => p.name) : [],
      role: role,
      user: adminUser
    });
  } catch (err) {
    res.json({
      success: true, message: 'Server is running',
      supabase: 'error'
    });
  }
});

// ---- Enterprise Auto-Cleanup ----
async function cleanupExpiredKeys() {
  try {
    // Lấy thời điểm 24 giờ trước
    const cutoffDate = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
    
    // Xóa các key có expires_at nhỏ hơn cutoffDate
    const { data, error, count } = await supabase
      .from('keys')
      .delete({ count: 'exact' })
      .lt('expires_at', cutoffDate);
      
    if (error) throw error;
    if (count > 0) {
      console.log(`[Auto-Cleanup] Deleted ${count} expired keys (older than 24h).`);
      await supabase.from('activity_log').insert({ 
        action: 'auto_cleanup', 
        key: 'SYSTEM', 
        detail: `Auto deleted ${count} keys expired over 24h`,
        ip: '127.0.0.1'
      });
    }
  } catch (err) {
    console.error('[Auto-Cleanup] Error:', err.message);
  }
}

// Chạy dọn dẹp ngay khi khởi động Server
cleanupExpiredKeys();
// Lên lịch dọn dẹp mỗi 1 giờ (3600000 ms)
setInterval(cleanupExpiredKeys, 3600000);

// ---- Sub-Admins Management (MASTER ONLY) ----
app.get('/api/subadmins', requireAdmin, async (req, res) => {
  if (req.adminRole !== 'master') return res.status(403).json({ success: false, message: 'Forbidden' });
  try {
    const { data, error } = await supabase.from('sub_admins').select('username, created_at, allowed_products').order('created_at', { ascending: false });
    if (error) throw error;
    
    // Fetch precise counts per product for each subadmin
    for (const sa of data) {
      sa.key_counts = {};
      let ap = sa.allowed_products;
      if (typeof ap === 'string') { try { ap = JSON.parse(ap); } catch(e) { ap = []; } }
      if (ap && Array.isArray(ap)) {
        sa.allowed_products = ap; // normalize to array for the frontend response too
        for (const pid of ap) {
          const { count, error: cErr } = await supabase.from('keys')
            .select('*', { count: 'exact', head: true })
            .eq('user', sa.username)
            .eq('product_id', pid);
          if (!cErr) {
            sa.key_counts[pid] = count || 0;
          }
        }
      }
    }

    res.json({ success: true, data });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

app.post('/api/subadmins', requireAdmin, async (req, res) => {
  if (req.adminRole !== 'master') return res.status(403).json({ success: false, message: 'Forbidden' });
  try {
    const { username, password, allowed_products } = req.body;
    if (!username || !password || username.length < 3 || password.length < 4) {
      return res.json({ success: false, message: 'Tên đăng nhập >= 3, mật khẩu >= 4 ký tự' });
    }
    const { error } = await supabase.from('sub_admins').insert({ 
      username, 
      password, 
      allowed_products: allowed_products || [] 
    });
    if (error) {
      if (error.code === '23505') return res.json({ success: false, message: 'Tên đăng nhập đã tồn tại' });
      throw error;
    }
    await supabase.from('activity_log').insert({ action: 'create_subadmin', key: username, detail: `Created subadmin ${username} | IP: ${req.ip}`, ip: req.ip });
    res.json({ success: true, message: 'Tạo tài khoản thành công' });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

app.put('/api/subadmins/:username', requireAdmin, async (req, res) => {
  if (req.adminRole !== 'master') return res.status(403).json({ success: false, message: 'Forbidden' });
  try {
    const { password, allowed_products } = req.body;
    const updateData = {};
    if (password && password.length >= 4) updateData.password = password;
    if (allowed_products) updateData.allowed_products = allowed_products;
    
    const { error } = await supabase.from('sub_admins').update(updateData).eq('username', req.params.username);
    if (error) throw error;
    await supabase.from('activity_log').insert({ action: 'update_subadmin', key: req.params.username, detail: `Updated subadmin ${req.params.username} | IP: ${req.ip}`, ip: req.ip });
    res.json({ success: true, message: 'Cập nhật tài khoản thành công' });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

app.delete('/api/subadmins/:username', requireAdmin, async (req, res) => {
  if (req.adminRole !== 'master') return res.status(403).json({ success: false, message: 'Forbidden' });
  try {
    const { error } = await supabase.from('sub_admins').delete().eq('username', req.params.username);
    if (error) throw error;
    await supabase.from('activity_log').insert({ action: 'delete_subadmin', key: req.params.username, detail: `Deleted subadmin ${req.params.username} | IP: ${req.ip}`, ip: req.ip });
    res.json({ success: true, message: 'Đã xóa tài khoản' });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
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
app.get('/api/verify', apiLimiter, async (req, res) => {
  try {
    const { key, hwid, secret } = req.query;
    if (!key || !hwid || !secret) {
      return res.json({ success: false, status: 'invalid', message: 'Authentication failed' });
    }

    // Rate limit: tối đa 5 request/giây từ 1 IP
    if (!checkRateLimit(req.ip, 5, 1000)) {
      return res.json({ success: false, status: 'invalid', message: 'Authentication failed' });
    }

    // 1. Resolve product từ secret
    const product = await resolveProduct(secret);
    if (!product) {
      return res.json({ success: false, status: 'invalid', message: 'Authentication failed' });
    }

    // 2. Preliminary product check (tránh gọi RPC khi sai product)
    const { data: keyCheck } = await supabase.from('keys').select('product_id').eq('key', key).maybeSingle();
    if (!keyCheck || keyCheck.product_id !== product.id) {
      return res.json({ success: false, status: 'invalid', message: 'Authentication failed' });
    }

    // 3. Atomic: toàn bộ check (status, expiry, HWID, product) trong 1 RPC lock
    const { data: rpc, error: rpcErr } = await supabase.rpc('register_hwid', {
      p_key: key,
      p_hwid: hwid,
      p_product_id: product.id,
    });
    if (rpcErr) throw rpcErr;

    // 4. Nếu RPC trả về không valid → luôn trả generic error
    if (rpc.status !== 'valid') {
      return res.json({ success: false, status: 'invalid', message: 'Authentication failed' });
    }

    // 5. Log
    await supabase.from('activity_log').insert({
      action: 'verify',
      key: key,
      detail: `Verified from HWID: ${hwid} | Product: ${product.name} | IP: ${req.ip}`,
      ip: req.ip,
    });

    const resType = rpc.type || 'basic';
    const resExpires = rpc.expires_at || '';
    const messageToHash = `true|${resType}|${resExpires}`;
    const hmac = require('crypto').createHmac('sha256', secret).update(messageToHash).digest('base64');

    res.json({
      success: true,
      status: 'valid',
      message: 'Authentication successful',
      expires_at: rpc.expires_at,
      server_time: new Date().toISOString(),
      type: resType,
      hmac: hmac
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
            product_id = 1, custom_key, creator = 'MASTER' } = req.body;

    // Validate product_id
    const { data: product } = await supabase.from('products').select('id').eq('id', product_id).maybeSingle();
    if (!product) return res.json({ success: false, message: 'Invalid product_id' });

    if (req.adminRole === 'subadmin') {
      const allowed = (req.allowedProducts || []).map(p => String(p));
      if (!allowed.includes(String(product_id))) {
        return res.status(403).json({ success: false, message: 'Bạn không có quyền tạo key cho sản phẩm này' });
      }
    }

    const actualCreator = req.adminRole === 'master' ? (creator || 'MASTER') : req.adminUser;
    const keyType = ['basic', 'pro', 'vip'].includes(rawType) ? rawType : 'basic';
    const now = new Date();
    const durationDays = parseInt(days) || 30;
    const maxDevices = Math.max(parseInt(max_devices) || 0, 0);

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
        user: actualCreator, note: note || '', type: keyType,
      });
      if (insertError) {
        if (insertError.code === '23505') return res.json({ success: false, message: 'Key already exists' });
        throw insertError;
      }

      await supabase.from('activity_log').insert({
        action: 'create', key: trimmedKey, detail: `[Creator: ${actualCreator}] [Type: ${keyType}] [Product: ${product_id}] Created key manually, ${days} days | IP: ${req.ip}`, ip: req.ip,
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
      user: actualCreator, note: note || '', type: keyType,
    }));

    const { error: insertError } = await supabase.from('keys').insert(inserts);
    if (insertError) throw insertError;

    await supabase.from('activity_log').insert({
      action: 'create', key: num > 1 ? `${num} keys` : keys[0].key,
      detail: `[Creator: ${actualCreator}] [Type: ${keyType}] [Product: ${product_id}] Created ${num} key(s), ${days} days. Note: ${note} | IP: ${req.ip}`, ip: req.ip,
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
    
    let allKeys = [];
    let from = 0;
    const step = 1000;
    while(true) {
      let q = supabase.from('keys').select('*').order('created_at', { ascending: false }).range(from, from + step - 1);
      if (req.adminRole === 'subadmin') q = q.eq('user', req.adminUser);
      if (product_id) q = q.eq('product_id', parseInt(product_id));
      if (status) q = q.eq('status', status);
      
      const { data, error } = await q;
      if (error) throw error;
      if (data && data.length > 0) allKeys = allKeys.concat(data);
      if (!data || data.length < step) break;
      from += step;
    }
    
    const keys = allKeys;
    const count = allKeys.length;
    
    // Nối danh sách thiết bị từ bảng key_devices
    const keysWithDevices = await attachDeviceInfo(keys);
    
    res.json({ success: true, data: keysWithDevices, total: count });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// ---- Get Key (ADMIN) ----
app.get('/api/keys/:key', requireAdmin, checkKeyOwnership, async (req, res) => {
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
app.delete('/api/keys/:key', requireAdmin, checkKeyOwnership, async (req, res) => {
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
app.post('/api/keys/:key/ban', requireAdmin, checkKeyOwnership, async (req, res) => {
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
app.post('/api/keys/:key/unban', requireAdmin, checkKeyOwnership, async (req, res) => {
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
app.post('/api/keys/:key/reset-hwid', requireAdmin, checkKeyOwnership, async (req, res) => {
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
app.post('/api/keys/:key/extend', requireAdmin, checkKeyOwnership, async (req, res) => {
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
app.post('/api/keys/:key/type', requireAdmin, checkKeyOwnership, async (req, res) => {
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
app.post('/api/keys/:key/max-devices', requireAdmin, checkKeyOwnership, async (req, res) => {
  try {
    const maxDevices = parseInt(req.body.max_devices);
    if (isNaN(maxDevices) || maxDevices < 0) {
      return res.json({ success: false, message: 'Invalid max devices (0 = unlimited)' });
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
    
    let allKeys = [];
    let from = 0;
    const step = 1000;
    while(true) {
      let q = supabase.from('keys').select('status,expires_at,product_id').range(from, from + step - 1);
      if (product_id) q = q.eq('product_id', parseInt(product_id));
      if (req.adminRole === 'subadmin') q = q.eq('user', req.adminUser);
      
      const { data, error } = await q;
      if (error) throw error;
      if (data && data.length > 0) allKeys = allKeys.concat(data);
      if (!data || data.length < step) break;
      from += step;
    }
    
    const keys = allKeys;

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
      .order('last_seen', { ascending: false })
      .limit(10000);

    const { product_id } = req.query;
    if (product_id) query = query.eq('product_id', parseInt(product_id));
    if (req.adminRole === 'subadmin') {
      query = query.eq('user', req.adminUser);
    }

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
    const { data: logs, error } = await supabase.from('activity_log').select('*').order('created_at', { ascending: false }).limit(10000);
    if (error) throw error;

    if (req.adminRole !== 'master') {
      // Sub-admins only see logs related to their own username
      const filtered = logs.filter(l => l.detail && l.detail.includes(`[Creator: ${req.adminUser}]`));
      return res.json({ success: true, data: filtered });
    }

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
    
    if (req.adminRole === 'subadmin') {
      const allowed = (req.allowedProducts || []).map(p => String(p));
      const filtered = data.filter(p => allowed.includes(String(p.id)));
      return res.json({ success: true, data: filtered });
    }
    
    res.json({ success: true, data });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// ---- Check Product Password (ADMIN) ----
app.post('/api/products/check-password', requireAdmin, async (req, res) => {
  if (req.adminRole !== 'master') return res.status(403).json({ success: false, message: 'Forbidden' });
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
  if (req.adminRole !== 'master') return res.status(403).json({ success: false, message: 'Forbidden' });
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
  if (req.adminRole !== 'master') return res.status(403).json({ success: false, message: 'Forbidden' });
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
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover, maximum-scale=1.0, user-scalable=no">
<title>PLEXUS AUTH - Dashboard</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;700&display=swap" rel="stylesheet">
<!-- Chart.js -->
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<!-- Feather Icons -->
<script src="https://unpkg.com/feather-icons"></script>
<style>
  :root {
    --bg-base: #f9fafb;
    --bg-card: #ffffff;
    --bg-hover: #f3f4f6;
    --border: #000000;
    --text-main: #000000;
    --text-muted: #4b5563;
    
    --accent: #2563eb;
    --accent-hover: #1d4ed8;
    --success: #16a34a;
    --danger: #dc2626;
    --warning: #d97706;
    
    --font-sans: 'Inter', system-ui, sans-serif;
    --font-mono: 'JetBrains Mono', monospace;
  }

  * { 
    margin: 0; padding: 0; box-sizing: border-box; 
    border-radius: 0 !important; /* KHONG BO GOC */
  }
  
  body {
    font-family: var(--font-sans);
    background-color: var(--bg-base);
    color: var(--text-main);
    display: flex;
    flex-direction: column;
    height: 100vh;
    overflow: hidden;
  }

  /* Subadmin Mode */
  body.subadmin-mode .admin-only { display: none !important; }

  /* Custom Scrollbar */
  ::-webkit-scrollbar { width: 10px; height: 10px; }
  ::-webkit-scrollbar-track { background: var(--bg-base); border-left: 1px solid #000; }
  ::-webkit-scrollbar-thumb { background: #000; border: 1px solid var(--bg-base); }
  ::-webkit-scrollbar-thumb:hover { background: var(--text-muted); }

  /* Login Overlay */
  .login-overlay {
    position: fixed; top: 0; left: 0; right: 0; bottom: 0;
    background: var(--bg-card);
    display: flex; align-items: center; justify-content: center;
    z-index: 9999;
  }
  .login-box {
    background: var(--bg-card);
    border: 2px solid #000;
    padding: 40px;
    width: 100%; max-width: 400px;
    box-shadow: 8px 8px 0px rgba(0,0,0,1);
  }
  .login-box h2 {
    font-size: 24px; font-weight: 700; text-align: center; margin-bottom: 24px;
    text-transform: uppercase;
    display: flex; align-items: center; justify-content: center; gap: 8px;
  }
  .login-box .form-group { margin-bottom: 20px; }
  .login-box input { width: 100%; padding: 12px; font-size: 16px; }

  /* Top Navigation / Tabs */
  .topbar {
    background: var(--bg-card);
    border-bottom: 2px solid #000;
    display: flex;
    flex-direction: column;
  }
  .topbar-header {
    display: flex; justify-content: space-between; align-items: center;
    padding: 16px 24px;
    border-bottom: 1px solid #000;
  }
  .brand { font-weight: 700; font-size: 20px; letter-spacing: 1px; display: flex; align-items: center; gap: 8px; text-transform: uppercase; }
  
  .tabs-container {
    display: flex; overflow-x: auto;
    background: var(--bg-base);
  }
  .tab-item {
    padding: 14px 24px;
    font-weight: 600; font-size: 14px;
    color: var(--text-muted);
    border-right: 1px solid #000;
    border-bottom: 2px solid transparent;
    cursor: pointer;
    text-transform: uppercase;
    display: flex; align-items: center; gap: 8px;
    transition: all 0.2s;
    white-space: nowrap;
  }
  .tab-item:hover { background: var(--bg-hover); color: var(--text-main); }
  .tab-item.active { background: var(--bg-card); color: var(--text-main); border-bottom: 2px solid #000; }

  /* Mobile Menu Base (Hidden on PC) */
  .mobile-menu-btn { display: none; background: transparent; border: none; cursor: pointer; color: #000; padding: 4px; }
  .mobile-menu-overlay { display: none; }

  /* Main Content */
  .main-wrapper { flex: 1; overflow-y: auto; padding: 32px; background: var(--bg-base); }
  .section { display: none; animation: fadeIn 0.3s ease; }
  .section.active { display: block; }
  @keyframes fadeIn { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: translateY(0); } }

  .section-header { margin-bottom: 24px; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 12px; }
  .section-title { font-size: 24px; font-weight: 700; color: #000; text-transform: uppercase; }

  /* Cards & Grid */
  .grid-4 { display: grid; grid-template-columns: repeat(4, 1fr); gap: 24px; margin-bottom: 32px; }
  .grid-2 { display: grid; grid-template-columns: repeat(2, 1fr); gap: 24px; margin-bottom: 32px; }
  .card {
    background: var(--bg-card);
    border: 2px solid #000;
    padding: 24px;
    box-shadow: 4px 4px 0px rgba(0,0,0,1);
  }
  .kpi-card { display: flex; flex-direction: column; gap: 12px; }
  .kpi-label { font-size: 14px; color: var(--text-muted); font-weight: 600; display: flex; align-items: center; justify-content: space-between; text-transform: uppercase;}
  .kpi-value { font-size: 36px; font-weight: 700; color: #000; font-family: var(--font-mono); }

  /* Tables */
  .table-container { 
    overflow-x: auto; 
    border: 2px solid #000; 
    background: var(--bg-card); 
    box-shadow: 4px 4px 0px rgba(0,0,0,1);
  }
  table { width: 100%; border-collapse: collapse; text-align: left; font-size: 14px; }
  th { background: #f9fafb; padding: 14px 16px; font-weight: 700; color: #000; border-bottom: 2px solid #000; white-space: nowrap; text-transform: uppercase; }
  td { padding: 14px 16px; border-bottom: 1px solid #000; vertical-align: middle; white-space: nowrap; }
  tr:last-child td { border-bottom: none; }
  tr:hover { background: #f0fdf4; }
  
  .mono { font-family: var(--font-mono); font-size: 13px; font-weight: 500; }
  .copyable { cursor: pointer; transition: color 0.2s; font-weight: 700; }
  .copyable:hover { color: var(--accent); text-decoration: underline; }

  /* Badges (Neo-brutalist) */
  .badge { display: inline-flex; align-items: center; padding: 4px 10px; font-size: 12px; font-weight: 700; border: 1px solid #000; box-shadow: 2px 2px 0px #000; text-transform: uppercase; }
  .badge-active { background: #bbf7d0; color: #000; }
  .badge-banned { background: #fecaca; color: #000; }
  .badge-expired { background: #fef08a; color: #000; }
  .badge-pending { background: #e5e7eb; color: #000; }
  .badge-warn { background: #fde047; color: #000; margin-left: 8px; }

  /* Forms */
  .form-group { margin-bottom: 16px; }
  .form-group label { display: block; font-size: 14px; font-weight: 600; margin-bottom: 8px; color: #000; text-transform: uppercase; }
  .form-row { display: flex; gap: 16px; align-items: flex-end; flex-wrap: wrap; margin-bottom: 16px; }
  
  input, select, textarea {
    width: 100%;
    padding: 10px 14px;
    background: #fff;
    border: 2px solid #000;
    color: #000;
    font-size: 15px;
    font-family: var(--font-sans);
    transition: all 0.2s;
  }
  input:focus, select:focus { outline: none; box-shadow: 4px 4px 0px #000; transform: translate(-2px, -2px); }
  input[type="checkbox"] { width: 20px; height: 20px; margin-right: 8px; accent-color: #000; border: 2px solid #000; cursor: pointer; }

  /* Neo-brutalist Buttons */
  .btn {
    display: inline-flex; align-items: center; justify-content: center; gap: 8px;
    padding: 10px 20px;
    font-size: 14px; font-weight: 700;
    text-transform: uppercase;
    cursor: pointer;
    border: 2px solid #000;
    background: #fff;
    color: #000;
    box-shadow: 4px 4px 0px #000;
    transition: all 0.15s ease-out;
  }
  .btn:hover { transform: translate(-2px, -2px); box-shadow: 6px 6px 0px #000; }
  .btn:active { transform: translate(4px, 4px); box-shadow: 0px 0px 0px #000; }
  
  .btn-primary { background: var(--accent); color: #fff; }
  .btn-danger { background: var(--danger); color: #fff; }
  .btn-success { background: var(--success); color: #fff; }
  .btn-warning { background: var(--warning); color: #fff; }
  
  .btn-sm { padding: 6px 12px; font-size: 12px; box-shadow: 2px 2px 0px #000; }
  .btn-sm:hover { transform: translate(-1px, -1px); box-shadow: 3px 3px 0px #000; }
  .btn-sm:active { transform: translate(2px, 2px); box-shadow: 0px 0px 0px #000; }

  .btn-icon { padding: 6px; border: 2px solid transparent; background: transparent; color: #000; cursor: pointer; transition: all 0.2s; }
  .btn-icon:hover { background: #f3f4f6; border-color: #000; box-shadow: 2px 2px 0px #000; }

  /* Toolbar */
  .toolbar { display: flex; justify-content: space-between; align-items: center; margin-bottom: 24px; flex-wrap: wrap; gap: 16px; }
  .toolbar-filters { display: flex; gap: 16px; flex-wrap: wrap; }
  .toolbar-actions { display: flex; gap: 12px; }
  .search-bar { display: flex; align-items: center; gap: 8px; background: #fff; border: 2px solid #000; padding: 6px 16px; width: 350px; box-shadow: 4px 4px 0px #000; }
  .search-bar input { border: none; background: transparent; padding: 0; box-shadow: none; transform: none; }
  .search-bar input:focus { box-shadow: none; transform: none; }

  /* Modal */
  .modal-overlay {
    position: fixed; top: 0; left: 0; right: 0; bottom: 0;
    background: rgba(0,0,0,0.6); backdrop-filter: blur(2px);
    display: none; align-items: center; justify-content: center;
    z-index: 1000;
  }
  .modal {
    background: var(--bg-card);
    border: 2px solid #000;
    width: 100%; max-width: 550px;
    max-height: 90vh; overflow-y: auto;
    box-shadow: 8px 8px 0px #000;
    animation: fadeIn 0.2s ease;
  }
  .modal-header { padding: 24px; border-bottom: 2px solid #000; display: flex; justify-content: space-between; align-items: center; background: #f9fafb; }
  .modal-header h3 { font-size: 20px; font-weight: 700; color: #000; text-transform: uppercase;}
  .modal-body { padding: 24px; }
  .modal-footer { padding: 20px 24px; border-top: 2px solid #000; display: flex; justify-content: flex-end; gap: 12px; background: #f9fafb; }

  /* Toast (Z-INDEX FIXED) */
  .toast-container { position: fixed; bottom: 32px; right: 32px; z-index: 10000; display: flex; flex-direction: column; gap: 12px; }
  .toast {
    display: flex; align-items: center; gap: 16px;
    padding: 16px 24px;
    background: #fff;
    border: 2px solid #000;
    box-shadow: 6px 6px 0px #000;
    color: #000; font-size: 15px; font-weight: 600;
    animation: slideIn 0.3s ease;
  }
  .toast.success i { color: var(--success); }
  .toast.error i { color: var(--danger); }
  .toast.warning i { color: var(--warning); }
  @keyframes slideIn { from { transform: translateX(100%); opacity: 0; } to { transform: translateX(0); opacity: 1; } }
  @keyframes fadeOut { to { opacity: 0; transform: translateY(10px); } }
  .show-on-mobile { display: none !important; }

  /* ================= RESPONSIVE / MOBILE ================= */
  @media (max-width: 768px) {
    .hide-on-mobile { display: none !important; }
    .show-on-mobile { display: flex !important; }
    /* Layout */
    .main-wrapper { padding: 16px; }
    .grid-4, .grid-2 { grid-template-columns: 1fr; gap: 16px; }
    .card { padding: 16px; }
    
    /* Topbar & Header */
    .topbar-header { flex-direction: column; align-items: stretch; gap: 16px; padding: 16px; padding-top: calc(env(safe-area-inset-top, 0px) + 16px); }
    .brand { justify-content: center; }
    .topbar-header > div:last-child { flex-direction: column; align-items: stretch; gap: 12px; width: 100%; }
    .search-bar { width: 100%; justify-content: flex-start; }
    
    /* Toolbar & Actions */
    .toolbar { flex-direction: column; align-items: stretch; gap: 16px; }
    .toolbar-filters { width: 100%; flex-direction: column; }
    .toolbar-actions { width: 100%; flex-wrap: wrap; justify-content: space-between; gap: 12px; }
    
    /* Forms */
    .form-row { flex-direction: column; align-items: stretch; gap: 12px; }
    .form-group { width: 100%; margin-bottom: 8px; }
    .form-row .form-group { flex: none !important; }
    
    /* Buttons */
    .btn { padding: 14px; width: 100%; justify-content: center; }
    .toolbar-actions .btn { width: 100%; }
    .section-header .toolbar-actions { width: 100%; flex-direction: column; }
    .section-header .toolbar-actions .btn { width: 100%; }
    
    /* Tables */
    .table-container { -webkit-overflow-scrolling: touch; }
    th, td { padding: 12px; font-size: 13px; }
    
    /* Modals */
    .modal { max-width: 95%; max-height: 90vh; margin: 16px; }
    .modal-header { padding: 16px; flex-direction: column; gap: 12px; text-align: center; position: relative; }
    .modal-header .btn-icon { position: absolute; top: 12px; right: 12px; }
    .modal-body { padding: 16px; }
    .modal-footer { padding: 16px; flex-direction: column; gap: 12px; }
    .modal-footer button { width: 100%; margin: 0; }
    
    /* Mobile Menu Override */
    .mobile-menu-btn { 
      display: inline-flex; align-items: center; justify-content: center; 
      padding: 12px; margin-left: -8px; border-radius: 8px;
    }
    .mobile-menu-btn:active { background: rgba(0,0,0,0.1); }
    .brand { justify-content: flex-start; gap: 8px; }
    .mobile-menu-overlay { 
      position: fixed; top: 0; left: 0; right: 0; bottom: 0; 
      background: rgba(0,0,0,0.5); z-index: 9999; 
      display: none; opacity: 0; transition: opacity 0.3s;
    }
    .mobile-menu-overlay.menu-open { display: block; opacity: 1; }
    
    /* Tabs Sidebar */
    .tabs-container {
      position: fixed; top: 0; left: -280px; width: 280px; height: 100vh;
      background: var(--bg-card); flex-direction: column;
      z-index: 10000; transition: transform 0.3s cubic-bezier(0.4, 0, 0.2, 1);
      box-shadow: 4px 0px 0px #000; padding-top: 24px;
    }
    .tabs-container.menu-open { transform: translateX(280px); }
    .tab-item { padding: 16px 24px; font-size: 16px; border-right: none; border-bottom: 1px solid #e5e7eb; }
    
    /* Specifics */
    .kpi-value { font-size: 28px; }
    .section-header { flex-direction: column; align-items: flex-start; gap: 16px; }
    .section-title { font-size: 20px; }
  }

</style>
</head>
<body>

<!-- LOGIN -->
<div class="login-overlay" id="loginOverlay">
  <div class="login-box">
    <h2><i data-feather="terminal"></i> PLEXUS AUTH</h2>
    <div class="form-group">
      <label>Tên đăng nhập</label>
      <input type="text" id="loginUser" placeholder="admin" onkeydown="if(event.key==='Enter') login()">
    </div>
    <div class="form-group">
      <label>Mật khẩu</label>
      <input type="password" id="loginPass" placeholder="••••••••" onkeydown="if(event.key==='Enter') login()">
    </div>
    <button class="btn btn-primary" style="width: 100%; margin-top: 8px; padding: 14px;" onclick="login()">ĐĂNG NHẬP</button>
    <div style="text-align: center; margin-top: 24px;">
      <button class="btn btn-sm" onclick="checkHealth()"><i data-feather="activity"></i> TRẠNG THÁI MÁY CHỦ</button>
    </div>
  </div>
</div>

<!-- TOP NAVIGATION TABS -->
<header class="topbar">
  <div class="topbar-header">
    <div class="brand">
      <button class="mobile-menu-btn" onclick="toggleMobileMenu()"><i data-feather="menu"></i></button>
      <i data-feather="hexagon" stroke-width="3"></i> PLEXUS SYSTEM
    </div>
    <div style="display: flex; align-items: center; gap: 24px;">
      <div class="search-bar">
        <i data-feather="search"></i>
        <input type="text" id="globalSearch" placeholder="Tìm kiếm key, người dùng..." oninput="debounceSearch()" onkeydown="if(event.key==='Enter') debounceSearch()">
      </div>
      <span style="font-weight: 600; font-size: 14px;" id="lastRefresh">ĐỒNG BỘ TỰ ĐỘNG</span>
      <button class="btn btn-sm btn-danger hide-on-mobile" onclick="logout()"><i data-feather="log-out"></i> THOÁT</button>
    </div>
  </div>
  <div class="mobile-menu-overlay" id="mobileOverlay" onclick="toggleMobileMenu()"></div>
  <div class="tabs-container" id="mobileTabs">
    <div class="tab-item active" onclick="nav('dashboard')"><i data-feather="grid"></i> Trang chủ</div>
    <div class="tab-item" onclick="nav('keys')"><i data-feather="key"></i> Quản lý Key</div>
    <div class="tab-item" onclick="nav('create')"><i data-feather="plus-square"></i> Tạo Key</div>
    <div class="tab-item" onclick="window.location.href='/admin/patches'"><i data-feather="box"></i> Quản lý Patch</div>
    <div class="tab-item" onclick="nav('online')"><i data-feather="radio"></i> Người dùng Online</div>
    <div class="tab-item" onclick="nav('products')"><i data-feather="package"></i> Sản phẩm</div>
    <div class="tab-item" onclick="nav('logs')"><i data-feather="list"></i> Nhật ký</div>
    <div class="tab-item admin-only" onclick="nav('subadmins')"><i data-feather="users"></i> Cấp dưới (Sub-Admin)</div>
    <div class="tab-item admin-only" onclick="nav('settings')"><i data-feather="settings"></i> Cài đặt App</div>
    <div class="tab-item show-on-mobile" onclick="logout()" style="color: var(--danger); font-weight: 700; border-top: 1px solid #e5e7eb; border-bottom: 2px solid transparent; margin-top: 12px;"><i data-feather="log-out"></i> Thoát hệ thống</div>
  </div>
</header>

<!-- MAIN CONTENT -->
<main class="main-wrapper">
  
  <!-- DASHBOARD -->
  <div id="sec-dashboard" class="section active">
    <div class="section-header">
      <h2 class="section-title">Tổng quan hệ thống</h2>
    </div>
    <div class="grid-4">
      <div class="card kpi-card">
        <div class="kpi-label">Tổng số Key <i data-feather="key"></i></div>
        <div class="kpi-value" id="kpiTotal">-</div>
      </div>
      <div class="card kpi-card">
        <div class="kpi-label">Key đang hoạt động <i data-feather="check-circle"></i></div>
        <div class="kpi-value" id="kpiActive" style="color: var(--success);">-</div>
      </div>
      <div class="card kpi-card">
        <div class="kpi-label">Online Now (60s) <i data-feather="activity"></i></div>
        <div class="kpi-value" id="kpiOnline" style="color: var(--accent);">-</div>
      </div>
      <div class="card kpi-card">
        <div class="kpi-label">Expiring Soon <i data-feather="alert-triangle"></i></div>
        <div class="kpi-value" id="kpiExpiring" style="color: var(--warning);">-</div>
      </div>
    </div>
    <div class="grid-2">
      <div class="card">
        <h3 style="font-size: 16px; font-weight: 700; margin-bottom: 24px; text-transform: uppercase;">Status Distribution</h3>
        <div style="height: 300px; position: relative;"><canvas id="chartStatus"></canvas></div>
      </div>
      <div class="card">
        <h3 style="font-size: 16px; font-weight: 700; margin-bottom: 24px; text-transform: uppercase;">Product Usage</h3>
        <div style="height: 300px; position: relative;"><canvas id="chartProducts"></canvas></div>
      </div>
    </div>
  </div>

  <!-- KEYS -->
  <div id="sec-keys" class="section">
    <div class="section-header">
      <h2 class="section-title">Keys Manager</h2>
      <div class="toolbar-actions">
        <button class="btn btn-success" onclick="exportCSV()"><i data-feather="download"></i> Xuất CSV</button>
        <button class="btn btn-primary" onclick="nav('create')"><i data-feather="plus"></i> Tạo mới</button>
      </div>
    </div>
    <div class="toolbar">
      <div class="toolbar-filters">
        <select id="filterProduct" onchange="renderKeysTable()">
          <option value="">Tất cả sản phẩm</option>
        </select>
        <select id="filterStatus" onchange="renderKeysTable()">
          <option value="">Tất cả trạng thái</option>
          <option value="active">Đang hoạt động</option>
          <option value="pending">Chờ sử dụng</option>
          <option value="expired">Đã hết hạn</option>
          <option value="banned">Đã bị cấm</option>
        </select>
      </div>
      <div class="toolbar-actions" id="bulkActions" style="display: none;">
        <span style="font-size: 14px; font-weight: 700; align-self: center;" id="bulkCount">0 selected</span>
        <button class="btn btn-danger" onclick="bulkAction('ban')"><i data-feather="slash"></i> Cấm tất cả</button>
        <button class="btn btn-danger" onclick="bulkAction('delete')"><i data-feather="trash"></i> Xóa tất cả</button>
      </div>
    </div>
    <div class="table-container">
      <table>
        <thead>
          <tr>
            <th style="width: 40px;"><input type="checkbox" id="selectAll" onchange="toggleSelectAll(this)"></th>
            <th>MÃ KEY</th>
            <th>SẢN PHẨM</th>
            <th>LOẠI</th>
            <th>TRẠNG THÁI</th>
            <th>NGƯỜI TẠO</th>
            <th>THIẾT BỊ</th>
            <th>HẾT HẠN</th>
            <th style="text-align: right;">THAO TÁC</th>
          </tr>
        </thead>
        <tbody id="keysTableBody">
          <tr><td colspan="9" style="text-align: center; padding: 40px; font-weight: 600;">ĐANG TẢI DỮ LIỆU...</td></tr>
        </tbody>
      </table>
    </div>
    <div style="display: flex; justify-content: space-between; align-items: center; margin-top: 24px; font-weight: 600;">
      <span id="pageInfo">Đang hiển thị 0 key</span>
      <div style="display: flex; gap: 12px;">
        <button class="btn btn-sm" onclick="changePage(-1)">TRANG TRƯỚC</button>
        <button class="btn btn-sm" onclick="changePage(1)">TRANG SAU</button>
      </div>
    </div>
  </div>

  <!-- CREATE KEYS -->
  <div id="sec-create" class="section">
    <div class="section-header">
      <h2 class="section-title">Tạo Key mới</h2>
    </div>
    <div class="grid-2">
      <div class="card">
        <div style="display: flex; gap: 24px; margin-bottom: 24px; padding-bottom: 16px; border-bottom: 2px solid #000; flex-wrap: wrap;">
          <label style="display: flex; align-items: center; gap: 8px; cursor: pointer; font-weight: 700; white-space: nowrap;">
            <input type="radio" name="createMode" value="auto" checked onchange="toggleCreateMode()"> TẠO TỰ ĐỘNG
          </label>
          <label style="display: flex; align-items: center; gap: 8px; cursor: pointer; font-weight: 700; white-space: nowrap;">
            <input type="radio" name="createMode" value="manual" onchange="toggleCreateMode()"> TẠO THỦ CÔNG
          </label>
        </div>

        <div id="createAutoForm" onkeydown="if(event.key==='Enter') executeCreateKey()">
          <div class="form-row">
            <div class="form-group" style="flex: 1;"><label>Sản phẩm</label><select id="cProduct"></select></div>
            <div class="form-group" style="flex: 1;"><label>Loại Key</label><select id="cType"><option value="basic">Basic</option><option value="pro">Pro</option><option value="vip">VIP</option></select></div>
          </div>
          <div class="form-row">
            <div class="form-group" style="flex: 1;"><label>Tiền tố</label><input type="text" id="cPrefix" placeholder="PLX" value="PLX" style="text-transform: uppercase;"></div>
            <div class="form-group" style="flex: 1;"><label>Độ dài (Blocks)</label><select id="cSuffix"><option value="8">2 Blocks</option><option value="12" selected>3 Blocks</option><option value="16">4 Blocks</option><option value="24">6 Blocks</option></select></div>
          </div>
          <div class="form-row">
            <div class="form-group" style="flex: 1;"><label>Thời hạn (Ngày)</label><input type="number" id="cDays" value="30" min="1"></div>
            <div class="form-group" style="flex: 1;">
              <label>Thiết bị tối đa</label>
              <div style="display: flex; align-items: center; gap: 12px;">
                <input type="number" id="cDevices" value="1" min="0">
                <label style="margin: 0; display: flex; align-items: center; white-space: nowrap;"><input type="checkbox" id="cUnlimited" onchange="if(this.checked){document.getElementById('cDevices').value=0;document.getElementById('cDevices').disabled=true}else{document.getElementById('cDevices').disabled=false;document.getElementById('cDevices').value=1}"> KHÔNG GIỚI HẠN</label>
              </div>
            </div>
          </div>
          <div class="form-group"><label>Số lượng</label><input type="number" id="cCount" value="1" min="1" max="500"></div>
          <div class="form-group"><label>Ghi chú</label><input type="text" id="cNote" placeholder="Ghi chú thêm..."></div>
        </div>

        <div id="createManualForm" style="display: none;" onkeydown="if(event.key==='Enter') executeCreateKey()">
           <div class="form-row">
            <div class="form-group" style="flex: 1;"><label>Sản phẩm</label><select id="cmProduct"></select></div>
            <div class="form-group" style="flex: 1;"><label>Loại Key</label><select id="cmType"><option value="basic">Basic</option><option value="pro">Pro</option><option value="vip">VIP</option></select></div>
          </div>
          <div class="form-group"><label>Nhập Key tùy chỉnh</label><input type="text" id="cmKey" placeholder="Nhập mã key..." class="mono"></div>
          <div class="form-row">
            <div class="form-group" style="flex: 1;"><label>Duration</label><input type="number" id="cmDays" value="30" min="1"></div>
            <div class="form-group" style="flex: 1;"><label>Devices</label><input type="number" id="cmDevices" value="1" min="0" placeholder="0 = unlim"></div>
          </div>
        </div>

        <button class="btn btn-primary" style="width: 100%; padding: 16px; margin-top: 16px; font-size: 16px;" onclick="executeCreateKey()" id="btnCreate"><i data-feather="zap"></i> TIẾN HÀNH TẠO KEY</button>
      </div>

      <div class="card" style="display: flex; flex-direction: column;">
        <h3 style="font-size: 18px; font-weight: 700; margin-bottom: 16px; text-transform: uppercase;">Bảng điều khiển</h3>
        <div id="createResultBox" style="flex: 1; background: #000; color: #0f0; border: 2px solid #000; padding: 20px; overflow-y: auto; font-family: var(--font-mono); font-size: 14px; box-shadow: inset 0 0 10px rgba(0,0,0,0.5);">
          > HỆ THỐNG ĐÃ SẴN SÀNG...
        </div>
        <button class="btn" style="margin-top: 16px; display: none; background: #e5e7eb;" id="btnCopyResult" onclick="copyResultKeys()"><i data-feather="copy"></i> COPY TO CLIPBOARD</button>
      </div>
    </div>
  
    <!-- New History Panel -->
    <div class="card" style="margin-top: 32px;">
      <h3 style="font-size: 16px; font-weight: 700; margin-bottom: 16px; text-transform: uppercase;">Key Generation History</h3>
      <div class="table-container">
        <table>
          <thead>
            <tr><th>Time</th><th>Creator</th><th>Sản phẩm</th><th>Type</th><th>Keys Generated</th></tr>
          </thead>
          <tbody id="createHistoryTableBody"></tbody>
        </table>
      </div>
    </div>
  </div>

  <!-- ONLINE -->
  <div id="sec-online" class="section">
    <div class="section-header">
      <h2 class="section-title">Online Streams</h2>
    </div>
    <div class="table-container">
      <table>
        <thead>
          <tr><th>MÃ KEY</th><th>SẢN PHẨM</th><th>LOẠI</th><th>MÃ PHẦN CỨNG</th><th>NGƯỜI TẠO</th><th>LAST SEEN</th></tr>
        </thead>
        <tbody id="onlineTableBody"></tbody>
      </table>
    </div>
  </div>

  <!-- PRODUCTS -->
  <div id="sec-products" class="section">
    <div class="section-header">
      <h2 class="section-title">Product Config</h2>
    </div>
    <div class="card" style="margin-bottom: 32px;">
      <div class="form-row" style="margin: 0; align-items: flex-end;" onkeydown="if(event.key==='Enter') createProduct()">
        <div class="form-group" style="margin: 0; flex: 1;"><label>Name</label><input type="text" id="pName" placeholder="e.g. internal"></div>
        <div class="form-group" style="margin: 0; flex: 1;"><label>Secret</label><input type="text" id="pSecret" class="mono" placeholder="Alphanumeric string"></div>
        <div class="form-group" style="margin: 0; flex: 1;"><label>Admin Pass</label><input type="password" id="pPass" placeholder="Required"></div>
        <button class="btn btn-primary" onclick="createProduct()" style="height: 44px; padding: 0 24px;"><i data-feather="plus"></i> REGISTER</button>
      </div>
    </div>
    <div class="table-container">
      <table>
        <thead><tr><th>ID</th><th>NAME</th><th>SECRET</th><th>CREATED</th><th style="text-align: right;">THAO TÁC</th></tr></thead>
        <tbody id="productsTableBody"></tbody>
      </table>
    </div>
  </div>

  <!-- LOGS -->
  <div id="sec-logs" class="section">
    <div class="section-header">
      <h2 class="section-title">Audit Trail</h2>
    </div>
    <div class="table-container">
      <table>
        <thead><tr><th>TIMESTAMP</th><th>HÀNH ĐỘNG</th><th>TARGET KEY</th><th>DETAILS</th></tr></thead>
        <tbody id="logsTableBody"></tbody>
      </table>
    </div>
  </div>

  <!-- SUB-ADMINS -->
  <div id="sec-subadmins" class="section admin-only">
    <div class="section-header">
      <h2 class="section-title">Tài khoản cấp dưới</h2>
      <button class="btn btn-primary" onclick="openSubAdminModal()"><i data-feather="user-plus"></i> THÊM TÀI KHOẢN</button>
    </div>
    <div class="table-container" style="max-width: 1000px;">
      <table>
        <thead><tr><th>TÊN TÀI KHOẢN</th><th>SẢN PHẨM ĐƯỢC PHÉP</th><th>CHỨC VỤ</th><th style="text-align: right;">THAO TÁC</th></tr></thead>
        <tbody id="subAdminsTableBody"></tbody>
      </table>
    </div>
  </div>

  <!-- SETTINGS -->
  <div id="sec-settings" class="section admin-only">
    <div class="section-header">
      <h2 class="section-title">Cài đặt Hệ thống</h2>
      <button class="btn btn-primary" onclick="saveSettings()"><i data-feather="save"></i> LƯU THAY ĐỔI</button>
    </div>
    <div class="card" style="max-width: 600px;">
      <div class="form-group">
        <label>Phiên bản iOS mới nhất bắt buộc cập nhật</label>
        <input type="text" id="setIosVersion" placeholder="e.g. 1.2.0">
      </div>
      <div class="form-group">
        <label>Đường dẫn cập nhật (URL)</label>
        <input type="url" id="setUpdateUrl" placeholder="https://github.com/..." class="mono">
      </div>
    </div>
  </div>

</main>

<!-- Sub-Admin Edit Modal -->
<div class="modal-overlay" id="subAdminModal" onclick="if(event.target===this) closeModal('subAdminModal')">
  <div class="modal">
    <div class="modal-header">
      <h3 id="saModalTitle">Thêm Sub-Admin</h3>
      <button class="btn-icon" onclick="closeModal('subAdminModal')"><i data-feather="x"></i></button>
    </div>
    <div class="modal-body">
      <input type="hidden" id="saMode" value="add">
      <div class="form-group">
        <label>Tên đăng nhập</label>
        <input type="text" id="samUser" placeholder="admin2">
      </div>
      <div class="form-group">
        <label>Mật khẩu <span id="samPassHint" class="text-muted" style="font-weight: normal; font-size: 12px;"></span></label>
        <input type="password" id="samPass" placeholder="••••••••">
      </div>
      <div class="form-group">
        <label>Sản phẩm được cấp phép</label>
        <div id="samProductsList" style="display: flex; flex-direction: column; gap: 8px; max-height: 200px; overflow-y: auto; background: var(--bg); border: 1px solid var(--border); padding: 12px;">
          <!-- populated dynamically -->
        </div>
      </div>
    </div>
    <div class="modal-footer" style="margin-top: 24px; display: flex; justify-content: flex-end; gap: 16px;">
      <button class="btn" onclick="closeModal('subAdminModal')">HỦY</button>
      <button class="btn btn-primary" onclick="saveSubAdmin()">LƯU LẠI</button>
    </div>
  </div>
</div>

<!-- Key Detail / Edit Modal -->
<div class="modal-overlay" id="editModal" onclick="if(event.target===this) closeModal('editModal')">
  <div class="modal">
    <div class="modal-header">
      <h3>Key Inspector</h3>
      <button class="btn-icon" onclick="closeModal('editModal')"><i data-feather="x"></i></button>
    </div>
    <div class="modal-body" onkeydown="if(event.key==='Enter') actionKey('save')">
      <div style="background: #000; padding: 16px; border: 2px solid #000; font-family: var(--font-mono); color: #0f0; font-size: 16px; text-align: center; margin-bottom: 24px; word-break: break-all;" id="emKey">
        -
      </div>
      <div class="grid-2">
        <div class="form-group"><label>Status</label><div id="emStatus" class="badge"></div></div>
        <div class="form-group"><label>Sản phẩm</label><div id="emProduct" style="font-weight: 700; font-size: 18px;">-</div></div>
        <div class="form-group"><label>Type</label>
          <select id="emType"><option value="basic">Basic</option><option value="pro">Pro</option><option value="vip">VIP</option></select>
        </div>
        <div class="form-group"><label>Thiết bị tối đa</label>
          <input type="number" id="emDevices" min="0">
        </div>
        <div class="form-group" style="grid-column: span 2;"><label>User Name</label><input type="text" id="emUser" disabled style="background: #f3f4f6; cursor: not-allowed;"></div>
        <div class="form-group" style="grid-column: span 2;"><label>Bound HWIDs</label><div id="emHwid" class="mono text-muted" style="background: #f9fafb; padding: 12px; border: 1px dashed #000; word-break: break-all;"></div></div>
        
        <div class="form-group" style="grid-column: span 2; border-top: 2px solid #000; padding-top: 24px; margin-top: 8px;">
          <label>Add Time (Days)</label>
          <div style="display: flex; gap: 16px;">
            <input type="number" id="emExtend" value="30" min="1" style="width: 120px;">
            <button class="btn btn-warning" onclick="actionKey('extend')"><i data-feather="clock"></i> EXTEND</button>
          </div>
        </div>
      </div>
    </div>
    <div class="modal-footer">
      <button class="btn" onclick="actionKey('reset')"><i data-feather="refresh-cw"></i> CLEAR HWID</button>
      <button class="btn btn-danger" id="emBanBtn" onclick="actionKey('toggleBan')"><i data-feather="slash"></i> BAN</button>
      <button class="btn btn-danger" onclick="actionKey('delete')"><i data-feather="trash"></i> PURGE</button>
      <button class="btn btn-primary" onclick="actionKey('save')"><i data-feather="save"></i> SAVE</button>
    </div>
  </div>
</div>

<!-- Toasts -->
<div class="toast-container" id="toastContainer"></div>

<script>
  // --- Core State & Auth ---
  const API = window.location.origin + '/api';
  let token = '';
  let isSubAdmin = false;
  let currentAdminName = "MASTER";
  let dataStore = { keys: [], products: [], logs: [], stats: null, online: [] };
  let selectedKeys = new Set();
  let currentPage = 1;
  const perPage = 50;
  let editCurrentKey = null;
  let charts = {};

  // --- Init ---
  feather.replace();
  
  function showToast(msg, type = 'success') {
    const t = document.createElement('div');
    t.className = \`toast \${type}\`;
    t.innerHTML = \`<i data-feather="\${type==='success'?'check-circle': type==='warning'?'alert-triangle':'alert-circle'}"></i> <span>\${msg}</span>\`;
    document.getElementById('toastContainer').appendChild(t);
    feather.replace();
    setTimeout(() => {
      t.style.animation = 'fadeOut 0.3s forwards';
      setTimeout(() => t.remove(), 300);
    }, 4000);
  }

  async function req(endpoint, opts = {}) {
    opts.headers = { ...opts.headers, 'Authorization': 'Basic ' + token };
    const r = await fetch(API + endpoint, opts);
    const j = await r.json();
    if (r.status === 401) throw new Error('Unauthorized');
    if (!j.success && j.message) throw new Error(j.message);
    return j;
  }

  async function login() {
    const u = document.getElementById('loginUser').value.trim();
    const p = document.getElementById('loginPass').value.trim();
    if(!u || !p) return showToast('Vui lòng nhập tài khoản và mật khẩu', 'warning');
    
    try {
      token = btoa(unescape(encodeURIComponent(u + ':' + p)));
    } catch(e) {
      return showToast('Mật khẩu chứa kí tự không hợp lệ', 'error');
    }

    try {
      const r = await fetch(API + '/health', { headers: { 'Authorization': 'Basic ' + token } });
      
      if (r.status === 401) {
        throw new Error('Sai tài khoản hoặc mật khẩu');
      }

      const j = await r.json();
      
      document.getElementById('loginOverlay').style.display = 'none';
      if (j.role === 'subadmin') {
        isSubAdmin = true;
        currentAdminName = j.user;
        showToast('Đăng nhập Sub-Admin thành công', 'success');
      } else {
        isSubAdmin = false;
        currentAdminName = j.user || "MASTER";
        showToast('Đăng nhập thành công', 'success');
      }
      
      initApp();
      
      if (!j.success || j.supabase === 'error') {
         showToast('Cảnh báo: Server chưa kết nối được Database!', 'warning');
      }
      
    } catch(e) {
      showToast(e.message, 'error');
      token = '';
    }
  }

  function logout() {
    token = '';
    document.getElementById('loginOverlay').style.display = 'flex';
    document.getElementById('loginPass').value = '';
    if (refreshTimer) clearInterval(refreshTimer);
  }

  async function checkHealth() {
    try {
      const r = await fetch(API + '/health');
      const j = await r.json();
      showToast('Server OK! DB: ' + j.supabase);
    } catch(e) { showToast('Server offline', 'error'); }
  }

  // --- App Logic ---
  let refreshTimer;
  function initApp() {
    if(!isSubAdmin) {
      localStorage.setItem('rox_master_token', token);
      document.body.classList.remove('subadmin-mode');
    } else {
      document.body.classList.add('subadmin-mode');
    }
    nav('dashboard');
    refreshAll();
    refreshTimer = setInterval(refreshAll, 15000);
    renderSubAdmins();
  }

  let isMobileMenuOpen = false;
  function toggleMobileMenu(forceState) {
    if (typeof forceState === 'boolean') isMobileMenuOpen = forceState;
    else isMobileMenuOpen = !isMobileMenuOpen;
    
    const tabs = document.getElementById('mobileTabs');
    const overlay = document.getElementById('mobileOverlay');
    if(!tabs || !overlay) return;

    if (isMobileMenuOpen) {
      overlay.style.display = 'block';
      setTimeout(() => {
        tabs.classList.add('menu-open');
        overlay.classList.add('menu-open');
      }, 10);
    } else {
      tabs.classList.remove('menu-open');
      overlay.classList.remove('menu-open');
      setTimeout(() => { if(!isMobileMenuOpen) overlay.style.display = 'none'; }, 300);
    }
  }

  function nav(sec) {
    document.querySelectorAll('.section').forEach(e => e.classList.remove('active'));
    document.getElementById('sec-' + sec).classList.add('active');
    document.querySelectorAll('.tab-item').forEach(e => e.classList.remove('active'));
    const target = Array.from(document.querySelectorAll('.tab-item')).find(e => e.textContent.toLowerCase().includes(sec.replace('subadmins', 'sub-admins').toLowerCase()));
    if(target) target.classList.add('active');
    if(sec === 'dashboard') initCharts();
    toggleMobileMenu(false); // Auto-close menu on mobile
  }

  async function refreshAll() {
    try {
      const [pr, keys, logs, stats, onl] = await Promise.all([
        req('/products'), req('/keys'), req('/logs'), req('/stats'), req('/online')
      ]);
      dataStore.products = pr.data || [];
      dataStore.keys = keys.data || [];
      dataStore.logs = logs.data || [];
      dataStore.stats = stats.data || null;
      dataStore.online = onl.data || [];
      
      updateUI();
      document.getElementById('lastRefresh').textContent = new Date().toLocaleTimeString();
    } catch(e) {
      if(e.message === 'Unauthorized') logout();
    }
  }

  function updateUI() {
    updateDashboard();
    renderKeysTable();
    updateFilters();
    renderOnline();
    renderProducts();
    renderLogs();
    if (typeof renderCreateHistory === 'function') renderCreateHistory();
  }

  function getStatusStyle(k) {
    if(k.status === 'banned') return {c: 'badge-banned', t: 'BANNED'};
    if(k.status === 'expired') return {c: 'badge-expired', t: 'EXPIRED'};
    if(!k.expires_at) return {c: 'badge-pending', t: 'PENDING'};
    const exp = new Date(k.expires_at);
    if(exp <= new Date()) return {c: 'badge-expired', t: 'EXPIRED'};
    return {c: 'badge-active', t: 'ACTIVE'};
  }
  function copy(txt) { navigator.clipboard.writeText(txt); showToast('Copied to clipboard'); }

  // --- Dashboard ---
  function updateDashboard() {
    if(!dataStore.stats) return;
    document.getElementById('kpiTotal').textContent = dataStore.stats.total;
    document.getElementById('kpiActive').textContent = dataStore.stats.active;
    document.getElementById('kpiOnline').textContent = dataStore.online.length;
    
    const now = new Date();
    const next7Days = new Date(now.getTime() + 7 * 24 * 3600 * 1000);
    const expiring = dataStore.keys.filter(k => k.status === 'active' && k.expires_at && new Date(k.expires_at) < next7Days && new Date(k.expires_at) > now).length;
    document.getElementById('kpiExpiring').textContent = expiring;

    updateCharts();
  }

  function initCharts() {
    if(charts.status) return;
    Chart.defaults.color = '#000';
    Chart.defaults.font.family = "'Inter', sans-serif";
    Chart.defaults.font.weight = "600";
    
    const ctx1 = document.getElementById('chartStatus').getContext('2d');
    charts.status = new Chart(ctx1, {
      type: 'doughnut',
      data: { labels: ['ACTIVE', 'PENDING', 'EXPIRED', 'BANNED'], datasets: [{ data: [0,0,0,0], backgroundColor: ['#16a34a', '#e5e7eb', '#d97706', '#dc2626'], borderWidth: 2, borderColor: '#000' }] },
      options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { position: 'right' } }, cutout: '60%' }
    });

    const ctx2 = document.getElementById('chartProducts').getContext('2d');
    charts.products = new Chart(ctx2, {
      type: 'bar',
      data: { labels: [], datasets: [{ label: 'KEYS', data: [], backgroundColor: '#2563eb', borderWidth: 2, borderColor: '#000' }] },
      options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } }, scales: { y: { beginAtZero: true, grid: { color: '#000' } }, x: { grid: { display: false } } } }
    });
  }

  function updateCharts() {
    if(!charts.status) return;
    const { total, active, banned, expired } = dataStore.stats;
    const pending = total - active - banned - expired;
    charts.status.data.datasets[0].data = [active, Math.max(pending,0), expired, banned];
    charts.status.update();

    const pMap = {};
    dataStore.products.forEach(p => pMap[p.id] = p.name);
    const counts = {};
    dataStore.keys.forEach(k => counts[k.product_id] = (counts[k.product_id] || 0) + 1);
    charts.products.data.labels = Object.keys(counts).map(id => pMap[id] || 'UNK');
    charts.products.data.datasets[0].data = Object.values(counts);
    charts.products.update();
  }

  // --- Keys Manager ---
  let searchTimeout;
  function debounceSearch() { clearTimeout(searchTimeout); searchTimeout = setTimeout(() => { currentPage = 1; renderKeysTable(); }, 300); }
  function updateFilters() {
    const pSel = document.getElementById('filterProduct');
    const cSel = document.getElementById('cProduct');
    const cmSel = document.getElementById('cmProduct');
    const curP = pSel.value, curC = cSel.value, curCm = cmSel.value;
    
    let html = '<option value="">ALL PRODUCTS</option>' + dataStore.products.map(p => \`<option value="\${p.id}">\${p.name.toUpperCase()}</option>\`).join('');
    let htmlOpts = dataStore.products.map(p => \`<option value="\${p.id}">\${p.name.toUpperCase()}</option>\`).join('');
    
    pSel.innerHTML = html; pSel.value = curP;
    cSel.innerHTML = htmlOpts; cSel.value = curC || (dataStore.products[0]?.id);
    cmSel.innerHTML = htmlOpts; cmSel.value = curCm || (dataStore.products[0]?.id);
  }

  function getFilteredKeys() {
    let q = document.getElementById('globalSearch').value.toLowerCase();
    let p = document.getElementById('filterProduct').value;
    let s = document.getElementById('filterStatus').value;
    
    return dataStore.keys.filter(k => {
      if(p && k.product_id != p) return false;
      if(s) {
        const style = getStatusStyle(k);
        if(s === 'active' && style.t !== 'ACTIVE') return false;
        if(s === 'pending' && style.t !== 'PENDING') return false;
        if(s === 'expired' && style.t !== 'EXPIRED') return false;
        if(s === 'banned' && style.t !== 'BANNED') return false;
      }
      if(q) {
        if(!k.key.toLowerCase().includes(q) && !(k.user||'').toLowerCase().includes(q) && !(k.hwid||'').toLowerCase().includes(q)) return false;
      }
      return true;
    });
  }

  function changePage(delta) {
    const list = getFilteredKeys();
    const max = Math.ceil(list.length / perPage) || 1;
    currentPage = Math.max(1, Math.min(currentPage + delta, max));
    renderKeysTable();
  }

  function renderKeysTable() {
    const list = getFilteredKeys();
    const max = Math.ceil(list.length / perPage) || 1;
    if(currentPage > max) currentPage = max;
    
    document.getElementById('pageInfo').textContent = \`SHOWING \${(currentPage-1)*perPage + 1} - \${Math.min(currentPage*perPage, list.length)} OF \${list.length}\`;
    
    const tbody = document.getElementById('keysTableBody');
    if(!list.length) { tbody.innerHTML = \`<tr><td colspan="9" style="text-align: center; padding: 40px; font-weight: 700;">NO MATCHES</td></tr>\`; return; }

    const pMap = {}; dataStore.products.forEach(x => pMap[x.id] = x.name);
    const now = new Date();
    const next7Days = new Date(now.getTime() + 7 * 24 * 3600 * 1000);

    const slice = list.slice((currentPage-1)*perPage, currentPage*perPage);
    tbody.innerHTML = slice.map(k => {
      const s = getStatusStyle(k);
      const hwidCount = k.device_count || 0;
      const maxDev = k.max_devices === 0 ? 'UNL' : k.max_devices;
      const expD = k.expires_at ? new Date(k.expires_at) : null;
      let expStr = expD ? expD.toLocaleDateString() : 'NEVER';
      let warn = '';
      if(s.t === 'ACTIVE' && expD && expD < next7Days) warn = \`<span class="badge badge-warn" title="Expiring soon!">!</span>\`;
      
      return \`<tr>
        <td><input type="checkbox" class="row-check" value="\${k.key}" \${selectedKeys.has(k.key)?'checked':''} onchange="toggleSelect(this)"></td>
        <td class="mono copyable" onclick="copy('\${k.key}')">\${k.key}</td>
        <td><span class="badge" style="background: #e5e7eb;">\${pMap[k.product_id]||'UNK'}</span></td>
        <td style="font-size: 13px; font-weight: 700; text-transform: uppercase;">\${k.type||'BASIC'}</td>
        <td><span class="badge \${s.c}">\${s.t}</span>\${warn}</td>
        <td style="font-weight: 600;">\${k.user||'-'}</td>
        <td class="mono">\${hwidCount}/\${maxDev}</td>
        <td style="font-weight: 600;">\${expStr}</td>
        <td style="text-align: right;">
          <button class="btn-icon" onclick="openEditModal('\${k.key}')"><i data-feather="edit-2"></i></button>
        </td>
      </tr>\`;
    }).join('');
    feather.replace();
    updateBulkUI();
  }

  // --- Bulk & Export ---
  function toggleSelectAll(el) {
    const slice = getFilteredKeys().slice((currentPage-1)*perPage, currentPage*perPage);
    slice.forEach(k => {
      if(el.checked) selectedKeys.add(k.key); else selectedKeys.delete(k.key);
    });
    renderKeysTable();
  }
  function toggleSelect(el) {
    if(el.checked) selectedKeys.add(el.value); else selectedKeys.delete(el.value);
    updateBulkUI();
  }
  function updateBulkUI() {
    const bar = document.getElementById('bulkActions');
    if(selectedKeys.size > 0 && !isSubAdmin) {
      bar.style.display = 'flex';
      document.getElementById('bulkCount').textContent = selectedKeys.size + ' SELECTED';
    } else {
      bar.style.display = 'none';
    }
  }
  async function bulkAction(action) {

    if(!confirm(\`EXECUTE \${action.toUpperCase()} ON \${selectedKeys.size} KEYS?\`)) return;
    const keys = Array.from(selectedKeys);
    let successCount = 0;
    for(let k of keys) {
      try {
        if(action === 'delete') await req('/keys/' + k, { method: 'DELETE' });
        if(action === 'ban') await req('/keys/' + k + '/ban', { method: 'POST' });
        successCount++;
      } catch(e) {}
    }
    showToast(\`\${action} COMPLETED (\${successCount})\`);
    selectedKeys.clear();
    refreshAll();
  }
  function exportCSV() {
    const list = getFilteredKeys();
    const pMap = {}; dataStore.products.forEach(x => pMap[x.id] = x.name);
    let csv = 'Key,Product,Type,Status,User,Devices,MaxDevices,Expires,Note\\\\n';
    list.forEach(k => {
      const p = pMap[k.product_id] || '';
      const hwidCount = k.hwid && k.hwid !== '[]' && k.hwid !== '' ? (k.hwid.startsWith('[') ? JSON.parse(k.hwid).length : 1) : 0;
      csv += \`\${k.key},\${p},\${k.type},\${getStatusStyle(k).t},\${k.user||''},\${hwidCount},\${k.max_devices},\${k.expires_at||''},"\${k.note||''}"\\\\n\`;
    });
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a'); a.href = url; a.download = 'plexus_export.csv'; a.click();
  }

  // --- Create ---
  function toggleCreateMode() {
    const mode = document.querySelector('input[name="createMode"]:checked').value;
    document.getElementById('createAutoForm').style.display = mode === 'auto' ? 'block' : 'none';
    document.getElementById('createManualForm').style.display = mode === 'manual' ? 'block' : 'none';
  }
  let generatedKeys = [];
  async function executeCreateKey() {

    const mode = document.querySelector('input[name="createMode"]:checked').value;
    const btn = document.getElementById('btnCreate');
    btn.disabled = true; btn.innerHTML = '<i data-feather="loader" class="spin"></i> EXECUTING...'; feather.replace();

    let body = {};
    if(mode === 'auto') {
      body = {
        product_id: parseInt(document.getElementById('cProduct').value),
        type: document.getElementById('cType').value,
        prefix: document.getElementById('cPrefix').value.trim(),
        suffixLength: parseInt(document.getElementById('cSuffix').value),
        days: parseInt(document.getElementById('cDays').value),
        max_devices: document.getElementById('cUnlimited').checked ? 0 : parseInt(document.getElementById('cDevices').value),
        count: parseInt(document.getElementById('cCount').value),
        creator: currentAdminName,
        note: document.getElementById('cNote').value.trim()
      };
    } else {
      body = {
        product_id: parseInt(document.getElementById('cmProduct').value),
        type: document.getElementById('cmType').value,
        custom_key: document.getElementById('cmKey').value.trim(),
        days: parseInt(document.getElementById('cmDays').value),
        max_devices: parseInt(document.getElementById('cmDevices').value),
        creator: currentAdminName
      };
    }

    try {
      const r = await req('/keys', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify(body) });
      showToast(r.message);
      
      const resBox = document.getElementById('createResultBox');
      const list = Array.isArray(r.data) ? r.data : [r.data];
      generatedKeys = list.map(x => x.key);
      resBox.innerHTML = list.map(x => \`<div>> \${x.key}</div>\`).join('');
      document.getElementById('btnCopyResult').style.display = 'inline-flex';
      refreshAll();
    } catch(e) { showToast(e.message, 'error'); }
    
    btn.disabled = false; btn.innerHTML = '<i data-feather="zap"></i> TIẾN HÀNH TẠO KEY'; feather.replace();
  }
  function copyResultKeys() { copy(generatedKeys.join('\\\\n')); }

  // --- Modal / Edit ---
  function openEditModal(keyString) {
    const k = dataStore.keys.find(x => x.key === keyString);
    if(!k) return;
    editCurrentKey = k;
    const pMap = {}; dataStore.products.forEach(x => pMap[x.id] = x.name);
    
    document.getElementById('emKey').textContent = k.key;
    document.getElementById('emStatus').className = 'badge ' + getStatusStyle(k).c;
    document.getElementById('emStatus').textContent = getStatusStyle(k).t;
    document.getElementById('emProduct').textContent = pMap[k.product_id]||'UNK';
    document.getElementById('emType').value = k.type || 'basic';
    document.getElementById('emDevices').value = k.max_devices === 0 ? 0 : k.max_devices;
    document.getElementById('emUser').value = k.user || '-';
    
    let hList = k.devices || [];
    document.getElementById('emHwid').textContent = hList.length ? hList.join(', ') : 'NO HARDWARE BOUND';
    
    const banBtn = document.getElementById('emBanBtn');
    if(k.status === 'banned') { banBtn.innerHTML = '<i data-feather="check"></i> UNBAN'; banBtn.className = 'btn btn-primary'; }
    else { banBtn.innerHTML = '<i data-feather="slash"></i> BAN'; banBtn.className = 'btn btn-danger'; }

    document.getElementById('editModal').style.display = 'flex';
    feather.replace();
  }
  function closeModal(id) { document.getElementById(id).style.display = 'none'; }

  async function actionKey(action) {

    const k = editCurrentKey; if(!k) return;
    const kenc = encodeURIComponent(k.key);
    try {
      if(action === 'delete') {
        if(!confirm('PURGE KEY FOREVER?')) return;
        await req('/keys/' + kenc, { method: 'DELETE' });
        showToast('PURGED'); closeModal('editModal');
      }
      else if(action === 'reset') {
        await req('/keys/' + kenc + '/reset-hwid', { method: 'POST' });
        showToast('HWID CLEARED');
      }
      else if(action === 'toggleBan') {
        const a = k.status === 'banned' ? 'unban' : 'ban';
        await req('/keys/' + kenc + '/' + a, { method: 'POST' });
        showToast(a.toUpperCase() + 'NED');
      }
      else if(action === 'extend') {
        const d = document.getElementById('emExtend').value;
        await req('/keys/' + kenc + '/extend', { method: 'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({days:parseInt(d)}) });
        showToast('EXTENDED');
      }
      else if(action === 'save') {
        const t = document.getElementById('emType').value;
        const d = parseInt(document.getElementById('emDevices').value);
        if(t !== k.type) await req('/keys/' + kenc + '/type', { method: 'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({type:t}) });
        if(d !== k.max_devices) await req('/keys/' + kenc + '/max-devices', { method: 'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({max_devices:d}) });
        showToast('SAVED');
      }
      refreshAll();
      if(action !== 'delete') setTimeout(() => openEditModal(k.key), 500);
    } catch(e) { showToast(e.message, 'error'); }
  }

  
  function renderCreateHistory() {
    const tbody = document.getElementById('createHistoryTableBody');
    if (!tbody) return;
    const createLogs = dataStore.logs.filter(l => l.action === 'create').slice(0, 50);
    if (!createLogs.length) {
      tbody.innerHTML = '<tr><td colspan="5" style="text-align: center; padding: 20px; font-weight: 700;">CHƯA CÓ LỊCH SỬ</td></tr>';
      return;
    }
    const pMap = {}; dataStore.products.forEach(x => pMap[x.id] = x.name);
    
    tbody.innerHTML = createLogs.map(l => {
      const creatorMatch = l.detail.match(/\\[Creator: (.*?)\\]/);
      const typeMatch = l.detail.match(/\\[Type: (.*?)\\]/);
      const prodMatch = l.detail.match(/\\[Product: (\\d+)\\]/);
      
      const creator = creatorMatch ? creatorMatch[1] : 'MASTER';
      const type = typeMatch ? typeMatch[1] : 'UNK';
      const prodId = prodMatch ? parseInt(prodMatch[1]) : null;
      const product = pMap[prodId] || 'UNK';
      
      return '<tr>' +
        '<td class="mono text-muted">' + new Date(l.created_at).toLocaleString() + '</td>' +
        '<td style="font-weight: 700; color: var(--accent);">' + creator + '</td>' +
        '<td><span class="badge" style="background: #e5e7eb;">' + product + '</span></td>' +
        '<td style="font-weight: 700; text-transform: uppercase;">' + type + '</td>' +
        '<td class="mono">' + l.key + '</td>' +
      '</tr>';
    }).join('');
  }

  // --- Online & Logs & Products ---
  function renderOnline() {
    const tbody = document.getElementById('onlineTableBody');
    if(!dataStore.online.length) { tbody.innerHTML = \`<tr><td colspan="6" style="text-align: center; padding: 40px; font-weight: 700;">NO STREAMS</td></tr>\`; return; }
    const pMap = {}; dataStore.products.forEach(x => pMap[x.id] = x.name);
    tbody.innerHTML = dataStore.online.map(k => \`<tr>
      <td class="mono copyable" onclick="copy('\${k.key}')">\${k.key}</td>
      <td><span class="badge" style="background: #e5e7eb;">\${pMap[k.product_id]||'UNK'}</span></td>
      <td style="font-weight: 700; text-transform: uppercase;">\${k.type||'BASIC'}</td>
      <td class="mono">\${k.hwid}</td>
      <td style="font-weight: 600;">\${k.user||'-'}</td>
      <td class="mono text-muted">\${new Date(k.last_seen).toLocaleTimeString()}</td>
    </tr>\`).join('');
  }
  function renderLogs() {
    const tbody = document.getElementById('logsTableBody');
    if(!dataStore.logs.length) { tbody.innerHTML = \`<tr><td colspan="4" style="text-align: center; padding: 40px; font-weight: 700;">KHÔNG CÓ NHẬT KÝ</td></tr>\`; return; }
    tbody.innerHTML = dataStore.logs.slice(0, 100).map(l => \`<tr>
      <td class="mono text-muted">\${new Date(l.created_at).toLocaleString()}</td>
      <td style="color: var(--accent); font-weight: 700; text-transform: uppercase;">\${l.action}</td>
      <td class="mono copyable" onclick="copy('\${l.key}')">\${l.key}</td>
      <td style="white-space: normal;">\${l.detail}</td>
    </tr>\`).join('');
  }
  function renderProducts() {
    const tbody = document.getElementById('productsTableBody');
    if(!dataStore.products.length) { tbody.innerHTML = \`<tr><td colspan="5" style="text-align: center; padding: 40px; font-weight: 700;">CHƯA CÓ SẢN PHẨM</td></tr>\`; return; }
    tbody.innerHTML = dataStore.products.map(p => \`<tr>
      <td class="mono text-muted">\${p.id}</td>
      <td style="font-weight: 700; text-transform: uppercase;">\${p.name}</td>
      <td class="mono copyable" onclick="copy('\${p.secret}')">\${p.secret}</td>
      <td class="mono text-muted">\${new Date(p.created_at).toLocaleDateString()}</td>
      <td style="text-align: right;"><button class="btn-icon text-danger" onclick="deleteProduct(\${p.id})"><i data-feather="trash"></i></button></td>
    </tr>\`).join('');
    feather.replace();
  }
  async function createProduct() {

    const n = document.getElementById('pName').value.trim();
    const s = document.getElementById('pSecret').value.trim();
    const p = document.getElementById('pPass').value.trim();
    if(!n||!s||!p) return showToast('MISSING FIELDS', 'error');
    try {
      await req('/products', { method: 'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({name:n, secret:s, password:p}) });
      showToast('PRODUCT REGISTERED'); refreshAll();
      document.getElementById('pName').value=''; document.getElementById('pSecret').value=''; document.getElementById('pPass').value='';
    } catch(e) { showToast(e.message, 'error'); }
  }
  async function deleteProduct(id) {

    const pw = prompt('AUTH REQUIREMENT: Enter master password');
    if(!pw) return;
    try {
      await req('/products/' + id, { method: 'DELETE', headers:{'Content-Type':'application/json'}, body: JSON.stringify({password:pw}) });
      showToast('PRODUCT PURGED'); refreshAll();
    } catch(e) { showToast(e.message, 'error'); }
  }

  // --- Sub Admins (Local) ---
  
  let subAdminsData = [];

  async function renderSubAdmins() {
    const tbody = document.getElementById('subAdminsTableBody');
    if(isSubAdmin) return;
    try {
      const res = await fetch(API + '/subadmins', { headers: { 'Authorization': 'Basic ' + token } });
      const data = await res.json();
      if(!data.success || !data.data || data.data.length === 0) {
        tbody.innerHTML = '<tr><td colspan="4" style="text-align: center; padding: 40px; font-weight: 700;">CHƯA CÓ TÀI KHOẢN CẤP DƯỚI</td></tr>';
        return;
      }
      subAdminsData = data.data;
      const pMap = {}; 
      if (dataStore.products && Array.isArray(dataStore.products)) {
        dataStore.products.forEach(x => { if(x.name) pMap[x.id] = x.name.toUpperCase(); });
      }
      
      tbody.innerHTML = data.data.map((s) => {
        let rawProds = s.allowed_products;
        let prodArr = [];
        if (Array.isArray(rawProds)) prodArr = rawProds;
        else if (typeof rawProds === 'string') {
          try { prodArr = JSON.parse(rawProds); } catch(e) {}
        }
        let prods = prodArr.map(pid => {
          let count = (s.key_counts && s.key_counts[pid]) ? s.key_counts[pid] : 0;
          return \`<span class="badge" style="background: #e5e7eb; color: #000; margin-right: 4px;">\${pMap[pid] || pid} (\${count} keys)</span>\`;
        }).join('');
        if (!prods) prods = '<span class="text-muted mono">NONE</span>';
        
        return '<tr>' +
        '<td style="font-weight: 700;">' + esc(s.username || 'unknown') + '</td>' +
        '<td>' + prods + '</td>' +
        '<td><span class="badge badge-active">SUB ADMIN</span></td>' +
        '<td style="text-align: right;">' +
        '<button class="btn-icon admin-only" onclick="openSubAdminModal(\\'' + esc(s.username || '') + '\\')" style="margin-right: 8px;"><i data-feather="edit"></i></button>' +
        '<button class="btn-icon text-danger admin-only" onclick="delSubAdmin(\\'' + esc(s.username || '') + '\\')"><i data-feather="trash"></i></button>' +
        '</td></tr>';
      }).join('');
      feather.replace();
    } catch(e) { console.error(e); }
  }

  function openSubAdminModal(username = null) {
    if(isSubAdmin) return;
    const mode = username ? 'edit' : 'add';
    document.getElementById('saMode').value = mode;
    document.getElementById('saModalTitle').textContent = mode === 'add' ? 'Thêm Sub-Admin' : 'Sửa Sub-Admin';
    document.getElementById('samUser').value = username || '';
    document.getElementById('samUser').disabled = mode === 'edit';
    document.getElementById('samPass').value = '';
    document.getElementById('samPassHint').textContent = mode === 'edit' ? '(Để trống nếu không muốn đổi)' : '';
    
    let allowed = [];
    if (mode === 'edit') {
      const sa = subAdminsData.find(x => x.username === username);
      if (sa) allowed = (sa.allowed_products || []).map(String);
    }
    
    const prodList = document.getElementById('samProductsList');
    prodList.innerHTML = dataStore.products.map(p => {
      const checked = allowed.includes(String(p.id)) ? 'checked' : '';
      return \`<label style="display: flex; align-items: center; gap: 8px; cursor: pointer;">
        <input type="checkbox" value="\${p.id}" class="sam-prod-cb" \${checked}>
        <span style="font-weight: 600; text-transform: uppercase;">\${p.name}</span>
      </label>\`;
    }).join('');
    
    document.getElementById('subAdminModal').style.display = 'flex';
  }

  async function saveSubAdmin() {
    if(isSubAdmin) return;
    const mode = document.getElementById('saMode').value;
    const u = document.getElementById('samUser').value.trim();
    const p = document.getElementById('samPass').value.trim();
    
    if (mode === 'add' && (!u || !p)) return showToast('Vui lòng nhập đủ tên và mật khẩu', 'warning');
    
    const cbs = document.querySelectorAll('.sam-prod-cb');
    const allowed = Array.from(cbs).filter(cb => cb.checked).map(cb => parseInt(cb.value));
    
    try {
      const url = API + (mode === 'edit' ? '/subadmins/' + encodeURIComponent(u) : '/subadmins');
      const method = mode === 'edit' ? 'PUT' : 'POST';
      const body = { allowed_products: allowed };
      if (mode === 'add') {
        body.username = u;
        body.password = p;
      } else if (p.length >= 4) {
        body.password = p;
      }
      
      const res = await fetch(url, {
        method, headers: { 'Content-Type': 'application/json', 'Authorization': 'Basic ' + token },
        body: JSON.stringify(body)
      });
      const data = await res.json();
      if(data.success) {
        closeModal('subAdminModal');
        renderSubAdmins();
        showToast(data.message, 'success');
      } else {
        showToast(data.message, 'error');
      }
    } catch(e) { showToast('Lỗi máy chủ', 'error'); }
  }

  async function delSubAdmin(username) {
    if(isSubAdmin) return showToast('Không có quyền thao tác', 'error');
    if(!confirm('Xác nhận xóa tài khoản: ' + username + '?')) return;
    try {
      const res = await fetch(API + '/subadmins/' + username, {
        method: 'DELETE', headers: { 'Authorization': 'Basic ' + token }
      });
      const data = await res.json();
      if(data.success) {
        renderSubAdmins();
        showToast(data.message, 'success');
      } else {
        showToast(data.message, 'error');
      }
    } catch(e) {
      showToast('Lỗi máy chủ', 'error');
    }
  }

  // --- Settings ---
  async function loadSettings() {
    if(isSubAdmin) return;
    try {
      const res = await fetch(API + '/admin/config', { headers: { 'Authorization': 'Basic ' + token } });
      const data = await res.json();
      if(data.success && data.data) {
        data.data.forEach(item => {
          if(item.key === 'latest_ios_version') document.getElementById('setIosVersion').value = item.value;
          if(item.key === 'update_url') document.getElementById('setUpdateUrl').value = item.value;
        });
      }
    } catch(e) { console.error('Error loading settings', e); }
  }

  async function saveSettings() {
    if(isSubAdmin) return showToast('Không có quyền thao tác', 'error');
    const iosVer = document.getElementById('setIosVersion').value.trim();
    const updUrl = document.getElementById('setUpdateUrl').value.trim();
    if(!iosVer || !updUrl) return showToast('Vui lòng nhập đầy đủ thông tin', 'warning');
    
    const settings = [
      { key: 'latest_ios_version', value: iosVer },
      { key: 'update_url', value: updUrl }
    ];
    
    try {
      const res = await fetch(API + '/admin/config', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': 'Basic ' + token },
        body: JSON.stringify({ settings })
      });
      const data = await res.json();
      if(data.success) {
        showToast('Đã lưu cấu hình', 'success');
      } else {
        showToast(data.message, 'error');
      }
    } catch(e) {
      showToast('Lỗi máy chủ', 'error');
    }
  }

</script>
</body>
</html>

</html>
`);
});

// ============================================================
//  PATCH MANAGER - Web Admin Panel
// ============================================================
app.get('/admin/patches', (req, res) => {
  res.send(`<!DOCTYPE html>
<html lang="vi">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>NovaX Patch Manager</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:w400;500;700&display=swap" rel="stylesheet">
<script src="https://unpkg.com/feather-icons"></script>
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{--bg:#06080d;--bg2:#0c1017;--bg3:#111827;--bg4:#1a2332;--border:#1e293b;--border2:#334155;--text:#e2e8f0;--text2:#94a3b8;--text3:#64748b;--accent:#3b82f6;--accent2:#60a5fa;--accent-glow:rgba(59,130,246,.15);--green:#10b981;--green-bg:rgba(16,185,129,.1);--red:#ef4444;--red-bg:rgba(239,68,68,.1);--yellow:#f59e0b;--yellow-bg:rgba(245,158,11,.1);--purple:#8b5cf6;--purple-bg:rgba(139,92,246,.1)}
body{font-family:'Inter',sans-serif;background:var(--bg);color:var(--text);min-height:100vh;overflow-x:hidden}
::selection{background:var(--accent);color:#fff}
::-webkit-scrollbar{width:6px}::-webkit-scrollbar-track{background:var(--bg2)}::-webkit-scrollbar-thumb{background:var(--border2);border-radius:3px}

.header{background:linear-gradient(180deg,rgba(15,23,42,.95),rgba(6,8,13,.98));border-bottom:1px solid var(--border);padding:16px 32px;display:flex;align-items:center;justify-content:space-between;position:sticky;top:0;z-index:100;backdrop-filter:blur(20px)}
.header-left{display:flex;align-items:center;gap:16px}
.logo{width:40px;height:40px;border-radius:12px;background:linear-gradient(135deg,var(--accent),var(--purple));display:flex;align-items:center;justify-content:center;box-shadow:0 0 20px rgba(59,130,246,.3)}
.logo i{color:#fff;width:22px;height:22px}
.header h1{font-size:20px;font-weight:800;letter-spacing:-.5px}
.header h1 span{background:linear-gradient(135deg,var(--accent2),var(--purple));-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.header .subtitle{font-size:11px;color:var(--text3);font-weight:500;letter-spacing:.5px;text-transform:uppercase;margin-top:2px}
.nav{display:flex;gap:4px;background:var(--bg2);border:1px solid var(--border);border-radius:12px;padding:4px}
.nav a{color:var(--text3);text-decoration:none;padding:8px 18px;border-radius:8px;font-size:13px;font-weight:600;transition:all .2s;display:flex;align-items:center;gap:6px}
.nav a:hover{color:var(--text);background:var(--bg3)}
.nav a.active{color:#fff;background:var(--accent);box-shadow:0 0 15px rgba(59,130,246,.3)}
.nav a i{width:16px;height:16px}

.container{max-width:1400px;margin:0 auto;padding:24px 32px}

.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-bottom:24px}
.stat{background:var(--bg2);border:1px solid var(--border);border-radius:16px;padding:20px;position:relative;overflow:hidden;transition:all .3s}
.stat:hover{border-color:var(--accent);box-shadow:0 0 30px var(--accent-glow)}
.stat::before{content:'';position:absolute;top:0;left:0;right:0;height:2px;background:linear-gradient(90deg,transparent,var(--accent),transparent);opacity:0;transition:opacity .3s}
.stat:hover::before{opacity:1}
.stat .stat-icon{width:44px;height:44px;border-radius:12px;display:flex;align-items:center;justify-content:center;margin-bottom:12px}
.stat .stat-icon i{width:22px;height:22px}
.stat .stat-icon.blue{background:var(--accent-glow);color:var(--accent)}
.stat .stat-icon.green{background:var(--green-bg);color:var(--green)}
.stat .stat-icon.yellow{background:var(--yellow-bg);color:var(--yellow)}
.stat .stat-icon.purple{background:var(--purple-bg);color:var(--purple)}
.stat .num{font-size:32px;font-weight:800;font-family:'JetBrains Mono',monospace}
.stat .label{font-size:12px;color:var(--text3);font-weight:500;margin-top:4px;text-transform:uppercase;letter-spacing:.5px}

.section{background:var(--bg2);border:1px solid var(--border);border-radius:16px;margin-bottom:20px;overflow:hidden}
.section-header{display:flex;align-items:center;justify-content:space-between;padding:16px 20px;border-bottom:1px solid var(--border)}
.section-title{font-size:15px;font-weight:700;display:flex;align-items:center;gap:10px}
.section-title i{width:20px;height:20px;color:var(--accent)}
.section-body{padding:20px}

table{width:100%;border-collapse:collapse}
th{text-align:left;padding:12px 16px;font-size:11px;font-weight:700;color:var(--text3);text-transform:uppercase;letter-spacing:.5px;border-bottom:1px solid var(--border);background:var(--bg)}
td{padding:12px 16px;border-bottom:1px solid var(--border);font-size:13px}
tr:last-child td{border-bottom:none}
tr:hover td{background:rgba(59,130,246,.03)}

.badge{display:inline-flex;align-items:center;gap:4px;padding:4px 10px;border-radius:6px;font-size:11px;font-weight:700;letter-spacing:.3px}
.badge-green{background:var(--green-bg);color:var(--green);border:1px solid rgba(16,185,129,.2)}
.badge-gray{background:var(--bg3);color:var(--text3);border:1px solid var(--border)}
.badge-blue{background:var(--accent-glow);color:var(--accent2);border:1px solid rgba(59,130,246,.2)}
.badge-yellow{background:var(--yellow-bg);color:var(--yellow);border:1px solid rgba(245,158,11,.2)}
.badge-red{background:var(--red-bg);color:var(--red);border:1px solid rgba(239,68,68,.2)}

.btn{padding:8px 16px;border-radius:8px;border:none;font-size:13px;font-weight:600;cursor:pointer;transition:all .2s;display:inline-flex;align-items:center;gap:6px;font-family:'Inter',sans-serif}
.btn i{width:15px;height:15px}
.btn-primary{background:var(--accent);color:#fff;box-shadow:0 0 15px rgba(59,130,246,.2)}.btn-primary:hover{background:#2563eb;box-shadow:0 0 25px rgba(59,130,246,.3)}
.btn-danger{background:var(--red);color:#fff}.btn-danger:hover{background:#dc2626}
.btn-secondary{background:var(--bg3);color:var(--text2);border:1px solid var(--border)}.btn-secondary:hover{background:var(--bg4);border-color:var(--border2)}
.btn-ghost{background:transparent;color:var(--text3)}.btn-ghost:hover{color:var(--text);background:var(--bg3)}
.btn-sm{padding:6px 12px;font-size:12px}
.btn-lg{padding:12px 24px;font-size:14px}

.form-group{margin-bottom:16px}
.form-group label{display:block;font-size:12px;font-weight:600;color:var(--text2);margin-bottom:6px;text-transform:uppercase;letter-spacing:.3px}
.form-group input,.form-group select,.form-group textarea{width:100%;padding:10px 14px;background:var(--bg);border:1px solid var(--border);border-radius:10px;color:var(--text);font-size:13px;font-family:'Inter',sans-serif;outline:none;transition:all .2s}
.form-group input:focus,.form-group select:focus,.form-group textarea:focus{border-color:var(--accent);box-shadow:0 0 0 3px var(--accent-glow)}
.form-group textarea{resize:vertical;min-height:80px}
.form-row{display:grid;grid-template-columns:1fr 1fr;gap:14px}
.form-hint{font-size:11px;color:var(--text3);margin-top:4px}

.modal-overlay{position:fixed;inset:0;background:rgba(0,0,0,.75);backdrop-filter:blur(8px);z-index:200;display:flex;align-items:center;justify-content:center;opacity:0;pointer-events:none;transition:opacity .25s}
.modal-overlay.show{opacity:1;pointer-events:auto}
.modal{background:var(--bg2);border:1px solid var(--border);border-radius:20px;padding:28px;width:92%;max-width:540px;max-height:85vh;overflow-y:auto;transform:scale(.95);transition:transform .25s}
.modal-overlay.show .modal{transform:scale(1)}
.modal h3{font-size:18px;font-weight:700;margin-bottom:20px;display:flex;align-items:center;gap:10px}
.modal h3 i{width:22px;height:22px;color:var(--accent)}
.modal-actions{display:flex;gap:8px;justify-content:flex-end;margin-top:24px;padding-top:16px;border-top:1px solid var(--border)}

.patch-img{width:48px;height:48px;border-radius:12px;object-fit:cover;background:var(--bg3);border:1px solid var(--border)}
.patch-img-placeholder{width:48px;height:48px;border-radius:12px;background:var(--bg3);border:1px solid var(--border);display:flex;align-items:center;justify-content:center;color:var(--text3)}
.patch-img-placeholder i{width:20px;height:20px}

.toggle{position:relative;width:44px;height:24px;cursor:pointer;display:inline-block}
.toggle input{opacity:0;width:0;height:0;position:absolute}
.toggle .slider{position:absolute;inset:0;background:var(--bg3);border:1px solid var(--border);border-radius:24px;transition:all .3s}
.toggle .slider:before{content:'';position:absolute;width:18px;height:18px;left:2px;bottom:2px;background:var(--text3);border-radius:50%;transition:all .3s}
.toggle input:checked+.slider{background:var(--accent);border-color:var(--accent)}
.toggle input:checked+.slider:before{transform:translateX(20px);background:#fff}

.empty{text-align:center;padding:48px 20px;color:var(--text3)}
.empty i{width:48px;height:48px;margin-bottom:16px;opacity:.3}
.empty p{font-size:14px;margin-top:8px}

.toast{position:fixed;bottom:24px;right:24px;padding:14px 20px;border-radius:12px;font-size:13px;font-weight:600;z-index:300;transform:translateY(100px);opacity:0;transition:all .3s;display:flex;align-items:center;gap:8px;box-shadow:0 8px 30px rgba(0,0,0,.4)}
.toast.show{transform:translateY(0);opacity:1}
.toast i{width:18px;height:18px}
.toast-ok{background:var(--green-bg);color:var(--green);border:1px solid rgba(16,185,129,.3)}
.toast-err{background:var(--red-bg);color:var(--red);border:1px solid rgba(239,68,68,.3)}
.toast i{color:inherit}

.file-input{position:relative;overflow:hidden;display:inline-block}
.file-input input[type=file]{position:absolute;left:0;top:0;opacity:0;width:100%;height:100%;cursor:pointer}

.tab-bar{display:flex;gap:4px;background:var(--bg);border:1px solid var(--border);border-radius:10px;padding:4px;margin-bottom:16px}
.tab-bar .tab{padding:8px 16px;border-radius:8px;font-size:12px;font-weight:600;cursor:pointer;transition:all .2s;color:var(--text3);display:flex;align-items:center;gap:6px;border:none;background:none;font-family:'Inter',sans-serif}
.tab-bar .tab i{width:14px;height:14px}
.tab-bar .tab:hover{color:var(--text);background:var(--bg3)}
.tab-bar .tab.active{color:#fff;background:var(--accent)}

.builder-preview{background:var(--bg);border:1px solid var(--border);border-radius:12px;padding:16px;font-family:'JetBrains Mono',monospace;font-size:12px;color:var(--text2);max-height:200px;overflow-y:auto;white-space:pre-wrap;margin-top:12px}

@keyframes fadeIn{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:translateY(0)}}
.fade-in{animation:fadeIn .3s ease-out}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.5}}
.loading{animation:pulse 1.5s infinite}

@media(max-width:768px){
  .header{padding:12px 16px;flex-direction:column;gap:12px}
  .container{padding:16px}
  .stats{grid-template-columns:repeat(2,1fr)}
  .form-row{grid-template-columns:1fr}
  .nav{width:100%;justify-content:center}
}
.login-overlay{position:fixed;inset:0;background:var(--bg2);display:flex;align-items:center;justify-content:center;z-index:9999}
.login-box{background:var(--bg2);border:1px solid var(--border);padding:40px;width:100%;max-width:400px;border-radius:20px;box-shadow:0 8px 30px rgba(0,0,0,.4)}
.login-box h2{font-size:20px;font-weight:700;text-align:center;margin-bottom:24px;display:flex;align-items:center;justify-content:center;gap:8px}
.login-box h2 i{color:var(--accent)}
</style>
</head>
<body>

<!-- LOGIN -->
<div class="login-overlay" id="loginOverlay">
  <div class="login-box">
    <h2><i data-feather="grid"></i> PATCH MANAGER</h2>
    <div id="loginForm">
      <div class="form-group">
        <label>Tên đăng nhập</label>
        <input type="text" id="loginUser" placeholder="admin" onkeydown="if(event.key==='Enter') login()">
      </div>
      <div class="form-group">
        <label>Mật khẩu</label>
        <input type="password" id="loginPass" placeholder="•" onkeydown="if(event.key==='Enter') login()">
      </div>
      <button class="btn btn-primary" style="width: 100%; margin-top: 8px; justify-content: center; padding: 12px;" onclick="login()">ĐĂNG NHẬP</button>
    </div>
    <div id="loginLoading" style="display: none; text-align: center; color: var(--text3); padding: 20px 0;">
      <i data-feather="loader" class="loading" style="width: 32px; height: 32px; margin-bottom: 12px;"></i>
      <div>Đang đăng nhập tự động...</div>
    </div>
  </div>
</div>

<div class="header">
  <div class="header-left">
    <div class="logo"><i data-feather="cpu"></i></div>
    <div>
      <h1>Nova<span>X</span> Patch Manager</h1>
      <div class="subtitle">Quản lý chức năng & phân phối bản vá</div>
    </div>
  </div>
  <div class="nav">
    <a href="/"><i data-feather="shield"></i> Auth</a>
    <a href="/admin/patches" class="active"><i data-feather="grid"></i> Patches</a>
    <a href="#" onclick="logout(); return false;" style="color:var(--red)"><i data-feather="log-out"></i> Thoát</a>
  </div>
</div>

<div class="container">
  <div class="stats fade-in" id="stats"></div>

  <!-- Categories Section -->
  <div class="section fade-in">
    <div class="section-header">
      <div class="section-title"><i data-feather="layers"></i> Game Categories</div>
      <button class="btn btn-primary btn-sm" onclick="showCategoryModal()"><i data-feather="plus"></i> Thêm Category</button>
    </div>
    <div class="section-body" style="padding:0">
      <table>
        <thead><tr><th>Ảnh</th><th>ID</th><th>Tên</th><th>Icon</th><th>Sort</th><th>Trạng thái</th><th style="text-align:right">Hành động</th></tr></thead>
        <tbody id="catTable"></tbody>
      </table>
    </div>
  </div>

  <!-- Patches Section -->
  <div class="section fade-in">
    <div class="section-header">
      <div class="section-title"><i data-feather="package"></i> Patches</div>
      <div style="display:flex;gap:8px;align-items:center">
        <select id="filterCat" onchange="loadPatches()" style="padding:7px 12px;background:var(--bg);border:1px solid var(--border);border-radius:8px;color:var(--text);font-size:12px;font-family:'Inter',sans-serif;outline:none">
          <option value="">Tất cả categories</option>
        </select>
        <button class="btn btn-primary btn-sm" onclick="showPatchModal()"><i data-feather="plus"></i> Thêm Patch</button>
      </div>
    </div>
    <div class="section-body" style="padding:0">
      <table>
        <thead><tr><th>Ảnh</th><th>Tên</th><th>Category</th><th>File</th><th>Version</th><th>Trạng thái</th><th style="text-align:right">Hành động</th></tr></thead>
        <tbody id="patchTable"></tbody>
      </table>
    </div>
  </div>

  <!-- .3105 Builder Section -->
  <div class="section fade-in">
    <div class="section-header">
      <div class="section-title"><i data-feather="file-plus"></i> .3105 File Builder</div>
    </div>
    <div class="section-body">
      <p style="font-size:13px;color:var(--text3);margin-bottom:16px">Tạo file .3105 trực tiếp trên trình duyệt. File mã hóa AES-256-GCM, compatible với NovaX app.</p>
      <div class="form-row">
        <div class="form-group"><label>Tên Project</label><input id="bldName" placeholder="My Patch v1"></div>
        <div class="form-group"><label>Bundle ID</label><input id="bldBundle" placeholder="com.apple.mobile.MobileHouseArrest" value="com.apple.mobile.MobileHouseArrest"></div>
      </div>
      <div class="form-row">
        <div class="form-group">
          <label>Password protect (tùy chọn)</label>
          <input id="bldPass" type="password" placeholder="Để trống = không mã hóa">
          <div class="form-hint">Nếu để trống, file sẽ dùng public key</div>
        </div>
        <div class="form-group">
          <label>Schema Version</label>
          <select id="bldSchema"><option value="2">v2 (Workspace)</option><option value="1">v1 (Legacy)</option></select>
        </div>
      </div>
      <div class="form-group">
        <label>Replacement Files</label>
        <div class="file-input btn btn-secondary btn-sm"><i data-feather="upload"></i> Chọn files<input type="file" id="bldFiles" multiple></div>
        <span id="bldFilesInfo" style="margin-left:10px;font-size:12px;color:var(--text3)"></span>
        <div class="form-hint">Mỗi file cần 1 relative path (vd: Documents/file.dylib). Click vào ô Path để sửa.</div>
      </div>
      <div id="bldFileList" style="margin-top:10px"></div>
      <div style="margin-top:20px;display:flex;gap:10px;align-items:center">
        <button class="btn btn-primary btn-lg" onclick="buildPackage()" id="bldBtn"><i data-feather="download"></i> Tạo & Tải .3105</button>
        <span id="bldStatus" style="font-size:12px;color:var(--text3)"></span>
      </div>
      <div class="builder-preview" id="bldPreview" style="display:none"></div>
    </div>
  </div>
</div>

<!-- Category Modal -->
<div class="modal-overlay" id="catModal">
  <div class="modal">
    <h3 id="catModalTitle"><i data-feather="layers"></i> Thêm Category</h3>
    <input type="hidden" id="catEditId">
    <div class="form-group"><label>Tên</label><input id="catName" placeholder="Free Fire"></div>
    <div class="form-row">
      <div class="form-group"><label>Icon (SF Symbol)</label><input id="catIcon" placeholder="flame.fill"></div>
      <div class="form-group"><label>Sort Order</label><input id="catSort" type="number" value="0"></div>
    </div>
    <div class="form-group"><label>Ảnh category</label>
      <div class="file-input btn btn-secondary btn-sm"><i data-feather="image"></i> Chọn ảnh<input type="file" id="catImage" accept="image/*"></div>
      <span id="catImageName" style="margin-left:10px;font-size:12px;color:var(--text3)"></span>
    </div>
    <div class="modal-actions">
      <button class="btn btn-secondary" onclick="closeModal('catModal')">Hủy</button>
      <button class="btn btn-primary" onclick="saveCategory()"><i data-feather="check"></i> Lưu</button>
    </div>
  </div>
</div>

<!-- Patch Modal -->
<div class="modal-overlay" id="patchModal">
  <div class="modal">
    <h3 id="patchModalTitle"><i data-feather="package"></i> Thêm Patch</h3>
    <input type="hidden" id="patchEditId">
    <div class="form-row">
      <div class="form-group"><label>Tên</label><input id="patchName" placeholder="Aimbot"></div>
      <div class="form-group"><label>Category</label><select id="patchCat"></select></div>
    </div>
    <div class="form-group"><label>Mô tả</label><input id="patchDesc" placeholder="Mô tả ngắn"></div>
    <div class="form-row">
      <div class="form-group"><label>Sort Order</label><input id="patchSort" type="number" value="0"></div>
      <div class="form-group"><label>Trạng thái</label>
        <select id="patchActive"><option value="true">Active</option><option value="false">Inactive</option></select>
      </div>
    </div>
    <div class="form-group"><label>Ảnh preview</label>
      <div class="file-input btn btn-secondary btn-sm"><i data-feather="image"></i> Chọn ảnh<input type="file" id="patchImage" accept="image/*"></div>
      <span id="imageName" style="margin-left:10px;font-size:12px;color:var(--text3)"></span>
    </div>
    <div class="form-group"><label>File .3105</label>
      <div class="file-input btn btn-secondary btn-sm"><i data-feather="file"></i> Chọn file<input type="file" id="patchFile" accept=".3105"></div>
      <span id="fileName" style="margin-left:10px;font-size:12px;color:var(--text3)"></span>
    </div>
    <div class="modal-actions">
      <button class="btn btn-secondary" onclick="closeModal('patchModal')">Hủy</button>
      <button class="btn btn-primary" onclick="savePatch()"><i data-feather="check"></i> Lưu</button>
    </div>
  </div>
</div>

<div class="toast" id="toast"></div>

<script>
const API = '';
let categories = [];
let bldFileData = [];
let token = '';

async function login() {
  const u = document.getElementById('loginUser').value.trim();
  const p = document.getElementById('loginPass').value.trim();
  if(!u || !p) return toast('Vui lòng nhập tài khoản và mật khẩu', false);
  try {
    token = btoa(unescape(encodeURIComponent(u + ':' + p)));
  } catch(e) {
    return toast('Mật khẩu chứa kí tự không hợp lệ', false);
  }
  try {
    const r = await fetch(API + '/api/admin/ff/categories', { headers: { 'Authorization': 'Basic ' + token } });
    if(r.status === 401) { token = ''; return toast('Tài khoản hoặc mật khẩu không đúng (Chỉ Main Admin)', false); }
    if(!r.ok) return toast('Lỗi máy chủ', false);
    
    document.getElementById('loginOverlay').style.display = 'none';
    toast('Đăng nhập thành công', true);
    
    await loadCategories();
    await loadStats();
    await loadPatches();
    feather.replace();
  } catch(e) {
    toast('Lỗi kết nối', false);
  }
}

function logout() {
  token = '';
  document.getElementById('loginOverlay').style.display = 'flex';
  document.getElementById('loginForm').style.display = 'block';
  document.getElementById('loginLoading').style.display = 'none';
  document.getElementById('loginPass').value = '';
}

async function api(path, opts = {}) {
  const headers = { 'Authorization': 'Basic ' + token, ...opts.headers };
  if (opts.body && !(opts.body instanceof FormData)) {
    headers['Content-Type'] = 'application/json';
    opts.body = JSON.stringify(opts.body);
  }
  const r = await fetch(API + path, { ...opts, headers });
  if (r.status === 401) {
    logout();
    throw new Error('Unauthorized');
  }
  return r.json();
}

function toast(msg, ok = true) {
  const t = document.getElementById('toast');
  const icon = ok ? '<i data-feather="check-circle"></i>' : '<i data-feather="alert-circle"></i>';
  t.innerHTML = icon + ' ' + msg;
  t.className = 'toast show ' + (ok ? 'toast-ok' : 'toast-err');
  feather.replace();
  setTimeout(() => t.className = 'toast', 3500);
}

function closeModal(id) { document.getElementById(id).classList.remove('show'); }
function openModal(id) { document.getElementById(id).classList.add('show'); feather.replace(); }

// ─── Stats ───
async function loadStats() {
  const [catRes, patchRes] = await Promise.all([api('/api/admin/ff/categories'), api('/api/admin/ff/patches')]);
  const cats = catRes.data || [];
  const patches = patchRes.data || [];
  const active = patches.filter(p => p.is_active).length;
  document.getElementById('stats').innerHTML =
    '<div class="stat"><div class="stat-icon blue"><i data-feather="layers"></i></div><div class="num">' + cats.length + '</div><div class="label">Categories</div></div>' +
    '<div class="stat"><div class="stat-icon purple"><i data-feather="package"></i></div><div class="num">' + patches.length + '</div><div class="label">Total Patches</div></div>' +
    '<div class="stat"><div class="stat-icon green"><i data-feather="check-circle"></i></div><div class="num">' + active + '</div><div class="label">Active</div></div>' +
    '<div class="stat"><div class="stat-icon yellow"><i data-feather="pause-circle"></i></div><div class="num">' + (patches.length - active) + '</div><div class="label">Inactive</div></div>';
  feather.replace();
}

// ─── Categories ───
async function loadCategories() {
  const res = await api('/api/admin/ff/categories');
  categories = res.data || [];
  const tbody = document.getElementById('catTable');
  if (!categories.length) {
    tbody.innerHTML = '<tr><td colspan="6" class="empty"><i data-feather="inbox"></i><p>Chưa có category nào</p></td></tr>';
    feather.replace(); return;
  }
  tbody.innerHTML = categories.map(c => {
    const imgHtml = c.image_url ? '<img src="' + c.image_url + '" class="patch-img">' : '<div class="patch-img-placeholder"><i data-feather="layers"></i></div>';
    return '<tr>' +
    '<td>' + imgHtml + '</td>' +
    '<td><span style="color:var(--text3);font-family:JetBrains Mono,monospace">#' + c.id + '</span></td>' +
    '<td><strong>' + esc(c.name) + '</strong></td>' +
    '<td><code style="background:var(--bg3);padding:2px 8px;border-radius:4px;font-size:12px">' + esc(c.icon || '-') + '</code></td>' +
    '<td>' + c.sort_order + '</td>' +
    '<td>' + (c.is_active ? '<span class="badge badge-green"><i data-feather="check" style="width:12px;height:12px"></i> Active</span>' : '<span class="badge badge-gray"><i data-feather="minus" style="width:12px;height:12px"></i> Inactive</span>') + '</td>' +
    '<td style="text-align:right"><button class="btn btn-ghost btn-sm" onclick="editCategory(' + c.id + ')"><i data-feather="edit-2"></i></button> ' +
    '<button class="btn btn-ghost btn-sm" onclick="deleteCategory(' + c.id + ')" style="color:var(--red)"><i data-feather="trash-2"></i></button></td></tr>';
  }).join('');
  const sel = document.getElementById('filterCat');
  const patchSel = document.getElementById('patchCat');
  sel.innerHTML = '<option value="">Tất cả categories</option>' + categories.map(c => '<option value="' + c.id + '">' + c.name + '</option>').join('');
  patchSel.innerHTML = categories.map(c => '<option value="' + c.id + '">' + c.name + '</option>').join('');
  feather.replace();
}

function showCategoryModal(cat) {
  document.getElementById('catModalTitle').innerHTML = '<i data-feather="layers"></i> ' + (cat ? 'Sửa Category' : 'Thêm Category');
  document.getElementById('catEditId').value = cat ? cat.id : '';
  document.getElementById('catName').value = cat ? cat.name : '';
  document.getElementById('catIcon').value = cat ? (cat.icon || '') : '';
  document.getElementById('catSort').value = cat ? cat.sort_order : 0;
  document.getElementById('catImageName').textContent = '';
  document.getElementById('catImage').value = '';
  openModal('catModal');
}

async function editCategory(id) {
  const res = await api('/api/admin/ff/categories');
  const cat = (res.data || []).find(c => c.id === id);
  if (cat) showCategoryModal(cat);
}

async function saveCategory() {
  const id = document.getElementById('catEditId').value;
  const body = {
    name: document.getElementById('catName').value.trim(),
    icon: document.getElementById('catIcon').value.trim(),
    sort_order: parseInt(document.getElementById('catSort').value) || 0
  };
  const imageFile = document.getElementById('catImage').files[0];
  if (!body.name) { toast('Nhập tên category', false); return; }
  if (imageFile) {
    const imgRes = await uploadFile(imageFile, 'image');
    if (imgRes.success) body.image_url = imgRes.url;
    else { toast('Upload ảnh thất bại', false); return; }
  }
  const res = id ? await api('/api/admin/ff/categories/' + id, { method: 'PUT', body }) : await api('/api/admin/ff/categories', { method: 'POST', body });
  if (res.success) { toast(id ? 'Đã cập nhật category' : 'Đã tạo category'); closeModal('catModal'); loadCategories(); loadStats(); }
  else { toast(res.message || 'Lỗi', false); }
}

async function deleteCategory(id) {
  if (!confirm('Xóa category này? Patches trong category cũng sẽ bị xóa.')) return;
  const res = await api('/api/admin/ff/categories/' + id, { method: 'DELETE' });
  if (res.success) { toast('Đã xóa category'); loadCategories(); loadStats(); loadPatches(); }
  else { toast(res.message || 'Lỗi', false); }
}

// ─── Patches ───
async function loadPatches() {
  const catId = document.getElementById('filterCat').value;
  const url = catId ? '/api/admin/ff/patches?category_id=' + catId : '/api/admin/ff/patches';
  const res = await api(url);
  const patches = res.data || [];
  const tbody = document.getElementById('patchTable');
  if (!patches.length) {
    tbody.innerHTML = '<tr><td colspan="7" class="empty"><i data-feather="inbox"></i><p>Chưa có patch nào</p></td></tr>';
    feather.replace(); return;
  }
  tbody.innerHTML = patches.map(p => {
    const cat = categories.find(c => c.id === p.category_id);
    const imgHtml = p.image_url ? '<img src="' + p.image_url + '" class="patch-img">' : '<div class="patch-img-placeholder"><i data-feather="image"></i></div>';
    const fileSize = p.file_size ? (p.file_size > 1048576 ? (p.file_size/1048576).toFixed(1)+' MB' : Math.round(p.file_size/1024)+' KB') : '';
    return '<tr>' +
      '<td>' + imgHtml + '</td>' +
      '<td><strong>' + esc(p.name) + '</strong><br><span style="font-size:11px;color:var(--text3);font-family:JetBrains Mono,monospace">' + esc(p.slug || '') + '</span></td>' +
      '<td>' + (cat ? '<span class="badge badge-blue">' + esc(cat.name) + '</span>' : '<span class="badge badge-gray">#' + p.category_id + '</span>') + '</td>' +
      '<td>' + (p.file_url ? '<span class="badge badge-green"><i data-feather="file" style="width:11px;height:11px"></i> ' + fileSize + '</span>' : '<span class="badge badge-gray">Chưa upload</span>') + '</td>' +
      '<td><span style="font-family:JetBrains Mono,monospace;font-weight:700">v' + (p.version || 1) + '</span></td>' +
      '<td><label class="toggle"><input type="checkbox" ' + (p.is_active ? 'checked' : '') + ' onchange="togglePatch(' + p.id + ',this.checked)"><span class="slider"></span></label></td>' +
      '<td style="text-align:right"><button class="btn btn-ghost btn-sm" onclick="editPatch(' + p.id + ')"><i data-feather="edit-2"></i></button> ' +
      '<button class="btn btn-ghost btn-sm" onclick="deletePatch(' + p.id + ')" style="color:var(--red)"><i data-feather="trash-2"></i></button></td></tr>';
  }).join('');
  feather.replace();
}

function showPatchModal(patch) {
  document.getElementById('patchModalTitle').innerHTML = '<i data-feather="package"></i> ' + (patch ? 'Sửa Patch' : 'Thêm Patch');
  document.getElementById('patchEditId').value = patch ? patch.id : '';
  document.getElementById('patchName').value = patch ? patch.name : '';
  document.getElementById('patchCat').value = patch ? patch.category_id : (categories[0]?.id || '');
  document.getElementById('patchDesc').value = patch ? (patch.description || '') : '';
  document.getElementById('patchSort').value = patch ? patch.sort_order : 0;
  document.getElementById('patchActive').value = patch ? String(patch.is_active) : 'true';
  document.getElementById('imageName').textContent = '';
  document.getElementById('fileName').textContent = '';
  document.getElementById('patchImage').value = '';
  document.getElementById('patchFile').value = '';
  openModal('patchModal');
}

async function editPatch(id) {
  const res = await api('/api/admin/ff/patches');
  const patch = (res.data || []).find(p => p.id === id);
  if (patch) showPatchModal(patch);
}

async function uploadFile(file, bucket) {
  const formData = new FormData();
  formData.append('file', file);
  const r = await fetch(API + '/api/admin/upload/' + bucket, {
    method: 'POST',
    headers: { 'Authorization': 'Basic ' + token },
    body: formData
  });
  if (r.status === 401) { logout(); throw new Error('Unauthorized'); }
  return r.json();
}

async function savePatch() {
  const id = document.getElementById('patchEditId').value;
  const name = document.getElementById('patchName').value.trim();
  const category_id = parseInt(document.getElementById('patchCat').value);
  const description = document.getElementById('patchDesc').value.trim();
  const sort_order = parseInt(document.getElementById('patchSort').value) || 0;
  const is_active = document.getElementById('patchActive').value === 'true';
  const imageFile = document.getElementById('patchImage').files[0];
  const patchFile = document.getElementById('patchFile').files[0];
  if (!name) { toast('Nhập tên patch', false); return; }
  if (!category_id) { toast('Chọn category', false); return; }
  const body = { name, category_id, description, sort_order, is_active };
  if (imageFile) {
    const imgRes = await uploadFile(imageFile, 'image');
    if (imgRes.success) body.image_url = imgRes.url;
    else { toast('Upload ảnh thất bại', false); return; }
  }
  if (patchFile) {
    const fileRes = await uploadFile(patchFile, 'file');
    if (fileRes.success) { body.file_url = fileRes.url; body.file_hash = fileRes.hash; body.file_size = fileRes.size; }
    else { toast('Upload file thất bại', false); return; }
  }
  const res = id ? await api('/api/admin/ff/patches/' + id, { method: 'PUT', body }) : await api('/api/admin/ff/patches', { method: 'POST', body });
  if (res.success) { toast(id ? 'Đã cập nhật patch' : 'Đã tạo patch'); closeModal('patchModal'); loadPatches(); loadStats(); }
  else { toast(res.message || 'Lỗi', false); }
}

async function togglePatch(id, active) {
  await api('/api/admin/ff/patches/' + id, { method: 'PUT', body: { is_active: active } });
  loadStats();
}

async function deletePatch(id) {
  if (!confirm('Xóa patch này?')) return;
  const res = await api('/api/admin/ff/patches/' + id, { method: 'DELETE' });
  if (res.success) { toast('Đã xóa patch'); loadPatches(); loadStats(); }
  else { toast(res.message || 'Lỗi', false); }
}

// ─── .3105 Builder ───
document.getElementById('bldFiles').addEventListener('change', function() {
  bldFileData = [];
  const info = document.getElementById('bldFilesInfo');
  const list = document.getElementById('bldFileList');
  if (!this.files.length) { info.textContent = ''; list.innerHTML = ''; return; }
  const promises = Array.from(this.files).map(f => new Promise(resolve => {
    const reader = new FileReader();
    reader.onload = () => {
      bldFileData.push({ name: f.name, size: f.size, data: new Uint8Array(reader.result), relativePath: f.name });
      resolve();
    };
    reader.readAsArrayBuffer(f);
  }));
  Promise.all(promises).then(() => {
    info.textContent = bldFileData.length + ' file(s), ' + formatSize(bldFileData.reduce((a,b) => a + b.size, 0));
    list.innerHTML = bldFileData.map((f,i) =>
      '<div style="display:flex;align-items:center;gap:8px;padding:8px 12px;background:var(--bg);border:1px solid var(--border);border-radius:8px;margin-bottom:6px">' +
      '<i data-feather="file" style="width:14px;height:14px;color:var(--accent);flex-shrink:0"></i>' +
      '<div style="flex:1;min-width:0">' +
        '<div style="font-size:12px;font-family:JetBrains Mono,monospace;color:var(--text);white-space:nowrap;overflow:hidden;text-overflow:ellipsis">' + esc(f.name) + '</div>' +
        '<div style="display:flex;align-items:center;gap:6px;margin-top:4px">' +
          '<span style="font-size:11px;color:var(--text3);flex-shrink:0">Path:</span>' +
          '<input type="text" value="' + esc(f.relativePath) + '" onchange="updateBldPath(' + i + ', this.value)" ' +
            'style="flex:1;padding:3px 8px;background:var(--bg2);border:1px solid var(--border);border-radius:4px;color:var(--text);font-size:11px;font-family:JetBrains Mono,monospace;outline:none">' +
          '<span style="font-size:11px;color:var(--text3)">' + formatSize(f.size) + '</span>' +
        '</div>' +
      '</div>' +
      '<button class="btn btn-ghost btn-sm" onclick="removeBldFile(' + i + ')" style="color:var(--red);padding:2px;flex-shrink:0"><i data-feather="x" style="width:14px;height:14px"></i></button>' +
      '</div>'
    ).join('');
    feather.replace();
  });
});

function updateBldPath(idx, val) { if (bldFileData[idx]) bldFileData[idx].relativePath = val; }

function removeBldFile(idx) {
  bldFileData.splice(idx, 1);
  document.getElementById('bldFiles').dispatchEvent(new Event('change'));
}

function formatSize(bytes) {
  if (bytes > 1048576) return (bytes/1048576).toFixed(1) + ' MB';
  if (bytes > 1024) return Math.round(bytes/1024) + ' KB';
  return bytes + ' B';
}

function esc(s) { const d = document.createElement('div'); d.textContent = s; return d.innerHTML; }

// ─── Binary Plist Encoder ───
const PLIST = {
  MAGIC: 'bplist00',

  encode(rootObj) {
    const objects = [];
    const objIndex = new Map();

    function collect(obj) {
      if (obj === null || obj === undefined) {
        const key = 'null';
        if (!objIndex.has(key)) { objIndex.set(key, objects.length); objects.push(null); }
        return objIndex.get(key);
      }
      if (typeof obj === 'boolean') {
        const key = 'b:' + obj;
        if (!objIndex.has(key)) { objIndex.set(key, objects.length); objects.push(obj); }
        return objIndex.get(key);
      }
      if (typeof obj === 'number') {
        const key = 'n:' + obj;
        if (!objIndex.has(key)) { objIndex.set(key, objects.length); objects.push(obj); }
        return objIndex.get(key);
      }
      if (typeof obj === 'string') {
        const key = 's:' + obj;
        if (!objIndex.has(key)) { objIndex.set(key, objects.length); objects.push(obj); }
        return objIndex.get(key);
      }
      if (obj instanceof Uint8Array || obj instanceof ArrayBuffer) {
        const u8 = obj instanceof ArrayBuffer ? new Uint8Array(obj) : obj;
        const idx = objects.length;
        objects.push(u8);
        return idx;
      }
      if (Array.isArray(obj)) {
        const idx = objects.length;
        const itemRefs = obj.map(item => collect(item));
        objects.push({ _type: 'array', _refs: itemRefs });
        return idx;
      }
      if (typeof obj === 'object') {
        const idx = objects.length;
        const keys = Object.keys(obj).sort();
        const kRefs = keys.map(k => collect(k));
        const vRefs = keys.map(k => collect(obj[k]));
        objects.push({ _type: 'dict', _keys: kRefs, _vals: vRefs });
        return idx;
      }
      return 0;
    }

    collect(rootObj);
    const numObjects = objects.length;

    let refSize = 1;
    if (numObjects > 255) refSize = 2;
    if (numObjects > 65535) refSize = 4;

    const encoded = [];
    const offsets = [];
    let cursor = 0;
    for (let i = 0; i < numObjects; i++) {
      const bytes = this._encodeObj(objects[i], refSize);
      offsets.push(cursor);
      cursor += bytes.length;
      encoded.push(bytes);
    }

    const parts = [];
    const header = new Uint8Array(8 + 5 * 4);
    let hp = 0;
    for (let c of 'bplist00') header[hp++] = c.charCodeAt(0);
    header[hp++] = 0; header[hp++] = 0; header[hp++] = 0; header[hp++] = 0x08;
    header[hp++] = 0; header[hp++] = 0; header[hp++] = 0; header[hp++] = 0;
    header[hp++] = (numObjects >>> 24) & 0xff; header[hp++] = (numObjects >>> 16) & 0xff;
    header[hp++] = (numObjects >>> 8) & 0xff; header[hp++] = numObjects & 0xff;
    const otoOffset = 8 + 20 + cursor;
    header[hp++] = 0; header[hp++] = 0; header[hp++] = 0; header[hp++] = 0;
    header[hp++] = (otoOffset >>> 24) & 0xff; header[hp++] = (otoOffset >>> 16) & 0xff;
    header[hp++] = (otoOffset >>> 8) & 0xff; header[hp++] = otoOffset & 0xff;
    header[hp++] = 0; header[hp++] = 0; header[hp++] = 0; header[hp++] = refSize;
    header[hp++] = (numObjects >>> 24) & 0xff; header[hp++] = (numObjects >>> 16) & 0xff;
    header[hp++] = (numObjects >>> 8) & 0xff; header[hp++] = numObjects & 0xff;
    header[hp++] = 0; header[hp++] = 0; header[hp++] = 0; header[hp++] = 0x08;
    parts.push(header);
    for (const b of encoded) parts.push(b);
    for (const off of offsets) {
      const part = new Uint8Array(8);
      const h = Math.floor(off / 0x100000000);
      const l = off & 0xFFFFFFFF;
      part[0]=(h>>>24)&0xff; part[1]=(h>>>16)&0xff; part[2]=(h>>>8)&0xff; part[3]=h&0xff;
      part[4]=(l>>>24)&0xff; part[5]=(l>>>16)&0xff; part[6]=(l>>>8)&0xff; part[7]=l&0xff;
      parts.push(part);
    }
    let totalLen = 0;
    for (const p of parts) totalLen += p.length;
    const result = new Uint8Array(totalLen);
    let rp = 0;
    for (const p of parts) { result.set(p, rp); rp += p.length; }
    return result;
  },

  _encodeObj(obj, refSize) {
    if (obj === null) return new Uint8Array([0x00]);
    if (typeof obj === 'boolean') return new Uint8Array([obj ? 0x09 : 0x08]);
    if (typeof obj === 'number') {
      if (Number.isInteger(obj)) {
        if (obj < 0) {
          const abs = Math.abs(obj);
          if (abs < 0x80) return new Uint8Array([0x11, 0x00, abs]);
          if (abs < 0x8000) return new Uint8Array([0x12, 0x00, (abs>>8)&0xff, abs&0xff]);
          return new Uint8Array([0x13, 0x00, (abs>>24)&0xff, (abs>>16)&0xff, (abs>>8)&0xff, abs&0xff]);
        }
        if (obj < 0x100) return new Uint8Array([0x10, 0x00, obj]);
        if (obj < 0x10000) return new Uint8Array([0x10, 0x01, (obj>>8)&0xff, obj&0xff]);
        if (obj < 0x100000000) return new Uint8Array([0x10, 0x02, (obj>>24)&0xff, (obj>>16)&0xff, (obj>>8)&0xff, obj&0xff]);
        const hi = Math.floor(obj / 0x100000000); const lo = obj & 0xFFFFFFFF;
        return new Uint8Array([0x10, 0x03, (hi>>>24)&0xff, (hi>>>16)&0xff, (hi>>>8)&0xff, hi&0xff, (lo>>>24)&0xff, (lo>>>16)&0xff, (lo>>>8)&0xff, lo&0xff]);
      }
      const buf = new ArrayBuffer(8);
      new DataView(buf).setFloat64(0, obj, false);
      return new Uint8Array([0x23, ...new Uint8Array(buf)]);
    }
    if (typeof obj === 'string') {
      const s = new TextEncoder().encode(obj);
      if (s.length < 15) return new Uint8Array([0x50 | s.length, ...s]);
      const lenBytes = s.length < 0x100 ? [0x10, 0x00, s.length] :
                       s.length < 0x10000 ? [0x10, 0x01, (s.length>>8)&0xff, s.length&0xff] :
                       [0x10, 0x02, (s.length>>24)&0xff, (s.length>>16)&0xff, (s.length>>8)&0xff, s.length&0xff];
      return new Uint8Array([0x5f, ...lenBytes, ...s]);
    }
    if (obj instanceof Uint8Array) {
      if (obj.length < 15) return new Uint8Array([0x40 | obj.length, ...obj]);
      const lenBytes = obj.length < 0x100 ? [0x10, 0x00, obj.length] :
                       obj.length < 0x10000 ? [0x10, 0x01, (obj.length>>8)&0xff, obj.length&0xff] :
                       [0x10, 0x02, (obj.length>>24)&0xff, (obj.length>>16)&0xff, (obj.length>>8)&0xff, obj.length&0xff];
      return new Uint8Array([0x4f, ...lenBytes, ...obj]);
    }
    if (obj && obj._type === 'array') {
      const refs = obj._refs;
      const refBytes = this._encodeRefs(refs, refSize);
      if (refs.length < 15) return new Uint8Array([0xA0 | refs.length, ...refBytes]);
      const lenBytes = refs.length < 0x100 ? [0x10, 0x00, refs.length] :
                       refs.length < 0x10000 ? [0x10, 0x01, (refs.length>>8)&0xff, refs.length&0xff] :
                       [0x10, 0x02, (refs.length>>24)&0xff, (refs.length>>16)&0xff, (refs.length>>8)&0xff, refs.length&0xff];
      return new Uint8Array([0xAF, ...lenBytes, ...refBytes]);
    }
    if (obj && obj._type === 'dict') {
      const count = obj._keys.length;
      const kBytes = this._encodeRefs(obj._keys, refSize);
      const vBytes = this._encodeRefs(obj._vals, refSize);
      if (count < 15) return new Uint8Array([0xD0 | count, ...kBytes, ...vBytes]);
      const lenBytes = count < 0x100 ? [0x10, 0x00, count] :
                       count < 0x10000 ? [0x10, 0x01, (count>>8)&0xff, count&0xff] :
                       [0x10, 0x02, (count>>24)&0xff, (count>>16)&0xff, (count>>8)&0xff, count&0xff];
      return new Uint8Array([0xDF, ...lenBytes, ...kBytes, ...vBytes]);
    }
    return new Uint8Array([0x00]);
  },

  _encodeRefs(refs, refSize) {
    const buf = new Uint8Array(refs.length * refSize);
    for (let i = 0; i < refs.length; i++) {
      const v = refs[i];
      for (let j = refSize - 1; j >= 0; j--) {
        buf[i * refSize + j] = (v >> (j * 8)) & 0xff;
      }
    }
    return buf;
  }
};

// ─── .3105 Crypto Helpers ───
function bytesToHex(b) { return Array.from(b).map(x => x.toString(16).padStart(2,'0')).join(''); }

// Swift Codable Date: seconds since 2001-01-01 00:00:00 UTC
const APPLE_EPOCH_OFFSET = 978307200;
function swiftDateNow() { return Date.now() / 1000 - APPLE_EPOCH_OFFSET; }

async function sha256(data) {
  const hash = await crypto.subtle.digest('SHA-256', data);
  return new Uint8Array(hash);
}

async function pbkdf2Derive(password, salt, iterations) {
  const keyMaterial = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['wrapKey', 'unwrapKey']
  );
}

async function aesGcmEncrypt(key, data, aad) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad, tagLength: 128 }, key, data);
  return { iv, ciphertext: new Uint8Array(encrypted) };
}

async function buildPackage() {
  const name = document.getElementById('bldName').value.trim();
  const bundleId = document.getElementById('bldBundle').value.trim();
  const password = document.getElementById('bldPass').value;
  const schemaVersion = parseInt(document.getElementById('bldSchema').value);
  const btn = document.getElementById('bldBtn');
  const status = document.getElementById('bldStatus');
  const preview = document.getElementById('bldPreview');

  if (!name) { toast('Nhập tên project', false); return; }
  if (!bundleId) { toast('Nhập Bundle ID', false); return; }
  if (!bldFileData.length) { toast('Chọn ít nhất 1 file', false); return; }

  btn.disabled = true; btn.innerHTML = '<i data-feather="loader"></i> Đang tạo...'; feather.replace();
  status.textContent = 'Đang mã hóa...';
  preview.style.display = 'none';

  try {
    const packageID = crypto.randomUUID();
    const now = swiftDateNow();
    const rules = bldFileData.map((f) => ({
      id: crypto.randomUUID(),
      bundleID: bundleId,
      relativePath: f.relativePath || f.name,
      replacementFilename: f.name,
      replacementData: Array.from(f.data)
    }));

    const project = {
      id: packageID,
      name: name,
      createdAt: now,
      updatedAt: now,
      bundleIdentifiers: [bundleId],
      directories: [],
      rules: rules
    };

    const digests = {};
    for (const r of rules) {
      const digest = await sha256(r.replacementData);
      digests[r.id] = Array.from(digest);
    }
    const payloadObj = { project: project, replacementDigests: digests };

    const payloadPlist = PLIST.encode(payloadObj);
    const contentKeyRaw = crypto.getRandomValues(new Uint8Array(32));
    const keyFingerprint = await sha256(contentKeyRaw);
    let contentKey;

    const isPasswordProtected = password.length > 0;
    let kdfSalt, kdfIterations, wrappedContentKey, publicContentKey;

    if (isPasswordProtected) {
      kdfSalt = crypto.getRandomValues(new Uint8Array(16));
      kdfIterations = 250000;
      const wrappingKey = await pbkdf2Derive(password, kdfSalt, kdfIterations);
      const wrapResult = await crypto.subtle.wrapKey('raw', wrappingKey, { name: 'AES-KW' }, contentKeyRaw);
      wrappedContentKey = new Uint8Array(wrapResult);
      contentKey = await crypto.subtle.importKey('raw', contentKeyRaw, { name: 'AES-GCM', length: 256 }, false, ['encrypt']);
    } else {
      publicContentKey = contentKeyRaw;
      contentKey = await crypto.subtle.importKey('raw', contentKeyRaw, { name: 'AES-GCM', length: 256 }, false, ['encrypt']);
    }

    status.textContent = 'Đang mã hóa payload...';
    const payloadAad = new TextEncoder().encode('3105PATCH/v' + schemaVersion + '/payload/' + packageID);
    const { iv: payloadIv, ciphertext: payloadCipher } = await aesGcmEncrypt(contentKey, payloadPlist, payloadAad);
    // AES-GCM combined = iv(12) + ciphertext + tag(16)
    const encryptedPayload = new Uint8Array(payloadIv.length + payloadCipher.length);
    encryptedPayload.set(payloadIv, 0);
    encryptedPayload.set(payloadCipher, payloadIv.length);

    const envelope = {
      schemaVersion: schemaVersion,
      keyADVersion: isPasswordProtected ? schemaVersion : null,
      packageID: packageID,
      isPasswordProtected: isPasswordProtected,
      kdfSalt: kdfSalt || null,
      kdfIterations: kdfIterations || null,
      wrappedContentKey: wrappedContentKey || null,
      publicContentKey: publicContentKey || null,
      keyFingerprint: keyFingerprint,
      encryptedPayload: encryptedPayload
    };

    status.textContent = 'Đang đóng gói...';
    const envelopePlist = PLIST.encode(envelope);
    const magic = new Uint8Array([0x33, 0x31, 0x30, 0x35, 0x50, 0x41, 0x54, 0x43, 0x48, 0x00]);
    const fileData = new Uint8Array(magic.length + envelopePlist.length);
    fileData.set(magic, 0);
    fileData.set(envelopePlist, magic.length);

    const blob = new Blob([fileData], { type: 'application/octet-stream' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = name.replace(/[^a-zA-Z0-9_-]/g, '_') + '.3105';
    document.body.appendChild(a); a.click(); document.body.removeChild(a);
    URL.revokeObjectURL(url);

    const hash = bytesToHex(await sha256(fileData));
    preview.style.display = 'block';
    preview.textContent =
      'OK File created: ' + a.download + '\\n' +
      '  Size: ' + formatSize(fileData.length) + '\\n' +
      '  PackageID: ' + packageID + '\\n' +
      '  Schema: v' + schemaVersion + '\\n' +
      '  Password: ' + (isPasswordProtected ? 'Yes (' + kdfIterations + ' iterations)' : 'No (public key)') + '\\n' +
      '  Rules: ' + rules.length + '\\n' +
      '  SHA-256: ' + hash.substring(0, 32) + '...';

    toast('Da tao file .3105 thanh cong!');
    feather.replace();
  } catch (e) {
    toast('Loi: ' + e.message, false);
    preview.style.display = 'block';
    preview.textContent = 'ERROR: ' + e.message;
  } finally {
    btn.disabled = false; btn.innerHTML = '<i data-feather="download"></i> Tao & Tai .3105'; feather.replace();
    status.textContent = '';
  }
}

// ─── Init ───
document.getElementById('patchImage').onchange = function() { document.getElementById('imageName').textContent = this.files[0]?.name || ''; };
document.getElementById('patchFile').onchange = function() { document.getElementById('fileName').textContent = this.files[0]?.name || ''; };
document.getElementById('catImage').onchange = function() { document.getElementById('catImageName').textContent = this.files[0]?.name || ''; };

(async () => { 
  feather.replace(); 
  logout();
})();
</script>
</body>
</html>`);
});

// ============================================================
//  PATCH DISTRIBUTION API (NovaX Features Tab)
// ============================================================

// ---- PUBLIC: App calls ----

// GET /api/ff/categories — list active categories
app.get('/api/ff/categories', async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('game_categories')
      .select('id, name, icon, image_url, sort_order')
      .eq('is_active', true)
      .order('sort_order', { ascending: true });
    if (error) throw error;
    res.json({ success: true, data });
  } catch (err) {
    res.json({ success: false, message: 'Failed to load categories' });
  }
});

// GET /api/ff/patches?cat=X — list patches for a category
app.get('/api/ff/patches', async (req, res) => {
  try {
    const { cat } = req.query;
    let query = supabase
      .from('patches')
      .select('id, category_id, name, slug, description, image_url, file_url, file_hash, file_size, version')
      .eq('is_active', true)
      .order('sort_order', { ascending: true });
    if (cat) query = query.eq('category_id', parseInt(cat));
    const { data, error } = await query;
    if (error) throw error;
    res.json({ success: true, data });
  } catch (err) {
    res.json({ success: false, message: 'Failed to load patches' });
  }
});

// GET /api/ff/sync — full metadata for sync check
app.get('/api/ff/sync', apiLimiter, async (req, res) => {
  try {
    const authKey = req.headers['x-auth-key'];
    if (!authKey) {
      return res.status(401).json({ success: false, message: 'Missing auth key' });
    }

    const { data: keyData, error: keyErr } = await supabase
      .from('keys')
      .select('status, expires_at')
      .eq('key', authKey)
      .maybeSingle();

    if (keyErr || !keyData) {
      return res.status(401).json({ success: false, message: 'Invalid key' });
    }
    
    if (keyData.status !== 'active') {
      return res.status(403).json({ success: false, message: 'Key is not active' });
    }

    if (keyData.expires_at && new Date(keyData.expires_at) < new Date()) {
      return res.status(403).json({ success: false, message: 'Key expired' });
    }

    const { data: categories, error: catErr } = await supabase
      .from('game_categories')
      .select('id, name, icon, image_url, sort_order')
      .eq('is_active', true)
      .order('sort_order');
    if (catErr) throw catErr;

    const { data: patches, error: patErr } = await supabase
      .from('patches')
      .select('id, category_id, name, slug, description, image_url, file_url, file_hash, file_size, version')
      .eq('is_active', true)
      .order('sort_order');
    if (patErr) throw patErr;

    const finalCategories = categories || [];
    const finalPatches = patches || [];

    const scheme = req.headers['x-forwarded-proto'] || req.protocol;
    const proxyPatches = finalPatches.map(p => ({
      ...p,
      file_url: p.file_url ? `${scheme}://${req.get('host')}/api/ff/download/${p.slug}` : ''
    }));

    const messageToHash = `true|${finalCategories.length}|${proxyPatches.length}`;
    const hmac = require('crypto').createHmac('sha256', authKey).update(messageToHash).digest('base64');

    res.json({ success: true, hmac, categories: finalCategories, patches: proxyPatches });
  } catch (err) {
    res.json({ success: false, message: 'Sync failed' });
  }
});

// GET /api/ff/download/:slug — proxy download endpoint
app.get('/api/ff/download/:slug', apiLimiter, async (req, res) => {
  try {
    const authKey = req.headers['x-auth-key'];
    if (!authKey) {
      return res.status(401).json({ success: false, message: 'Missing auth key' });
    }

    const { data: keyData, error: keyErr } = await supabase
      .from('keys')
      .select('status, expires_at')
      .eq('key', authKey)
      .maybeSingle();

    if (keyErr || !keyData) {
      return res.status(401).json({ success: false, message: 'Invalid key' });
    }
    
    if (keyData.status !== 'active') {
      return res.status(403).json({ success: false, message: 'Key is not active' });
    }

    if (keyData.expires_at && new Date(keyData.expires_at) < new Date()) {
      return res.status(403).json({ success: false, message: 'Key expired' });
    }

    const { slug } = req.params;
    const { data: patch, error: patchErr } = await supabase
      .from('patches')
      .select('file_url')
      .eq('slug', slug)
      .eq('is_active', true)
      .maybeSingle();

    if (patchErr || !patch || !patch.file_url) {
      return res.status(404).json({ success: false, message: 'Patch not found' });
    }

    const fileResp = await fetch(patch.file_url);
    if (!fileResp.ok) {
      return res.status(500).json({ success: false, message: 'Failed to fetch source file' });
    }

    res.set('Content-Type', 'application/octet-stream');
    res.set('Content-Disposition', `attachment; filename="${slug}.3105"`);

    const { Readable } = require('stream');
    if (fileResp.body && fileResp.body.getReader) {
      Readable.fromWeb(fileResp.body).pipe(res);
    } else {
      const buffer = await fileResp.arrayBuffer();
      res.send(Buffer.from(buffer));
    }
  } catch (err) {
    res.status(500).json({ success: false, message: 'Download proxy failed' });
  }
});

// ---- ADMIN: Web admin calls (require Basic Auth) ----
function requirePatchAdmin(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Basic ')) {
    return res.status(401).json({ success: false, message: 'Unauthorized' });
  }
  const decoded = Buffer.from(authHeader.split(' ')[1], 'base64').toString();
  const [user, pass] = decoded.split(':');
  if (user !== ADMIN_USER || pass !== ADMIN_PASS) {
    return res.status(401).json({ success: false, message: 'Invalid credentials' });
  }
  next();
}

// GET /api/admin/ff/categories
app.get('/api/admin/ff/categories', requirePatchAdmin, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('game_categories')
      .select('*')
      .order('sort_order');
    if (error) throw error;
    res.json({ success: true, data });
  } catch (err) {
    res.json({ success: false, message: err.message });
  }
});

// POST /api/admin/ff/categories
app.post('/api/admin/ff/categories', requirePatchAdmin, async (req, res) => {
  try {
    const { name, icon = '', image_url = '', sort_order = 0, is_active = true } = req.body;
    if (!name) return res.json({ success: false, message: 'Name required' });
    const { data, error } = await supabase
      .from('game_categories')
      .insert({ name, icon, image_url, sort_order, is_active })
      .select()
      .single();
    if (error) throw error;
    res.json({ success: true, data });
  } catch (err) {
    res.json({ success: false, message: err.message });
  }
});

// PUT /api/admin/ff/categories/:id
app.put('/api/admin/ff/categories/:id', requirePatchAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const updates = req.body;
    const { data, error } = await supabase
      .from('game_categories')
      .update(updates)
      .eq('id', parseInt(id))
      .select()
      .single();
    if (error) throw error;
    res.json({ success: true, data });
  } catch (err) {
    res.json({ success: false, message: err.message });
  }
});

// DELETE /api/admin/ff/categories/:id
app.delete('/api/admin/ff/categories/:id', requirePatchAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { error } = await supabase
      .from('game_categories')
      .delete()
      .eq('id', parseInt(id));
    if (error) throw error;
    res.json({ success: true });
  } catch (err) {
    res.json({ success: false, message: err.message });
  }
});

// GET /api/admin/ff/patches
app.get('/api/admin/ff/patches', requirePatchAdmin, async (req, res) => {
  try {
    const { category_id } = req.query;
    let query = supabase.from('patches').select('*').order('sort_order');
    if (category_id) query = query.eq('category_id', parseInt(category_id));
    const { data, error } = await query;
    if (error) throw error;
    res.json({ success: true, data });
  } catch (err) {
    res.json({ success: false, message: err.message });
  }
});

// POST /api/admin/ff/patches
app.post('/api/admin/ff/patches', requirePatchAdmin, async (req, res) => {
  try {
    const { category_id, name, description = '', image_url = '', file_url = '', file_hash = '', file_size = 0, sort_order = 0, is_active = true } = req.body;
    if (!category_id || !name) return res.json({ success: false, message: 'category_id and name required' });
    const slug = name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
    const { data, error } = await supabase
      .from('patches')
      .insert({ category_id, name, slug, description, image_url, file_url, file_hash, file_size, sort_order, is_active, version: 1 })
      .select()
      .single();
    if (error) throw error;
    res.json({ success: true, data });
  } catch (err) {
    res.json({ success: false, message: err.message });
  }
});

// PUT /api/admin/ff/patches/:id
app.put('/api/admin/ff/patches/:id', requirePatchAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const updates = { ...req.body, updated_at: new Date().toISOString() };
    if (updates.name && !updates.slug) {
      updates.slug = updates.name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
    }
    if (updates.file_url || updates.file_hash) {
      updates.version = (updates.version || 0) + 1;
    }
    const { data, error } = await supabase
      .from('patches')
      .update(updates)
      .eq('id', parseInt(id))
      .select()
      .single();
    if (error) throw error;
    res.json({ success: true, data });
  } catch (err) {
    res.json({ success: false, message: err.message });
  }
});

// DELETE /api/admin/ff/patches/:id
app.delete('/api/admin/ff/patches/:id', requirePatchAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { error } = await supabase
      .from('patches')
      .delete()
      .eq('id', parseInt(id));
    if (error) throw error;
    res.json({ success: true });
  } catch (err) {
    res.json({ success: false, message: err.message });
  }
});

// ---- Upload endpoints (Supabase Storage) ----
const multer = require('multer');
const crypto = require('crypto');
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 15 * 1024 * 1024 } });

app.post('/api/admin/upload/image', requireAdmin, upload.single('file'), async (req, res) => {
  if (req.adminRole !== 'master') return res.status(403).json({ success: false, message: 'Forbidden' });
  try {
    if (!req.file) return res.json({ success: false, message: 'No file' });
    const ext = req.file.originalname.split('.').pop() || 'jpg';
    const name = crypto.randomBytes(8).toString('hex') + '.' + ext;
    const { error } = await supabase.storage.from('patch-images').upload(name, req.file.buffer, {
      contentType: req.file.mimetype,
      upsert: false
    });
    if (error) throw error;
    const { data: urlData } = supabase.storage.from('patch-images').getPublicUrl(name);
    res.json({ success: true, url: urlData.publicUrl });
  } catch (err) {
    res.json({ success: false, message: err.message });
  }
});

app.post('/api/admin/upload/file', requireAdmin, upload.single('file'), async (req, res) => {
  if (req.adminRole !== 'master') return res.status(403).json({ success: false, message: 'Forbidden' });
  try {
    if (!req.file) return res.json({ success: false, message: 'No file' });
    const name = crypto.randomBytes(8).toString('hex') + '.3105';
    const { error } = await supabase.storage.from('patch-files').upload(name, req.file.buffer, {
      contentType: 'application/octet-stream',
      upsert: false
    });
    if (error) throw error;
    const { data: urlData } = supabase.storage.from('patch-files').getPublicUrl(name);
    const hash = crypto.createHash('sha256').update(req.file.buffer).digest('hex');
    res.json({ success: true, url: urlData.publicUrl, hash, size: req.file.size });
  } catch (err) {
    res.json({ success: false, message: err.message });
  }
});

// ---- App Settings Endpoints ----
app.get('/api/client/config', async (req, res) => {
  try {
    const { data, error } = await supabase.from('app_settings').select('*');
    if (error) throw error;
    const config = {};
    if (data) {
      data.forEach(item => { config[item.key] = item.value; });
    }
    res.json({ success: true, config });
  } catch (err) {
    res.json({ success: false, message: err.message });
  }
});

app.get('/api/admin/config', requireAdmin, async (req, res) => {
  try {
    const { data, error } = await supabase.from('app_settings').select('*');
    if (error) throw error;
    res.json({ success: true, data });
  } catch (err) {
    res.json({ success: false, message: err.message });
  }
});

app.post('/api/admin/config', requireAdmin, async (req, res) => {
  if (req.adminRole !== 'master') return res.status(403).json({ success: false, message: 'Forbidden' });
  try {
    const { settings } = req.body;
    if (!settings || !Array.isArray(settings)) return res.json({ success: false, message: 'Invalid settings data' });
    
    // settings = [{ key: 'latest_ios_version', value: '1.2.0' }, ...]
    const { error } = await supabase.from('app_settings').upsert(settings, { onConflict: 'key' });
    if (error) throw error;
    
    res.json({ success: true, message: 'Updated successfully' });
  } catch (err) {
    res.json({ success: false, message: err.message });
  }
});

// ======================== START ========================
app.listen(PORT, () => {
  console.log(`ROX Auth Server running on port ${PORT}`);
  console.log(`Web UI: http://localhost:${PORT}/`);
  console.log(`API:   http://localhost:${PORT}/api/verify?key=xxx&hwid=xxx&secret=xxx`);
  console.log(`Patch API: http://localhost:${PORT}/api/ff/sync`);
});
