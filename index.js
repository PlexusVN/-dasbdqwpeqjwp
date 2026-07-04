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
app.get(['/', '/web'], (req, res) => {
  res.send(`<!DOCTYPE html>
<html lang="vi">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ROX CHEATS - Quản Lý Key</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Segoe UI',sans-serif;background:#0f0f0f;color:#e0e0e0;min-height:100vh}
.header{background:linear-gradient(135deg,#1a1a2e,#16213e);padding:20px;text-align:center;border-bottom:2px solid #e94560}
.header h1{color:#e94560;font-size:24px}
.header p{color:#888;font-size:13px;margin-top:5px}
.container{max-width:1200px;margin:20px auto;padding:0 20px}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:15px;margin-bottom:25px}
.stat-card{background:#1a1a2e;padding:20px;border-radius:10px;text-align:center;border:1px solid #2a2a4a}
.stat-card .num{font-size:28px;font-weight:bold;color:#e94560}
.stat-card .label{color:#888;font-size:13px;margin-top:5px}
.card{background:#1a1a2e;border-radius:10px;padding:20px;margin-bottom:20px;border:1px solid #2a2a4a}
.card h3{color:#e94560;margin-bottom:15px}
.form-row{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:10px;align-items:center}
.form-row input,.form-row select{flex:1;min-width:150px}
input,select,button{padding:10px 15px;border:1px solid #2a2a4a;border-radius:6px;background:#16213e;color:#e0e0e0;font-size:14px}
input:focus,select:focus{outline:none;border-color:#e94560}
button{cursor:pointer;transition:0.2s}
button:hover{opacity:0.85}
.btn-primary{background:#e94560;color:#fff;border:none}
.btn-danger{background:#c0392b;color:#fff;border:none}
.btn-success{background:#27ae60;color:#fff;border:none}
.btn-warning{background:#f39c12;color:#fff;border:none}
table{width:100%;border-collapse:collapse}
th,td{padding:10px 12px;text-align:left;border-bottom:1px solid #2a2a4a;font-size:13px}
th{background:#16213e;color:#e94560;font-weight:600;white-space:nowrap}
tr:hover td{background:#1e1e3a}
.status-active{color:#27ae60;font-weight:bold}
.status-banned{color:#c0392b;font-weight:bold}
.status-expired{color:#888}
.action-btn{padding:4px 10px;border-radius:4px;border:none;cursor:pointer;font-size:12px;margin:2px}
.toast{position:fixed;bottom:20px;right:20px;padding:12px 24px;border-radius:8px;color:#fff;font-size:14px;z-index:999;display:none}
.toast-success{background:#27ae60}
.toast-error{background:#c0392b}
.loading{text-align:center;padding:40px;color:#888}
.login-overlay{position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.85);display:flex;align-items:center;justify-content:center;z-index:1000}
.login-box{background:#1a1a2e;padding:40px;border-radius:12px;border:1px solid #2a2a4a;width:350px}
.login-box h2{color:#e94560;margin-bottom:20px;text-align:center}
.login-box input{width:100%;margin-bottom:12px}
.login-box button{width:100%}
</style>
</head>
<body>
<div class="header"><h1>🔐 ROX CHEATS - Quản Lý Key</h1><p>Hệ thống xác thực & quản lý key</p></div>
<div class="login-overlay" id="loginOverlay">
<div class="login-box">
<h2>Đăng Nhập</h2>
<input type="text" id="loginUser" placeholder="Tên đăng nhập">
<input type="password" id="loginPass" placeholder="Mật khẩu">
<button class="btn-primary" onclick="login()">Đăng Nhập</button>
</div>
</div>
<div class="container" id="mainContent" style="display:none">
<div class="stats" id="statsContainer"></div>
<div class="card">
<h3>➕ Tạo Key Mới</h3>
<div class="form-row">
<input type="number" id="createDays" value="30" min="1" max="3650">
<input type="text" id="createUser" placeholder="Người dùng">
<input type="text" id="createNote" placeholder="Ghi chú">
<button class="btn-success" onclick="createKey()">Tạo Key</button>
</div>
<div id="createResult" style="margin-top:10px;font-size:13px"></div>
</div>
<div class="card">
<h3>📋 Danh Sách Key</h3>
<div class="form-row" style="margin-bottom:15px">
<input type="text" id="searchInput" placeholder="🔍 Tìm key..." oninput="renderTable()">
<select id="statusFilter" onchange="renderTable()">
<option value="all">Tất cả</option><option value="active">Active</option><option value="banned">Banned</option><option value="expired">Expired</option>
</select>
<button class="btn-primary" onclick="refreshData()">🔄 Làm mới</button>
</div>
<div style="overflow-x:auto">
<table><thead><tr><th>STT</th><th>Mã Key</th><th>Trạng Thái</th><th>Ngày Tạo</th><th>Ngày Hết Hạn</th><th>HWID</th><th>Người Dùng</th><th>Ghi Chú</th><th>Hành Động</th></tr></thead>
<tbody id="keyTableBody"><tr><td colspan="9" class="loading">Đang tải...</td></tr></tbody></table>
</div>
</div>
<div class="card">
<h3>📜 Nhật Ký Hoạt Động</h3>
<div style="overflow-x:auto">
<table><thead><tr><th>ID</th><th>Hành Động</th><th>Key</th><th>Chi Tiết</th><th>Thời Gian</th></tr></thead>
<tbody id="logTableBody"><tr><td colspan="5" class="loading">Đang tải...</td></tr></tbody></table>
</div>
</div>
</div>
<div class="toast" id="toast"></div>
<script>
const BASE=window.location.origin;
let authToken='',allKeys=[],allLogs=[];
function login(){const u=document.getElementById('loginUser').value,p=document.getElementById('loginPass').value;if(!u||!p)return showToast('Vui lòng nhập đầy đủ thông tin','error');authToken=btoa(u+':'+p);fetch(BASE+'/api/keys',{headers:{'Authorization':'Basic '+authToken}}).then(r=>{if(r.ok){document.getElementById('loginOverlay').style.display='none';document.getElementById('mainContent').style.display='block';refreshData()}else{showToast('Sai thông tin đăng nhập','error');authToken=''}}).catch(()=>{showToast('Lỗi kết nối server','error');authToken=''})}
function showToast(m,t){const e=document.getElementById('toast');e.textContent=m;e.className='toast toast-'+t;e.style.display='block';setTimeout(()=>e.style.display='none',3000)}
function api(p,o){o=o||{};o.headers=o.headers||{};o.headers['Authorization']='Basic '+authToken;return fetch(BASE+p,o).then(r=>r.json())}
function refreshData(){Promise.all([api('/api/keys').then(r=>allKeys=r.data||[]),api('/api/logs').then(r=>allLogs=r.data||[]),api('/api/stats').then(r=>{if(r.data)renderStats(r.data)})]).then(()=>{renderTable();renderLogs()}).catch(()=>showToast('Lỗi tải dữ liệu','error'))}
function renderStats(d){document.getElementById('statsContainer').innerHTML='<div class="stat-card"><div class="num">'+d.total+'</div><div class="label">Tổng Key</div></div><div class="stat-card"><div class="num" style="color:#27ae60">'+d.active+'</div><div class="label">Đang Hoạt Động</div></div><div class="stat-card"><div class="num" style="color:#c0392b">'+d.banned+'</div><div class="label">Bị Khóa</div></div><div class="stat-card"><div class="num" style="color:#888">'+d.expired+'</div><div class="label">Hết Hạn</div></div>'}
function renderTable(){const s=document.getElementById('searchInput').value.toLowerCase(),f=document.getElementById('statusFilter').value;let k=allKeys;if(s)k=k.filter(x=>x.key.toLowerCase().includes(s));if(f!=='all')k=k.filter(x=>x.status===f);const t=document.getElementById('keyTableBody');if(!k.length){t.innerHTML='<tr><td colspan="9" style="text-align:center;color:#888">Không có dữ liệu</td></tr>';return}t.innerHTML=k.map((x,i)=>{const c='status-'+x.status,st=x.status==='active'?'✅ Active':x.status==='banned'?'🚫 Banned':'⏰ Expired';return '<tr><td>'+(i+1)+'</td><td style="font-family:monospace;font-size:12px">'+x.key+'</td><td class="'+c+'">'+st+'</td><td>'+new Date(x.created_at).toLocaleDateString('vi-VN')+'</td><td>'+new Date(x.expires_at).toLocaleDateString('vi-VN')+'</td><td style="font-family:monospace;font-size:11px;color:#888">'+(x.hwid||'-')+'</td><td>'+(x.user||'-')+'</td><td>'+(x.note||'-')+'</td><td nowrap>'+(x.status==='active'?'<button class="action-btn btn-danger" onclick="banKey(\\''+x.key+'\\')">Khóa</button>':'')+(x.status==='banned'?'<button class="action-btn btn-success" onclick="unbanKey(\\''+x.key+'\\')">Mở</button>':'')+'<button class="action-btn btn-warning" onclick="extendKey(\\''+x.key+'\\')">Gia Hạn</button><button class="action-btn btn-danger" onclick="deleteKey(\\''+x.key+'\\')">Xóa</button><button class="action-btn btn-primary" onclick="copyKey(\\''+x.key+'\\')">Copy</button></td></tr>'}).join('')}
function renderLogs(){const t=document.getElementById('logTableBody');if(!allLogs.length){t.innerHTML='<tr><td colspan="5" style="text-align:center;color:#888">Không có dữ liệu</td></tr>';return}t.innerHTML=allLogs.slice(0,50).map(x=>'<tr><td>'+x.id+'</td><td>'+x.action+'</td><td style="font-family:monospace;font-size:12px">'+x.key+'</td><td>'+x.detail+'</td><td>'+new Date(x.created_at).toLocaleString('vi-VN')+'</td></tr>').join('')}
function createKey(){const d=document.getElementById('createDays').value,u=document.getElementById('createUser').value,n=document.getElementById('createNote').value,btn=document.querySelector('.btn-success');btn.disabled=true;btn.textContent='Đang tạo...';api('/api/keys',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({days:parseInt(d),user:u,note:n})}).then(r=>{if(r.success){document.getElementById('createResult').innerHTML='<div style="background:#0a2a1a;padding:10px;border-radius:6px;border:1px solid #27ae60"><strong style="color:#27ae60">✅ Key mới:</strong><span style="font-family:monospace;color:#fff;font-size:16px;display:block;margin-top:5px">'+r.data.key+'</span><span style="color:#888;font-size:12px">Hạn: '+new Date(r.data.expires_at).toLocaleDateString('vi-VN')+'</span></div>';refreshData()}else showToast(r.message,'error')}).catch(()=>showToast('Lỗi tạo key','error')).finally(()=>{btn.disabled=false;btn.textContent='Tạo Key'})}
function banKey(k){if(confirm('Khóa key '+k+'?'))api('/api/keys/'+encodeURIComponent(k)+'/ban',{method:'POST'}).then(r=>{showToast(r.message,r.success?'success':'error');if(r.success)refreshData()})}
function unbanKey(k){if(confirm('Mở khóa key '+k+'?'))api('/api/keys/'+encodeURIComponent(k)+'/unban',{method:'POST'}).then(r=>{showToast(r.message,r.success?'success':'error');if(r.success)refreshData()})}
function deleteKey(k){if(confirm('Xóa key '+k+'? Không thể hoàn tác!'))api('/api/keys/'+encodeURIComponent(k),{method:'DELETE'}).then(r=>{showToast(r.message,r.success?'success':'error');if(r.success)refreshData()})}
function copyKey(k){navigator.clipboard.writeText(k).then(()=>showToast('Đã copy key: '+k))}
function extendKey(k){const d=prompt('Nhập số ngày gia hạn cho key '+k+':','30');if(!d||isNaN(d)||parseInt(d)<1)return;api('/api/keys/'+encodeURIComponent(k)+'/extend',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({days:parseInt(d)})}).then(r=>{showToast(r.message,r.success?'success':'error');if(r.success)refreshData()})}
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
