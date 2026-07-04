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
@keyframes glow{0%,100%{box-shadow:0 0 5px #ff2020,0 0 10px #ff2020}50%{box-shadow:0 0 15px #ff2020,0 0 30px #ff202044}}
@keyframes fadeIn{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:translateY(0)}}
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Segoe UI',sans-serif;background:#0a0000;color:#e0d0d0;min-height:100vh}
::-webkit-scrollbar{width:6px}::-webkit-scrollbar-track{background:#1a0808}::-webkit-scrollbar-thumb{background:#ff202066;border-radius:3px}
.header{background:linear-gradient(135deg,#1a0505,#2a0808);padding:25px 20px;text-align:center;border-bottom:2px solid #ff2020;animation:glow 2s infinite;position:relative}
.header h1{color:#ff2020;font-size:26px;text-shadow:0 0 20px #ff2020,0 0 40px #ff202044;letter-spacing:2px}
.header p{color:#ff8888;font-size:13px;margin-top:5px;opacity:0.8}
.container{max-width:1200px;margin:20px auto;padding:0 20px;animation:fadeIn 0.5s}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:15px;margin-bottom:25px}
.stat-card{background:#1a0808;padding:20px;border-radius:10px;text-align:center;border:1px solid #ff202033;transition:0.3s}
.stat-card:hover{border-color:#ff2020;box-shadow:0 0 20px #ff202022;transform:translateY(-2px)}
.stat-card .num{font-size:30px;font-weight:bold;color:#ff2020;text-shadow:0 0 15px #ff202066}
.stat-card .label{color:#ff8888;font-size:13px;margin-top:5px}
.card{background:#1a0808;border-radius:10px;padding:20px;margin-bottom:20px;border:1px solid #ff202033;transition:0.3s;animation:fadeIn 0.5s}
.card:hover{border-color:#ff202066;box-shadow:0 0 15px #ff202011}
.card h3{color:#ff2020;margin-bottom:15px;text-shadow:0 0 10px #ff202044;font-size:16px}
.form-row{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:10px;align-items:center}
.form-row input,.form-row select{flex:1;min-width:150px}
input,select,button{padding:10px 15px;border:1px solid #ff202033;border-radius:6px;background:#0d0000;color:#e0d0d0;font-size:14px;transition:0.3s}
input:focus,select:focus{outline:none;border-color:#ff2020;box-shadow:0 0 15px #ff202033;background:#150000}
button{cursor:pointer;font-weight:bold;letter-spacing:0.5px}
button:hover{transform:translateY(-1px);box-shadow:0 0 20px #ff202044!important}
.btn-primary{background:linear-gradient(135deg,#ff2020,#cc0000);color:#fff;border:none;box-shadow:0 0 10px #ff202033}
.btn-danger{background:linear-gradient(135deg,#ff4444,#aa0000);color:#fff;border:none}
.btn-success{background:linear-gradient(135deg,#ff2020,#cc0000);color:#fff;border:none;box-shadow:0 0 10px #ff202033}
.btn-warning{background:linear-gradient(135deg,#ff6622,#cc4400);color:#fff;border:none}
table{width:100%;border-collapse:collapse}
th,td{padding:12px;text-align:left;border-bottom:1px solid #ff202015;font-size:13px}
th{background:#150303;color:#ff2020;font-weight:700;white-space:nowrap;text-shadow:0 0 5px #ff202044}
tr:hover td{background:#200505}
.status-active{color:#ff2020;font-weight:bold;text-shadow:0 0 10px #ff202066}
.status-banned{color:#ff6666;font-weight:bold}
.status-expired{color:#884444}
.action-btn{padding:5px 12px;border-radius:4px;border:1px solid #ff202044;cursor:pointer;font-size:12px;margin:2px;background:transparent;color:#ff8888;transition:0.3s}
.action-btn:hover{background:#ff2020;color:#fff;border-color:#ff2020;box-shadow:0 0 15px #ff202044!important;transform:none!important}
.toast{position:fixed;bottom:20px;right:20px;padding:14px 28px;border-radius:8px;color:#fff;font-size:14px;z-index:999;display:none;animation:fadeIn 0.3s;border:1px solid}
.toast-success{background:#2a0505;border-color:#ff2020;box-shadow:0 0 20px #ff202044}
.toast-error{background:#2a0505;border-color:#ff4444;box-shadow:0 0 20px #ff444444}
.loading{text-align:center;padding:40px;color:#ff8888}
.login-overlay{position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.92);display:flex;align-items:center;justify-content:center;z-index:1000}
.login-box{background:#1a0808;padding:40px;border-radius:12px;border:1px solid #ff202044;width:380px;box-shadow:0 0 40px #ff202022;animation:fadeIn 0.5s}
.login-box h2{color:#ff2020;margin-bottom:25px;text-align:center;font-size:22px;text-shadow:0 0 15px #ff202066}
.login-box input{width:100%;margin-bottom:15px;text-align:center}
.login-box button{width:100%;padding:12px;font-size:16px}
.copy-field{font-family:monospace;color:#ff2020;font-size:15px;display:block;margin-top:5px;word-break:break-all}
</style>
</head>
<body>
<div class="header"><h1>🔐 ROX CHEATS</h1><p>Hệ thống quản lý key xác thực</p></div>
<div class="login-overlay" id="loginOverlay">
<div class="login-box">
<h2>🔑 ĐĂNG NHẬP</h2>
<input type="text" id="loginUser" placeholder="Tên đăng nhập">
<input type="password" id="loginPass" placeholder="Mật khẩu">
<button class="btn-primary" onclick="login()">ĐĂNG NHẬP</button>
</div>
</div>
<div class="container" id="mainContent" style="display:none">
<div class="stats" id="statsContainer"></div>
<div class="card">
<h3>➕ TẠO KEY MỚI</h3>
<div class="form-row">
<input type="number" id="createDays" value="30" min="1" max="3650" placeholder="Số ngày">
<input type="text" id="createUser" placeholder="Người dùng (tùy chọn)">
<input type="text" id="createNote" placeholder="Ghi chú (tùy chọn)">
<button class="btn-success" onclick="createKey()">🔥 TẠO KEY</button>
</div>
<div id="createResult" style="margin-top:10px;font-size:13px"></div>
</div>
<div class="card">
<h3>📋 DANH SÁCH KEY</h3>
<div class="form-row" style="margin-bottom:15px">
<input type="text" id="searchInput" placeholder="🔍 Tìm key..." oninput="renderTable()">
<select id="statusFilter" onchange="renderTable()">
<option value="all">Tất cả</option><option value="active">Active</option><option value="banned">Banned</option><option value="expired">Expired</option>
</select>
<button class="btn-primary" onclick="refreshData()">🔄 LÀM MỚI</button>
</div>
<div style="overflow-x:auto">
<table><thead><tr><th>STT</th><th>MÃ KEY</th><th>TRẠNG THÁI</th><th>NGÀY TẠO</th><th>HẾT HẠN</th><th>HWID</th><th>NGƯỜI DÙNG</th><th>GHI CHÚ</th><th>HÀNH ĐỘNG</th></tr></thead>
<tbody id="keyTableBody"><tr><td colspan="9" class="loading">Đang tải dữ liệu...</td></tr></tbody></table>
</div>
</div>
<div class="card">
<h3>📜 NHẬT KÝ HOẠT ĐỘNG</h3>
<div style="overflow-x:auto">
<table><thead><tr><th>ID</th><th>HÀNH ĐỘNG</th><th>KEY</th><th>CHI TIẾT</th><th>THỜI GIAN</th></tr></thead>
<tbody id="logTableBody"><tr><td colspan="5" class="loading">Đang tải...</td></tr></tbody></table>
</div>
</div>
</div>
<div class="toast" id="toast"></div>
<script>
const BASE=window.location.origin;
let authToken='',allKeys=[],allLogs=[];
function login(){const u=document.getElementById('loginUser').value,p=document.getElementById('loginPass').value;if(!u||!p)return showToast('Vui lòng nhập đầy đủ thông tin','error');authToken=btoa(u+':'+p);fetch(BASE+'/api/keys',{headers:{'Authorization':'Basic '+authToken}}).then(r=>{if(r.ok){document.getElementById('loginOverlay').style.display='none';document.getElementById('mainContent').style.display='block';refreshData()}else{showToast('Sai thông tin đăng nhập','error');authToken=''}}).catch(()=>{showToast('Lỗi kết nối server','error');authToken=''})}
function showToast(m,t){const e=document.getElementById('toast');e.textContent=m;e.className='toast toast-'+t;e.style.display='block';setTimeout(()=>e.style.display='none',3500)}
function api(p,o){o=o||{};o.headers=o.headers||{};o.headers['Authorization']='Basic '+authToken;return fetch(BASE+p,o).then(r=>r.json())}
function refreshData(){Promise.all([api('/api/keys').then(r=>allKeys=r.data||[]),api('/api/logs').then(r=>allLogs=r.data||[]),api('/api/stats').then(r=>{if(r.data)renderStats(r.data)})]).then(()=>{renderTable();renderLogs()}).catch(()=>showToast('Lỗi tải dữ liệu','error'))}
function renderStats(d){document.getElementById('statsContainer').innerHTML='<div class="stat-card"><div class="num">'+d.total+'</div><div class="label">Tổng Key</div></div><div class="stat-card"><div class="num">'+d.active+'</div><div class="label">Đang Hoạt Động</div></div><div class="stat-card"><div class="num">'+d.banned+'</div><div class="label">Bị Khóa</div></div><div class="stat-card"><div class="num">'+d.expired+'</div><div class="label">Hết Hạn</div></div>'}
function renderTable(){const s=document.getElementById('searchInput').value.toLowerCase(),f=document.getElementById('statusFilter').value;let k=allKeys;if(s)k=k.filter(x=>x.key.toLowerCase().includes(s));if(f!=='all')k=k.filter(x=>x.status===f);const t=document.getElementById('keyTableBody');if(!k.length){t.innerHTML='<tr><td colspan="9" style="text-align:center;color:#ff8888">Không có dữ liệu</td></tr>';return}t.innerHTML=k.map((x,i)=>{const c='status-'+x.status,st=x.status==='active'?'✅ Active':x.status==='banned'?'🚫 Banned':'⏰ Expired';return '<tr><td>'+(i+1)+'</td><td class="copy-field">'+x.key+'</td><td class="'+c+'">'+st+'</td><td>'+new Date(x.created_at).toLocaleDateString('vi-VN')+'</td><td>'+new Date(x.expires_at).toLocaleDateString('vi-VN')+'</td><td style="font-family:monospace;font-size:11px;color:#ff6666">'+(x.hwid||'-')+'</td><td>'+(x.user||'-')+'</td><td>'+(x.note||'-')+'</td><td nowrap>'+(x.status==='active'?'<button class="action-btn" onclick="banKey(\\''+x.key+'\\')">🚫 Khóa</button>':'')+(x.status==='banned'?'<button class="action-btn" onclick="unbanKey(\\''+x.key+'\\')">✅ Mở</button>':'')+'<button class="action-btn" onclick="extendKey(\\''+x.key+'\\')">📅 Gia Hạn</button><button class="action-btn" onclick="deleteKey(\\''+x.key+'\\')">🗑 Xóa</button><button class="action-btn" onclick="copyKey(\\''+x.key+'\\')">📋 Copy</button></td></tr>'}).join('')}
function renderLogs(){const t=document.getElementById('logTableBody');if(!allLogs.length){t.innerHTML='<tr><td colspan="5" style="text-align:center;color:#ff8888">Không có dữ liệu</td></tr>';return}t.innerHTML=allLogs.slice(0,50).map(x=>'<tr><td>'+x.id+'</td><td style="color:#ff2020;font-weight:bold">'+x.action+'</td><td class="copy-field">'+x.key+'</td><td>'+x.detail+'</td><td>'+new Date(x.created_at).toLocaleString('vi-VN')+'</td></tr>').join('')}
function createKey(){const d=document.getElementById('createDays').value,u=document.getElementById('createUser').value,n=document.getElementById('createNote').value,btn=document.querySelector('.btn-success');btn.disabled=true;btn.textContent='⏳ ĐANG TẠO...';api('/api/keys',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({days:parseInt(d),user:u,note:n})}).then(r=>{if(r.success){document.getElementById('createResult').innerHTML='<div style="background:#150303;padding:15px;border-radius:8px;border:1px solid #ff202066"><strong style="color:#ff2020;text-shadow:0 0 10px #ff202044">✅ KEY MỚI ĐÃ TẠO:</strong><span class="copy-field">'+r.data.key+'</span><span style="color:#ff8888;font-size:12px">📅 Hạn: '+new Date(r.data.expires_at).toLocaleDateString('vi-VN')+'</span></div>';refreshData()}else showToast(r.message,'error')}).catch(()=>showToast('Lỗi tạo key','error')).finally(()=>{btn.disabled=false;btn.textContent='🔥 TẠO KEY'})}
function banKey(k){if(confirm('🔒 Khóa key '+k+'?'))api('/api/keys/'+encodeURIComponent(k)+'/ban',{method:'POST'}).then(r=>{showToast(r.message,r.success?'success':'error');if(r.success)refreshData()})}
function unbanKey(k){if(confirm('🔓 Mở khóa key '+k+'?'))api('/api/keys/'+encodeURIComponent(k)+'/unban',{method:'POST'}).then(r=>{showToast(r.message,r.success?'success':'error');if(r.success)refreshData()})}
function deleteKey(k){if(confirm('🗑 Xóa key '+k+'? Không thể hoàn tác!'))api('/api/keys/'+encodeURIComponent(k),{method:'DELETE'}).then(r=>{showToast(r.message,r.success?'success':'error');if(r.success)refreshData()})}
function copyKey(k){navigator.clipboard.writeText(k).then(()=>showToast('📋 Đã copy key: '+k,'success'))}
function extendKey(k){const d=prompt('📅 Nhập số ngày gia hạn:','30');if(!d||isNaN(d)||parseInt(d)<1)return;api('/api/keys/'+encodeURIComponent(k)+'/extend',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({days:parseInt(d)})}).then(r=>{showToast(r.message,r.success?'success':'error');if(r.success)refreshData()})}
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
