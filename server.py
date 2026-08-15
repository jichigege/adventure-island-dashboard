# -*- coding: utf-8 -*-
"""
冒险岛水世界商店报表看板 —— 登录鉴权后端（Flask 版，适配云端部署）

部署平台：Render / Railway / Fly.io / 任意支持 Python 的 PaaS
依赖：Flask（requirements.txt）
数据：SQLite（accounts.db）持久化账号，不怕重启丢失
配置：
  ADMIN_PASSWORD 环境变量 = 超级管理员密码（必设，否则默认 Gs852789）
  SECRET_KEY    环境变量 = HMAC 签名密钥（必设，否则自动生成）
  DASHBOARD_PATH= 看板 HTML 文件路径（默认 ./dashboard.html）
  PORT          = 服务端口（默认 8787）

运行：
  pip install -r requirements.txt
  python server.py
  # 或云平台自动通过 Procfile 启动
"""
import os, sys, json, base64, hashlib, hmac, secrets, time, datetime
import sqlite3
import urllib.parse

from flask import (
    Flask, request, redirect, url_for,
    render_template_string, jsonify, make_response,
    send_from_directory, send_file
)

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", secrets.token_hex(32))
app.config["JSON_AS_ASCII"] = False
app.config["MAX_CONTENT_LENGTH"] = 1 * 1024 * 1024  # 1MB

# ---- 路径配置 ----
HERE = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("DB_PATH", os.path.join(HERE, "accounts.db"))
DASHBOARD_HTML = os.environ.get(
    "DASHBOARD_PATH",
    os.path.join(HERE, "dashboard.html"),
)
LOGO_PATHS = [
    os.path.join(HERE, "logo80X80.jpg"),
    os.path.join(HERE, "static", "logo80X80.jpg"),
]

# 密码策略
PW_MIN_LEN = 8
PW_UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
PW_LOWER = "abcdefghijklmnopqrstuvwxyz"
PW_DIGIT = "0123456789"
PW_SYMBOL = "!@#$%^&*()_+./*-"
DEFAULT_NEW_PW = "Mxd888888"
TOKEN_DAYS = 15
TOKEN_MAX_AGE = TOKEN_DAYS * 86400


# ============================================================
#  数据库（SQLite 持久化账号）
# ============================================================
def get_db():
    """获取数据库连接（线程安全）。"""
    db = getattr(app, "_db", None)
    if db is None:
        db = sqlite3.connect(DB_PATH, check_same_thread=False)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA foreign_keys=ON")
        # 建表
        db.executescript("""
            CREATE TABLE IF NOT EXISTS accounts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                role TEXT NOT NULL DEFAULT 'user',
                salt TEXT NOT NULL,
                pw_hash TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                created_by TEXT DEFAULT '',
                note TEXT DEFAULT '',
                updated_at TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_accounts_username ON accounts(username);
        """)
        # 种子管理员（仅当表为空时）
        row = db.execute("SELECT COUNT(*) FROM accounts").fetchone()[0]
        if row == 0:
            _seed_admin(db)
            db.commit()
        app._db = db
    return db


def _seed_admin(db):
    """写入超级管理员种子。"""
    salt, h = _hash_pw(os.environ.get("ADMIN_PASSWORD", "Gs852789"))
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    db.execute(
        "INSERT INTO accounts (username, role, salt, pw_hash, enabled, created_at, created_by, note) "
        "VALUES (?, 'admin', ?, ?, 1, ?, 'system', '超级管理员')",
        ("admin", salt, h, now),
    )


# ---- 密码工具 ----
def _hash_pw(pw, salt=None):
    if salt is None:
        salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode("utf-8"), bytes.fromhex(salt), 100000)
    return salt, dk.hex()


def verify_pw(pw, salt, expected):
    _, h = _hash_pw(pw, salt)
    return hmac.compare_digest(h, expected)


def check_pw_policy(pw):
    if not isinstance(pw, str) or len(pw) < PW_MIN_LEN:
        return False, f"密码长度至少 {PW_MIN_LEN} 位"
    if not any(c in PW_UPPER for c in pw):
        return False, "密码必须包含至少一个大写字母"
    if not any(c in PW_LOWER for c in pw):
        return False, "密码必须包含至少一个小写字母"
    if not any(c in PW_DIGIT for c in pw):
        return False, "密码必须包含至少一个数字"
    allowed = set(PW_UPPER + PW_LOWER + PW_DIGIT + PW_SYMBOL)
    bad = [c for c in pw if c not in allowed]
    if bad:
        return False, "密码包含不允许的字符：" + "".join(sorted(set(bad)))
    return True, "ok"


def _is_valid_username(u):
    if not isinstance(u, str) or not (3 <= len(u) <= 32):
        return False
    allowed = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-.")
    return all(c in allowed for c in u)


# ---- Token ----
def make_token(username):
    payload = {"u": username, "exp": int(time.time()) + TOKEN_MAX_AGE}
    raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    body = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
    sig = hmac.new(app.config["SECRET_KEY"].encode(), body.encode(), hashlib.sha256).hexdigest()
    return f"{body}.{sig}"


def verify_token(tok):
    if not tok:
        return None
    try:
        body, sig = tok.rsplit(".", 1)
        expect = hmac.new(app.config["SECRET_KEY"].encode(), body.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expect, sig):
            return None
        pad = "=" * (-len(body) % 4)
        payload = json.loads(base64.urlsafe_b64decode(body + pad))
        if int(time.time()) > int(payload.get("exp", 0)):
            return None
        return payload.get("u")
    except Exception:
        return None


def get_current_user():
    tok = request.cookies.get("dash_auth", "")
    if tok:
        return verify_token(tok)
    return None


def require_login():
    u = get_current_user()
    if not u:
        return None
    db = get_db()
    row = db.execute("SELECT * FROM accounts WHERE username=? AND enabled=1", (u,)).fetchone()
    return row if row else None


def require_admin():
    row = require_login()
    if row and row["role"] == "admin":
        return row
    return None


# ---- LOGO ----
_LOGO_B64 = None


def logo_b64():
    global _LOGO_B64
    if _LOGO_B64 is None:
        for p in LOGO_PATHS:
            if os.path.exists(p):
                try:
                    b = open(p, "rb").read()
                    _LOGO_B64 = "data:image/jpeg;base64," + base64.b64encode(b).decode("ascii")
                    break
                except Exception:
                    continue
        if _LOGO_B64 is None:
            _LOGO_B64 = ""
    return _LOGO_B64


# ============================================================
#  页面模板
# ============================================================
LOGIN_PAGE = """<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>登录 · 冒险岛水世界商店报表数据看板</title>
<style>
:root{--bg:#0b111d;--card:#151d30;--line:#243049;--txt:#e4ecf7;--mut:#7a8bae;--vk:#4faaff;--warn:#ff5c5c;--ok:#34d97a}
*{box-sizing:border-box;margin:0;padding:0}
body{background:radial-gradient(1200px 600px at 50% -10%,#16223f,#0b111d);color:var(--txt);min-height:100vh;
 font-family:-apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC","Microsoft YaHei",sans-serif;
 display:flex;align-items:center;justify-content:center;padding:20px}
.card{width:100%;max-width:360px;background:var(--card);border:1px solid var(--line);border-radius:16px;padding:28px 24px;box-shadow:0 20px 60px rgba(0,0,0,.4)}
.logo{width:64px;height:64px;border-radius:14px;display:block;margin:0 auto 14px;object-fit:contain;background:#fff}
h1{font-size:17px;text-align:center;margin-bottom:4px}
.sub{text-align:center;color:var(--mut);font-size:12.5px;margin-bottom:22px}
label{display:block;font-size:12.5px;color:var(--mut);margin:14px 0 6px}
input{width:100%;padding:11px 12px;border-radius:10px;border:1px solid var(--line);background:#0e1626;color:var(--txt);font-size:14px;outline:none}
input:focus{border-color:var(--vk)}
.btn{width:100%;margin-top:20px;padding:12px;border:none;border-radius:10px;background:linear-gradient(135deg,#4faaff,#3080e0);color:#fff;font-size:15px;font-weight:600;cursor:pointer}
.btn:active{transform:translateY(1px)}
.err{margin-top:14px;color:var(--warn);font-size:12.5px;text-align:center;min-height:16px}
.tip{margin-top:16px;color:var(--mut);font-size:11.5px;text-align:center;line-height:1.5}
</style></head>
<body>
<div class="card">
  <img class="logo" src="__LOGO__" alt="冒险岛水世界">
  <h1>冒险岛水世界商店报表</h1>
  <div class="sub">数据看板 · 请登录后查看</div>
  <form id="f" onsubmit="return doLogin()">
    <label>账号</label>
    <input id="user" autocomplete="username" placeholder="请输入账号" required autofocus>
    <label>密码</label>
    <input id="pass" type="password" autocomplete="current-password" placeholder="请输入密码" required>
    <button class="btn" type="submit">登 录</button>
  </form>
  <div class="err" id="err"></div>
  <div class="tip">登录后在本设备 15 天内免登录</div>
</div>
<script>
async function doLogin(){
  var u=document.getElementById('user').value.trim();
  var p=document.getElementById('pass').value;
  var err=document.getElementById('err'); err.textContent='';
  if(!u||!p){err.textContent='请输入账号和密码';return false;}
  try{
    var r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({user:u,pass:p})});
    var d=await r.json();
    if(d.ok){ location.href='/'; }
    else { err.textContent=d.msg||'账号或密码错误'; }
  }catch(e){ err.textContent='网络错误，请重试'; }
  return false;
}
</script>
</body></html>"""


ADMIN_PAGE = """<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>账号管理 · 冒险岛水世界商店报表</title>
<style>
:root{--bg:#0b111d;--card:#151d30;--card2:#1a2540;--line:#243049;--txt:#e4ecf7;--mut:#7a8bae;--vk:#4faaff;--warn:#ff5c5c;--ok:#34d97a;--gold:#ffc94d}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--txt);font-family:-apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC","Microsoft YaHei",sans-serif;padding:18px}
.wrap{max-width:880px;margin:0 auto}
.top{display:flex;align-items:center;gap:12px;margin-bottom:18px}
.top img{width:40px;height:40px;border-radius:9px;background:#fff;object-fit:contain}
.top h1{font-size:18px}
.top .who{margin-left:auto;color:var(--mut);font-size:13px}
.top a{color:var(--vk);font-size:13px;text-decoration:none;margin-left:14px}
.card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:18px;margin-bottom:16px}
.card h2{font-size:14px;margin-bottom:14px;color:var(--txt2)}
.add{display:flex;gap:10px;flex-wrap:wrap;align-items:flex-end}
.add input{padding:10px 12px;border-radius:9px;border:1px solid var(--line);background:#0e1626;color:var(--txt);font-size:14px;outline:none}
.add .u{flex:1;min-width:160px}
.btn{padding:10px 16px;border:none;border-radius:9px;background:linear-gradient(135deg,#4faaff,#3080e0);color:#fff;font-weight:600;cursor:pointer;font-size:13px}
.btn.sm{padding:6px 10px;font-size:12px}
.btn.ghost{background:#22304e;color:var(--txt)}
.btn.danger{background:#3a1d24;color:#ff8a8a}
table{width:100%;border-collapse:collapse;font-size:13px;margin-top:6px}
th,td{text-align:left;padding:10px 8px;border-bottom:1px solid var(--line)}
th{color:var(--mut);font-weight:600;font-size:12px}
.tag{display:inline-block;padding:2px 8px;border-radius:20px;font-size:11px}
.tag.admin{background:rgba(79,170,255,.15);color:var(--vk)}
.tag.user{background:rgba(255,170,64,.15);color:var(--gold)}
.tag.on{background:rgba(52,217,122,.15);color:var(--ok)}
.tag.off{background:rgba(255,92,92,.15);color:var(--warn)}
.ops{display:flex;gap:6px;flex-wrap:wrap}
.msg{margin-top:12px;font-size:12.5px;min-height:16px}
.err{color:var(--warn)} .ok{color:var(--ok)}
.modal{position:fixed;inset:0;background:rgba(0,0,0,.6);display:none;align-items:center;justify-content:center;padding:20px;z-index:50}
.modal.show{display:flex}
.mbox{width:100%;max-width:340px;background:var(--card);border:1px solid var(--line);border-radius:14px;padding:22px}
.mbox h3{font-size:15px;margin-bottom:14px}
.mbox input{width:100%;padding:10px 12px;border-radius:9px;border:1px solid var(--line);background:#0e1626;color:var(--txt);font-size:14px;margin:8px 0;outline:none}
.mbox .row{display:flex;gap:10px;margin-top:14px}
.mbox .row .btn{flex:1}
</style></head>
<body>
<div class="wrap">
  <div class="top">
    <img src="__LOGO__" alt="">
    <h1>账号管理</h1>
    <span class="who" id="who"></span>
    <a href="/">← 返回看板</a>
    <a href="#" onclick="logout()">退出</a>
  </div>

  <div class="card">
    <h2>新增账号（默认密码 Mxd888888，建好后请通知对方修改）</h2>
    <div class="add">
      <input class="u" id="nu" placeholder="新账号（3-32位，字母数字 _ - .）">
      <select id="nr" style="padding:10px;border-radius:9px;background:#0e1626;color:var(--txt);border:1px solid var(--line)">
        <option value="user">普通用户</option>
        <option value="admin">管理员</option>
      </select>
      <button class="btn" onclick="addUser()">新增</button>
    </div>
    <div class="msg" id="addmsg"></div>
  </div>

  <div class="card">
    <h2>账号列表</h2>
    <table>
      <thead><tr><th>账号</th><th>角色</th><th>状态</th><th>创建时间</th><th>操作</th></tr></thead>
      <tbody id="rows"></tbody>
    </table>
  </div>
</div>

<div class="modal" id="m"><div class="mbox">
  <h3 id="mt"></h3>
  <input id="np" type="password" placeholder="新密码">
  <div class="msg" id="mm"></div>
  <div class="row">
    <button class="btn ghost" onclick="closeM()">取消</button>
    <button class="btn" id="ms" onclick="saveM()">确定</button>
  </div>
</div></div>

<script>
var API='/api/accounts', cur=null, mode='', tuser='';
async function me(){var r=await fetch('/api/me');if(!r.ok){location.href='/login';return;}var d=await r.json();document.getElementById('who').textContent='当前：'+d.user+(d.role==='admin'?'（管理员）':'（普通用户）');}
function logout(){fetch('/api/logout',{method:'POST'}).then(()=>location.href='/login');}
async function load(){
  var r=await fetch(API); if(!r.ok){if(r.status===403)location.href='/login';return;}
  var list=await r.json();
  var tb=document.getElementById('rows'); tb.innerHTML='';
  list.forEach(function(a){
    var tr=document.createElement('tr');
    tr.innerHTML='<td>'+esc(a.username)+'</td>'+
      '<td><span class="tag '+(a.role==='admin'?'admin':'user')+'">'+(a.role==='admin'?'管理员':'普通用户')+'</span></td>'+
      '<td><span class="tag '+(a.enabled?'on':'off')+'">'+(a.enabled?'启用':'停用')+'</span></td>'+
      '<td style="color:var(--mut)">'+(a.created_at||'')+'</td>'+
      '<td><div class="class">'+opsHtml(a)+'</div></td>';
    tb.appendChild(tr);
  });
}
function opsHtml(a){
  var h='<button class="btn sm" onclick="openSetPw(\''+a.username+'\')">改密</button>';
  if(a.enabled) h+='<button class="btn sm ghost" onclick="setEnable(\''+a.username+'\',false)">停用</button>';
  else h+='<button class="btn sm" onclick="setEnable(\''+a.username+'\',true)">启用</button>';
  if(a.username!=='admin') h+='<button class="btn sm danger" onclick="del(\''+a.username+'\')">删除</button>';
  return h;
}
function esc(s){return String(s).replace(/[&<>"]/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c];});}
function addUser(){
  var u=document.getElementById('nu').value.trim(), r=document.getElementById('nr').value;
  var m=document.getElementById('addmsg'); m.className='msg'; m.textContent='';
  if(!u){m.className='msg err';m.textContent='请输入账号';return;}
  fetch(API,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:u,role:r})})
    .then(function(x){return x.json().then(function(d){return {s:x.ok,d:d};});})
    .then(function(o){ if(o.s){m.className='msg ok';m.textContent='已新增：'+u+'（默认密码 Mxd888888）';document.getElementById('nu').value='';load();} else {m.className='msg err';m.textContent=o.d.msg||'新增失败';} });
}
function setEnable(u,en){
  fetch(API+'/'+encodeURIComponent(u),{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({enabled:en})})
    .then(function(x){return x.json().then(function(d){return {s:x.ok,d:d};});})
    .then(function(o){ if(o.s)load(); else alert(o.d.msg||'操作失败'); });
}
function del(u){
  if(!confirm('确定删除账号 '+u+' ？此操作不可恢复。'))return;
  fetch(API+'/'+encodeURIComponent(u),{method:'DELETE'})
    .then(function(x){return x.json().then(function(d){return {s:x.ok,d:d};});})
    .then(function(o){ if(o.s)load(); else alert(o.d.msg||'删除失败'); });
}
function openSetPw(u){
  mode='setpw'; tuser=u; cur=null;
  document.getElementById('mt').textContent='修改密码 · '+u;
  document.getElementById('np').value=''; document.getElementById('mm').textContent='';
  document.getElementById('m').classList.add('show');
}
function closeM(){document.getElementById('m').classList.remove('show');}
function saveM(){
  var np=document.getElementById('np').value, mm=document.getElementById('mm');
  mm.className='msg'; mm.textContent='';
  fetch(API+'/'+encodeURIComponent(tuser),{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:np})})
    .then(function(x){return x.json().then(function(d){return {s:x.ok,d:d};});})
    .then(function(o){ if(o.s){mm.className='msg ok';mm.textContent='密码已更新';setTimeout(closeM,800);load();} else {mm.className='msg err';mm.textContent=o.d.msg||'修改失败';} });
}
me(); load();
</script>
</body></html>"""


AUTH_INJECT = """
<style>
#authbar{position:fixed;top:0;left:0;right:0;z-index:9999;display:none;align-items:center;gap:12px;
  background:linear-gradient(135deg,#182542,#101c32);border-bottom:1px solid var(--line);
  padding:7px 16px;font-size:12.5px;color:var(--txt2);backdrop-filter:blur(6px)}
#authbar .ab-logo{height:22px;width:22px;border-radius:5px;background:#fff;object-fit:contain}
#authbar .ab-user{color:var(--txt);font-weight:600}
#authbar .ab-role{color:var(--vk)}
#authbar .ab-sp{margin-left:auto}
#authbar button{background:#22304e;color:var(--txt);border:1px solid var(--line);border-radius:8px;padding:5px 12px;font-size:12px;cursor:pointer}
#authbar button:hover{background:#2c3c5e}
body{padding-top:38px}
</style>
<div id="authbar">
  <img class="ab-logo" src="__LOGO__" alt="">
  <span>欢迎，<span class="ab-user" id="ab_user"></span> <span class="ab-role" id="ab_role"></span></span>
  <span class="ab-sp"></span>
  <button onclick="abChange()">修改密码</button>
  <button id="ab_admin" style="display:none" onclick="location.href='/admin'">账号管理</button>
  <button onclick="abLogout()">退出</button>
</div>
<div class="modal" id="abm" style="position:fixed;inset:0;background:rgba(0,0,0,.6);display:none;align-items:center;justify-content:center;padding:20px;z-index:10000">
  <div style="width:100%;max-width:340px;background:#151d30;border:1px solid #243049;border-radius:14px;padding:22px">
    <h3 style="font-size:15px;margin-bottom:14px;color:#e4ecf7">修改密码</h3>
    <input id="ab_cur" type="password" placeholder="当前密码" style="width:100%;padding:10px 12px;border-radius:9px;border:1px solid #243049;background:#0e1626;color:#e4ecf7;font-size:14px;margin:6px 0;outline:none">
    <input id="ab_new" type="password" placeholder="新密码（大写+小写+数字）" style="width:100%;padding:10px 12px;border-radius:9px;border:1px solid #243049;background:#0e1626;color:#e4ecf7;font-size:14px;margin:6px 0;outline:none">
    <div id="ab_msg" style="font-size:12.5px;min-height:16px;margin-top:6px"></div>
    <div style="display:flex;gap:10px;margin-top:14px">
      <button onclick="abCloseM()" style="flex:1;padding:10px;border:1px solid #243049;border-radius:9px;background:#22304e;color:#e4ecf7;cursor:pointer">取消</button>
      <button onclick="abSavePw()" style="flex:1;padding:10px;border:none;border-radius:9px;background:linear-gradient(135deg,#4faaff,#3080e0);color:#fff;font-weight:600;cursor:pointer">确定</button>
    </div>
  </div>
</div>
<script>
(async function(){
  try{
    var r=await fetch('/api/me');
    if(!r.ok){location.href='/login';return;}
    var d=await r.json();
    var bar=document.getElementById('authbar');
    document.getElementById('ab_user').textContent=d.user;
    document.getElementById('ab_role').textContent=d.role==='admin'?'（管理员）':'（普通用户）';
    if(d.role==='admin')document.getElementById('ab_admin').style.display='';
    bar.style.display='flex';
  }catch(e){ location.href='/login'; }
})();
function abLogout(){fetch('/api/logout',{method:'POST'}).then(function(){location.href='/login';});}
function abChange(){document.getElementById('ab_cur').value='';document.getElementById('ab_new').value='';document.getElementById('ab_msg').textContent='';document.getElementById('abm').style.display='flex';}
function abCloseM(){document.getElementById('abm').style.display='none';}
async function abSavePw(){
  var cur=document.getElementById('ab_cur').value, np=document.getElementById('ab_new').value, m=document.getElementById('ab_msg');
  m.style.color='#ff5c5c'; m.textContent='';
  var r=await fetch('/api/change-password',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({current:cur,new:np})});
  var d=await r.json();
  if(r.ok){m.style.color='#34d97a';m.textContent='密码已修改，请牢记新密码';setTimeout(abCloseM,900);}
  else{m.textContent=d.msg||'修改失败';}
}
</script>
"""


def inject_auth(html):
    if "<!--AUTH_INJECTED-->" in html:
        return html
    inj = AUTH_INJECT.replace("__LOGO__", logo_b64()) + "\n<!--AUTH_INJECTED-->\n</body>"
    return html.replace("</body>", inj, 1)


# ============================================================
#  路由
# ============================================================

@app.route("/login")
def page_login():
    return LOGIN_PAGE.replace("__LOGO__", logo_b64())


@app.route("/admin")
def page_admin():
    row = require_admin()
    if not row:
        return redirect("/login")
    return ADMIN_PAGE.replace("__LOGO__", logo_b64())


@app.route("/")
def page_dashboard():
    row = require_login()
    if not row:
        return redirect("/login")
    if not os.path.exists(DASHBOARD_HTML):
        return "看板文件不存在，请联系管理员生成。", 500
    html = open(DASHBOARD_HTML, "r", encoding="utf-8").read()
    return inject_auth(html)


@app.route("/logo80X80.jpg")
@app.route("/favicon.ico")
def serve_logo():
    for p in LOGO_PATHS:
        if os.path.exists(p):
            return send_file(p, mimetype="image/jpeg")
    return ("", 404)


# ---- API ----

@app.route("/api/login", methods=["POST"])
def api_login():
    d = request.get_json(force=True, silent=True) or {}
    u = (d.get("user") or "").strip()
    p = d.get("pass") or ""
    db = get_db()
    row = db.execute("SELECT * FROM accounts WHERE username=?", (u,)).fetchone()
    if not row or not row["enabled"] or not verify_pw(p, row["salt"], row["pw_hash"]):
        return jsonify(ok=False, msg="账号或密码错误，或账号已停用")
    tok = make_token(u)
    resp = make_response(jsonify(ok=True, role=row["role"]))
    resp.set_cookie(
        "dash_auth", tok,
        max_age=TOKEN_MAX_AGE, httponly=True, samesite="Lax",
        secure=request.is_secure,
    )
    return resp


@app.route("/api/logout", methods=["POST"])
def api_logout():
    resp = make_response(jsonify(ok=True))
    resp.set_cookie("dash_auth", "", max_age=0, httponly=True, samesite="Lax")
    return resp


@app.route("/api/me")
def api_me():
    u = get_current_user()
    if not u:
        return jsonify(ok=False), 401
    db = get_db()
    row = db.execute("SELECT role FROM accounts WHERE username=? AND enabled=1", (u,)).fetchone()
    if not row:
        return jsonify(ok=False), 401
    return jsonify(ok=True, user=u, role=row["role"])


@app.route("/api/accounts", methods=["GET"])
def api_accounts_list():
    row = require_admin()
    if not row:
        return jsonify(ok=False, msg="无权限"), 403
    db = get_db()
    rows = db.execute("SELECT username, role, enabled, created_at, note FROM accounts ORDER BY id").fetchall()
    out = [dict(r) for r in rows]
    for o in out:
        o["enabled"] = bool(o["enabled"])
    return jsonify(out)


@app.route("/api/accounts", methods=["POST"])
def api_accounts_create():
    row = require_admin()
    if not row:
        return jsonify(ok=False, msg="无权限"), 403
    d = request.get_json(force=True, silent=True) or {}
    uname = (d.get("username") or "").strip()
    role = d.get("role", "user")
    if role not in ("user", "admin"):
        role = "user"
    if not _is_valid_username(uname):
        return jsonify(ok=False, msg="账号格式不合法（3-32位，仅字母数字 _ - .）")
    db = get_db()
    if db.execute("SELECT 1 FROM accounts WHERE username=?", (uname,)).fetchone():
        return jsonify(ok=False, msg="账号已存在")
    salt, h = _hash_pw(DEFAULT_NEW_PW)
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    cur_u = get_current_user() or "system"
    db.execute(
        "INSERT INTO accounts (username, role, salt, pw_hash, enabled, created_at, created_by) VALUES (?,?,?,?,1,?,?)",
        (uname, role, salt, h, now, cur_u),
    )
    db.commit()
    return jsonify(ok=True, username=uname, default_password=DEFAULT_NEW_PW)


@app.route("/api/accounts/<username>", methods=["PUT"])
def api_accounts_update(username):
    adm = require_admin()
    if not adm:
        return jsonify(ok=False, msg="无权限"), 403
    target = urllib.parse.unquote(username)
    db = get_db()
    row = db.execute("SELECT * FROM accounts WHERE username=?", (target,)).fetchone()
    if not row:
        return jsonify(ok=False, msg="账号不存在"), 404
    d = request.get_json(force=True, silent=True) or {}

    if "password" in d:
        new = d.get("password") or ""
        ok, msg = check_pw_policy(new)
        if not ok:
            return jsonify(ok=False, msg=msg)
        salt, h = _hash_pw(new)
        db.execute("UPDATE accounts SET salt=?, pw_hash=?, updated_at=? WHERE username=?", (salt, h, datetime.datetime.now().strftime("%Y-%m-%d %H:%M"), target))
        db.commit()
        return jsonify(ok=True)

    if "enabled" in d:
        if target == "admin" and not d["enabled"]:
            return jsonify(ok=False, msg="不能停用超级管理员")
        db.execute("UPDATE accounts SET enabled=?, updated_at=? WHERE username=?", (int(bool(d["enabled"])), datetime.datetime.now().strftime("%Y-%m-%d %H:%M"), target))
        db.commit()
        return jsonify(ok=True)

    return jsonify(ok=False, msg="无操作")


@app.route("/api/accounts/<username>", methods=["DELETE"])
def api_accounts_delete(username):
    adm = require_admin()
    if not adm:
        return jsonify(ok=False, msg="无权限"), 403
    target = urllib.parse.unquote(username)
    if target == "admin":
        return jsonify(ok=False, msg="不能删除超级管理员")
    db = get_db()
    row = db.execute("SELECT * FROM accounts WHERE username=?", (target,)).fetchone()
    if not row:
        return jsonify(ok=False, msg="账号不存在"), 404
    if row["role"] == "admin":
        admins = db.execute("SELECT COUNT(*) FROM accounts WHERE role='admin' AND enabled=1").fetchone()[0]
        if admins <= 1:
            return jsonify(ok=False, msg="不能删除最后一个管理员")
    db.execute("DELETE FROM accounts WHERE username=?", (target,))
    db.commit()
    return jsonify(ok=True)


@app.route("/api/change-password", methods=["POST"])
def api_change_password():
    u = get_current_user()
    if not u:
        return jsonify(ok=False, msg="未登录"), 401
    db = get_db()
    row = db.execute("SELECT * FROM accounts WHERE username=? AND enabled=1", (u,)).fetchone()
    if not row:
        return jsonify(ok=False, msg="未登录"), 401
    d = request.get_json(force=True, silent=True) or {}
    cur = d.get("current") or ""
    new = d.get("new") or ""
    if not verify_pw(cur, row["salt"], row["pw_hash"]):
        return jsonify(ok=False, msg="当前密码不正确")
    ok, msg = check_pw_policy(new)
    if not ok:
        return jsonify(ok=False, msg=msg)
    salt, h = _hash_pw(new)
    db.execute("UPDATE accounts SET salt=?, pw_hash=?, updated_at=? WHERE username=?", (salt, h, datetime.datetime.now().strftime("%Y-%m-%d %H:%M"), u))
    db.commit()
    return jsonify(ok=True)


# ---- 备份/健康检查 ----
@app.route("/api/health")
def api_health():
    db = get_db()
    n = db.execute("SELECT COUNT(*) FROM accounts").fetchone()[0]
    dash_exists = os.path.exists(DASHBOARD_HTML)
    return jsonify(ok=True, accounts=n, dashboard=dash_exists)


# ============================================================
#  入口
# ============================================================
if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8787"))
    host = os.environ.get("HOST", "0.0.0.0")
    print(f"冒险岛看板鉴权服务(Flask): http://{host}:{port}")
    print(f"  账号库: {DB_PATH}")
    print(f"  看板文件: {DASHBOARD_HTML}")
    app.run(host=host, port=port, debug=False, threaded=True)
