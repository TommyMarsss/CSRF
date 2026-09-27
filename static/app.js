'use strict';

const resultBox = document.getElementById('result');
let currentToken = null;
let staleToken = null;

function show(obj) {
  resultBox.textContent =
    typeof obj === 'string' ? obj : JSON.stringify(obj, null, 2);
}

function esc(s) {
  return String(s).replace(/[&<>"']/g, c => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[c]));
}

// 领取/轮换 token：服务端会轮换 nonce 并通过 Set-Cookie 更新双重提交 Cookie
async function refreshToken() {
  const r = await fetch('/api/token');
  const data = await r.json();
  if (currentToken && currentToken !== data.token) staleToken = currentToken;
  currentToken = data.token;
  document.getElementById('token-view').textContent = currentToken;
  return currentToken;
}

// 统一提交入口。cookieToken 用于演示“篡改/固定”场景：
// csrf_token Cookie 未设 HttpOnly（双重提交要求 JS 可读），因此前端可写。
async function submit({ token, useHeader = true, cookieToken } = {}) {
  if (cookieToken !== undefined) {
    document.cookie = 'csrf_token=' + encodeURIComponent(cookieToken) + ';path=/';
  }
  const headers = { 'Content-Type': 'application/json' };
  if (useHeader) headers['X-CSRF-Token'] = token;
  const r = await fetch('/api/submit', {
    method: 'POST',
    headers,
    body: JSON.stringify({ name: 'ghost', message: 'CSRF demo', ts: Date.now() }),
  });
  const data = await r.json();
  show({ HTTP状态: r.status, 服务端响应: data });
  return r.status;
}

// ① 正常同源表单提交
document.getElementById('msg-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const fd = new FormData(e.target);
  const r = await fetch('/api/submit', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': currentToken },
    body: JSON.stringify({ name: fd.get('name'), message: fd.get('message') }),
  });
  show({ HTTP状态: r.status, 服务端响应: await r.json() });
});

// 轮换 token：旧 token 立即失效
document.getElementById('btn-rotate').addEventListener('click', async () => {
  await refreshToken();
  show('已轮换 token。\n旧 token（已失效）: ' + (staleToken || '(无)') +
       '\n新 token: ' + currentToken);
});

// 旧 token：Cookie 与请求头一致（绕过双重提交比对），但 nonce 已轮换
document.getElementById('btn-stale').addEventListener('click', async () => {
  if (!staleToken) { show('请先点击「轮换 token」，使旧 token 失效'); return; }
  await submit({ token: staleToken, cookieToken: staleToken });
});

// 篡改 Cookie：Cookie 与请求头不一致
document.getElementById('btn-tamper').addEventListener('click', async () => {
  await submit({ token: currentToken, cookieToken: 'AAAA.forged-by-attacker' });
  resultBox.textContent += '\n\n提示：Cookie 已被篡改，点击「轮换 token」可恢复。';
});

// token 固定：攻击者自己会话签发的 token + 受害者的会话 Cookie
document.getElementById('btn-fixation').addEventListener('click', async () => {
  const r = await fetch('/api/attacker-token');
  const { token } = await r.json();
  await submit({ token, cookieToken: token });
  resultBox.textContent += '\n\n提示：提交用的是攻击者会话的 token，点击「轮换 token」可恢复。';
});

// 不带 token
document.getElementById('btn-notoken').addEventListener('click', async () => {
  await submit({ useHeader: false });
});

// 伪造 Origin：浏览器禁止 JS 修改 Origin 头，给出 curl 复现方式
document.getElementById('btn-forged-origin').addEventListener('click', () => {
  show([
    '浏览器禁止 JS 修改 Origin 头，页面内脚本无法伪造，可用 curl 复现：',
    '',
    '  curl -i -X POST ' + location.origin + '/api/submit \\',
    "    -H 'Origin: https://evil.example' \\",
    "    -H 'X-CSRF-Token: " + currentToken + "' \\",
    "    -H 'Cookie: session_id=...; csrf_token=...' \\",
    '    -H \'Content-Type: application/json\' \\',
    '    -d \'{"name":"hacker"}\'',
    '',
    '服务端会在第一层（Origin 校验）拦截。',
    '也可以点击「打开跨站攻击页」：浏览器会自动携带不可信的 Origin，效果相同。',
  ].join('\n'));
});

// 跨站攻击页（独立端口 = 独立 Origin）
document.getElementById('btn-evil').addEventListener('click', () => {
  window.open(EVIL_ORIGIN + '/', '_blank');
});

// 服务端拦截日志轮询
async function pollLog() {
  try {
    const r = await fetch('/api/log');
    const { events } = await r.json();
    document.querySelector('#log tbody').innerHTML = events.slice().reverse()
      .map(e => `<tr class="${e.ok ? 'ok' : 'bad'}"><td>${esc(e.time)}</td>` +
                `<td>${e.ok ? '✅ 放行' : '🚫 拦截'}</td>` +
                `<td>${esc(e.source)}</td><td>${esc(e.reason)}</td></tr>`)
      .join('');
  } catch (e) { /* 忽略瞬时错误 */ }
}

refreshToken();
pollLog();
setInterval(pollLog, 2000);
