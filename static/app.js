/* CSRF 演示前端 —— 原生 JS，无框架。
 * token 获取：GET /api/session 后从 JSON 响应（也可读非 HttpOnly 的 csrf_token Cookie）取得，
 * 提交时放入 X-CSRF-Token 自定义头（双重提交的“第二份”）。
 */

const ATTACKER = "http://localhost:9000";
let csrfToken = null;

const logEl = document.getElementById("log");

function log(title, detail, ok) {
  const entry = document.createElement("div");
  entry.className = "entry " + (ok ? "pass" : "blocked");
  const time = new Date().toLocaleTimeString();
  entry.innerHTML = `<strong>[${time}] ${title}</strong><pre></pre>`;
  entry.querySelector("pre").textContent =
    typeof detail === "string" ? detail : JSON.stringify(detail, null, 2);
  logEl.prepend(entry);
}

function getCookie(name) {
  const m = document.cookie.match(new RegExp("(?:^|; )" + name + "=([^;]*)"));
  return m ? decodeURIComponent(m[1]) : null;
}

async function initSession() {
  const resp = await fetch("/api/session");
  const data = await resp.json();
  csrfToken = data.csrf_token;
  document.getElementById("session-info").textContent =
    "会话已建立（SameSite=Lax），CSRF token 已下发：" + csrfToken.slice(0, 16) + "…";
  log("会话初始化", { csrf_token: csrfToken, cookie: getCookie("csrf_token") }, true);
}

async function submitForm(tokenOverride) {
  const form = document.getElementById("guestbook");
  const body = {
    name: form.name.value,
    message: form.message.value,
  };
  const resp = await fetch("/api/submit", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-CSRF-Token": tokenOverride || csrfToken,
    },
    body: JSON.stringify(body),
  });
  return { status: resp.status, data: await resp.json() };
}

// ---- 正常提交 -------------------------------------------------------------

document.getElementById("guestbook").addEventListener("submit", async (e) => {
  e.preventDefault();
  const r = await submitForm();
  log(`正常提交 → HTTP ${r.status}`, r.data, r.status === 200);
  refreshSubmissions();
});

// ---- 模拟攻击 -------------------------------------------------------------

const attacks = {
  // ① 复用旧 token：先让服务端轮换会话（旧 token 作废），再用旧 token 提交
  "stale-token": async () => {
    const oldToken = csrfToken;
    const resp = await fetch("/api/session/rotate", { method: "POST" });
    const data = await resp.json();
    const r = await submitForm(oldToken); // 注意：此时 Cookie 已是新 token
    csrfToken = data.csrf_token; // 恢复前端持有的新 token
    log(`① 复用旧 token → HTTP ${r.status}`, r.data, r.status === 403);
  },

  // ② token 固定：攻击者用自己会话换得合法 token，搭配受害者（我）的 Cookie 提交
  "token-fixation": async () => {
    let attacker;
    try {
      const resp = await fetch(`${ATTACKER}/attacker-token`);
      attacker = await resp.json();
    } catch {
      log("② token 固定攻击", "无法连接攻击者站点，请先运行 python3 attacker_server.py", false);
      return;
    }
    const r = await submitForm(attacker.attacker_csrf_token);
    log(`② token 固定攻击（攻击者 token: ${String(attacker.attacker_csrf_token).slice(0, 16)}…）→ HTTP ${r.status}`,
        r.data, r.status === 403);
  },

  // ③ 伪造 Origin：浏览器 JS 无法伪造 Origin，故经攻击者服务器代理
  "forged-origin": async () => {
    try {
      const resp = await fetch(`${ATTACKER}/proxy-submit?mode=forged-origin`);
      const data = await resp.json();
      log(`③ 伪造 Origin → 目标返回 HTTP ${data.target_status}`, data, data.target_status === 403);
    } catch {
      log("③ 伪造 Origin", "无法连接攻击者站点，请先运行 python3 attacker_server.py", false);
    }
  },

  // ④ 跨站自动表单：iframe 加载攻击者页面，自动 POST（SameSite=Lax 不带 Cookie）
  "cross-site-form": async () => {
    const slot = document.getElementById("iframe-slot");
    slot.innerHTML = "";
    const iframe = document.createElement("iframe");
    iframe.src = `${ATTACKER}/auto-form`;
    iframe.title = "跨站攻击 iframe";
    slot.appendChild(iframe);
    log("④ 跨站自动表单", "已在下方 iframe 中触发（来自 localhost:9000 的自动 POST），" +
        "iframe 内显示的是目标站的拦截响应。", true);
  },

  // ⑤ 缺失 Origin：经代理发送完全不带 Origin/Referer 的请求
  "no-origin": async () => {
    try {
      const resp = await fetch(`${ATTACKER}/proxy-submit?mode=no-origin`);
      const data = await resp.json();
      log(`⑤ 缺失 Origin → 目标返回 HTTP ${data.target_status}`, data, data.target_status === 403);
    } catch {
      log("⑤ 缺失 Origin", "无法连接攻击者站点，请先运行 python3 attacker_server.py", false);
    }
  },
};

document.querySelectorAll("[data-attack]").forEach((btn) => {
  btn.addEventListener("click", () => attacks[btn.dataset.attack]());
});

// ---- 留言列表 -------------------------------------------------------------

async function refreshSubmissions() {
  const resp = await fetch("/api/submissions");
  const data = await resp.json();
  const ul = document.getElementById("submissions");
  ul.innerHTML = "";
  for (const s of data.submissions) {
    const li = document.createElement("li");
    li.textContent = `${s.name}: ${s.message}`;
    ul.appendChild(li);
  }
  if (!data.submissions.length) ul.innerHTML = "<li>（暂无）</li>";
}

document.getElementById("refresh").addEventListener("click", refreshSubmissions);

initSession().then(refreshSubmissions);
