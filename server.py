#!/usr/bin/env python3
"""CSRF 防护演示服务（仅标准库，无框架）。

用法:
    python3 server.py [app_port] [evil_port]

    主应用:    http://localhost:8000/   正常表单 + 攻击模拟按钮 + 拦截日志
    攻击者站:  http://localhost:8001/   模拟跨站攻击页面（iframe 自动表单等）
"""

from __future__ import annotations

import http.client
import json
import sys
import threading
import time
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from csrf import (
    CSRF_COOKIE,
    CSRFProtection,
    SESSION_COOKIE,
    SessionStore,
)

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"

# 会话 Cookie 不暴露给 JS；CSRF Cookie 必须能被前端 JS 读取（双重提交），故不加 HttpOnly
SESSION_COOKIE_ATTRS = "HttpOnly; Path=/; SameSite=Lax"
CSRF_COOKIE_ATTRS = "Path=/; SameSite=Lax"

APP_PORT = 8000  # main() 中可能被命令行参数覆盖，供攻击者站回连使用


class AppServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, addr, handler, trusted_hosts=(), evil_origin=""):
        super().__init__(addr, handler)
        self.sessions = SessionStore()
        self.csrf = CSRFProtection(trusted_hosts=trusted_hosts)
        self.evil_origin = evil_origin
        self.events: list[dict] = []
        self.events_lock = threading.Lock()

    def log_event(self, ok: bool, source: str, reason: str) -> None:
        with self.events_lock:
            self.events.append({
                "time": time.strftime("%H:%M:%S"),
                "ok": ok,
                "source": source,
                "reason": reason,
            })
            del self.events[:-100]


def make_server(host="127.0.0.1", port=8000, trusted_hosts=(), evil_origin=""):
    return AppServer((host, port), AppHandler,
                     trusted_hosts=trusted_hosts, evil_origin=evil_origin)


class AppHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):  # 静默默认访问日志，改用事件日志
        pass

    # ---- 基础工具 ----

    def _cookies(self) -> dict:
        jar = {}
        raw = self.headers.get("Cookie")
        if raw:
            c = SimpleCookie()
            c.load(raw)
            for k, morsel in c.items():
                jar[k] = morsel.value
        return jar

    def _lower_headers(self) -> dict:
        return {k.lower(): v for k, v in self.headers.items()}

    def _respond(self, status, body=b"", content_type="text/plain; charset=utf-8",
                 set_cookies=()):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for sc in set_cookies:
            self.send_header("Set-Cookie", sc)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status, obj, set_cookies=()):
        self._respond(status, json.dumps(obj, ensure_ascii=False),
                      "application/json; charset=utf-8", set_cookies)

    def _ensure_session(self, cookies):
        sid = cookies.get(SESSION_COOKIE)
        if sid and self.server.sessions.get(sid):
            return sid, False
        return self.server.sessions.create(), True

    def _session_cookies(self, sid, token):
        return [
            f"{SESSION_COOKIE}={sid}; {SESSION_COOKIE_ATTRS}",
            f"{CSRF_COOKIE}={token}; {CSRF_COOKIE_ATTRS}",
        ]

    # ---- 路由 ----

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path == "/":
            self._serve_index()
        elif path == "/api/token":
            self._api_token()
        elif path == "/api/log":
            with self.server.events_lock:
                events = list(self.server.events)
            self._json(200, {"events": events})
        elif path == "/api/attacker-token":
            self._api_attacker_token()
        elif path.startswith("/static/"):
            self._serve_static(path[len("/static/"):])
        else:
            self._json(404, {"error": "not found"})

    def do_POST(self):
        path = self.path.split("?", 1)[0]
        if path == "/api/submit":
            self._api_submit()
        else:
            self._json(404, {"error": "not found"})

    # ---- 页面与静态资源 ----

    def _serve_index(self):
        html = (STATIC_DIR / "index.html").read_text(encoding="utf-8")
        app_origin = f"http://{self.headers.get('Host', 'localhost')}"
        html = (html
                .replace("__APP_ORIGIN__", app_origin)
                .replace("__EVIL_ORIGIN__", self.server.evil_origin))
        self._respond(200, html, "text/html; charset=utf-8")

    def _serve_static(self, name):
        if "/" in name or ".." in name or name.startswith("."):
            self._json(404, {"error": "not found"})
            return
        path = STATIC_DIR / name
        if not path.is_file():
            self._json(404, {"error": "not found"})
            return
        ctype = {
            "css": "text/css; charset=utf-8",
            "js": "text/javascript; charset=utf-8",
            "html": "text/html; charset=utf-8",
        }.get(path.suffix.lstrip("."), "application/octet-stream")
        self._respond(200, path.read_bytes(), ctype)

    # ---- API ----

    def _api_token(self):
        """签发/轮换 CSRF token，并通过 Set-Cookie 下发双重提交 Cookie。"""
        cookies = self._cookies()
        sid, is_new = self._ensure_session(cookies)
        token = self.server.csrf.issue_token(sid)
        self.server.sessions.set_nonce(sid, token.split(".", 1)[0])
        self._json(200, {
            "token": token,
            "session": "new" if is_new else "existing",
        }, self._session_cookies(sid, token))

    def _api_attacker_token(self):
        """【仅演示用】模拟攻击者用自己会话换取的 token，不下发任何 Cookie。

        用于在前端真实演示 token 固定（fixation）变体：受害者浏览器携带
        自己的会话 Cookie，却提交攻击者会话签发的 token。
        """
        sid = self.server.sessions.create()
        token = self.server.csrf.issue_token(sid)
        self.server.sessions.set_nonce(sid, token.split(".", 1)[0])
        self._json(200, {
            "token": token,
            "note": "演示专用：这是攻击者自己会话签发的 token",
        })

    def _api_submit(self):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""

        headers = self._lower_headers()
        cookies = self._cookies()
        self_host = self.headers.get("Host", "")

        ok, reason = self.server.csrf.verify(
            self.server.sessions, "POST", headers, cookies, self_host)
        source = headers.get("origin") or headers.get("referer") or "(无 Origin/Referer)"
        self.server.log_event(ok, source, reason)

        if not ok:
            self._json(403, {"ok": False, "reason": reason})
            return
        try:
            data = json.loads(raw or b"{}")
        except json.JSONDecodeError:
            data = {"_raw": raw.decode("utf-8", "replace")}
        self._json(200, {"ok": True, "reason": reason, "echo": data})


# ---------------------------------------------------------------------------
# 攻击者站点（运行在独立端口 = 独立 Origin，模拟 evil.com）
# ---------------------------------------------------------------------------

EVIL_HTML = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<title>攻击者站点</title>
<style>
  body { font-family: -apple-system, "PingFang SC", sans-serif; max-width: 780px;
         margin: 2rem auto; padding: 0 1rem; background: #1a1a2e; color: #eee; }
  code, pre { background: #16213e; padding: 2px 6px; border-radius: 4px; }
  .box { background: #16213e; border: 1px solid #e94560; border-radius: 8px;
         padding: 1rem; margin: 1rem 0; }
  a { color: #e94560; }
</style>
</head>
<body>
<h1>😈 攻击者站点（__EVIL_ORIGIN__）</h1>
<p>你“访问恶意链接”的瞬间，本页已自动向 <code>__APP_ORIGIN__</code> 发起三类跨站请求。
回到 <a href="__APP_ORIGIN__">主页面</a> 查看「服务端拦截日志」。</p>

<div class="box">
  <b>攻击 1：隐藏 iframe 自动提交表单（经典 CSRF）</b><br>
  浏览器自动提交，无法携带自定义头 token；SameSite=Lax 下真正的跨站 POST
  还不会携带会话 Cookie（本机 localhost 不同端口属同一 site，Cookie 实际会带上，
  因此还会被第一层 Origin 校验拦截）。
</div>
<div class="box">
  <b>攻击 2：fetch credentials:'include' 跨站 POST</b><br>
  浏览器自动带上 <code>Origin: __EVIL_ORIGIN__</code>，被第一层 Origin 校验拦截。
  结果：<span id="fetch-result">发送中…</span>
</div>
<div class="box">
  <b>攻击 3：token 固定（fixation）</b><br>
  表单内嵌攻击者自己会话签发的 token：<code>__ATTACKER_TOKEN__</code><br>
  即使受害者浏览器带上了自己的会话 Cookie，该 token 也无法通过受害者会话的
  HMAC 绑定校验。
</div>

<iframe name="sink" style="display:none"></iframe>
<form id="auto" method="POST" action="__APP_ORIGIN__/api/submit" target="sink">
  <input type="hidden" name="name" value="hacker">
  <input type="hidden" name="message" value="经典 CSRF 自动提交">
</form>
<form id="fix" method="POST" action="__APP_ORIGIN__/api/submit" target="sink">
  <input type="hidden" name="name" value="hacker">
  <input type="hidden" name="csrf_token" value="__ATTACKER_TOKEN__">
</form>
<script>
  document.getElementById('auto').submit();
  document.getElementById('fix').submit();
  // text/plain 属于“简单请求”，不会触发预检，请求会真实发到服务端
  fetch('__APP_ORIGIN__/api/submit', {
    method: 'POST', credentials: 'include',
    headers: { 'Content-Type': 'text/plain' },
    body: 'name=hacker&via=fetch',
  }).then(function (r) {
    document.getElementById('fetch-result').textContent = 'HTTP ' + r.status;
  }).catch(function () {
    document.getElementById('fetch-result').textContent =
      '响应被 CORS 拦截（请求已发出并被服务端拒绝，见主站日志）';
  });
</script>
</body>
</html>
"""


class EvilHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    app_origin = "http://localhost:8000"
    evil_origin = "http://localhost:8001"

    def log_message(self, *args):
        pass

    def do_GET(self):
        # 攻击者先用自己的会话向目标站换取一个合法 token（fixation 的准备阶段）
        token = "(获取失败)"
        try:
            conn = http.client.HTTPConnection("localhost", APP_PORT, timeout=3)
            conn.request("GET", "/api/token")
            resp = conn.getresponse()
            token = json.loads(resp.read())["token"]
            conn.close()
        except Exception:
            pass
        html = (EVIL_HTML
                .replace("__APP_ORIGIN__", self.app_origin)
                .replace("__EVIL_ORIGIN__", self.evil_origin)
                .replace("__ATTACKER_TOKEN__", token))
        body = html.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main():
    global APP_PORT
    app_port = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
    evil_port = int(sys.argv[2]) if len(sys.argv) > 2 else 8001
    APP_PORT = app_port

    app_origin = f"http://localhost:{app_port}"
    evil_origin = f"http://localhost:{evil_port}"

    app = make_server("localhost", app_port,
                      trusted_hosts=("trusted.localhost",),
                      evil_origin=evil_origin)
    EvilHandler.app_origin = app_origin
    EvilHandler.evil_origin = evil_origin
    evil = ThreadingHTTPServer(("localhost", evil_port), EvilHandler)
    threading.Thread(target=evil.serve_forever, daemon=True).start()

    print(f"主应用:    {app_origin}/   （正常表单 + 攻击模拟按钮 + 拦截日志）")
    print(f"攻击者站:  {evil_origin}/  （模拟跨站攻击页面）")
    print("按 Ctrl+C 停止")
    try:
        app.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        evil.shutdown()


if __name__ == "__main__":
    main()
