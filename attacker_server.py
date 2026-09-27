#!/usr/bin/env python3
"""模拟攻击者站点 —— 仅使用 Python 标准库。

运行在 http://localhost:9000 ，与主服务 http://127.0.0.1:8000 属于
不同 site（不同 host），因此：
  - 浏览器对跨站 POST 不附加 SameSite=Lax 的会话 Cookie；
  - 跨站请求的 Origin 为 http://localhost:9000，不在主服务可信列表。

提供：
  /                攻击演示页（自动提交表单、顶级导航 GET 对比）
  /auto-form       经典 CSRF：自动提交的跨站 POST 表单（可嵌入 iframe）
  /attacker-token  攻击者用自己会话向主服务换取的 token（token 固定演示）
  /proxy-submit    服务端转发并伪造/缺失 Origin 头（浏览器 JS 无法伪造 Origin）
"""

import json
import urllib.request
import urllib.error
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TARGET = "http://127.0.0.1:8000"

PAGE = """<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8"><title>攻击者站点</title>
<style>body{{font-family:system-ui;max-width:760px;margin:2rem auto;padding:0 1rem}}
code{{background:#eee;padding:2px 6px;border-radius:4px}}
.box{{border:1px solid #ccc;border-radius:8px;padding:1rem;margin:1rem 0}}
iframe{{width:100%;height:120px;border:1px dashed #aaa}}</style></head>
<body>
<h1>⚠️ 模拟攻击者站点（localhost:9000）</h1>
<p>目标：<code>{target}</code>。本站与目标不同 site，用于演示跨站请求被拦截。</p>

<div class="box">
  <h2>1. 经典 CSRF：自动提交的跨站 POST 表单</h2>
  <p>下方 iframe 中的表单会自动 POST 到目标站。SameSite=Lax 下浏览器<b>不会</b>附带会话
  Cookie，且 Origin 为 <code>http://localhost:9000</code> —— 两层防线都会拦截：</p>
  <iframe src="/auto-form"></iframe>
</div>

<div class="box">
  <h2>2. 对比：顶级导航 GET（SameSite=Lax 放行 Cookie）</h2>
  <p><a href="{target}/api/whoami" target="_blank">点击打开 {target}/api/whoami</a>
  —— 顶级导航 GET 会携带会话 Cookie，返回 <code>session_cookie_present: true</code>。
  这正是 SameSite=Lax 的边界：放行“安全的”跨站导航，拦截跨站 POST。</p>
</div>

<div class="box">
  <h2>3. 伪造 Origin（服务端代理）</h2>
  <p>浏览器 JS 无法伪造 Origin 头，但攻击者可以用自己的服务器转发请求并任意设置请求头。
  下面两个链接由本站服务端代为请求目标站：</p>
  <ul>
    <li><a href="/proxy-submit?mode=forged-origin" target="_blank">伪造 Origin: http://evil.example</a></li>
    <li><a href="/proxy-submit?mode=no-origin" target="_blank">完全不带 Origin/Referer</a></li>
  </ul>
  <p>注意：服务端代理拿不到受害者浏览器里的 Cookie，所以即使伪造了同源 Origin，
  也会因缺少有效会话/token 被拦截 —— 这正体现了“双重提交 + 会话绑定”与
  “Origin 校验”互补的价值。</p>
</div>
</body></html>"""

AUTO_FORM = """<!DOCTYPE html>
<html><body style="font-family:monospace">
<p>正在自动提交跨站 POST 表单…</p>
<form id="f" method="POST" action="{target}/api/submit">
  <input type="hidden" name="name" value="evil-bot">
  <input type="hidden" name="message" value="这是攻击者伪造的提交">
  <input type="hidden" name="csrf_token" value="attacker-guessed-token">
</form>
<script>document.getElementById('f').submit();</script>
</body></html>"""


def _post_to_target(path, body: bytes, headers: dict):
    req = urllib.request.Request(TARGET + path, data=body, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    for k, v in headers.items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()
    except urllib.error.URLError as e:
        return 502, json.dumps({"error": f"目标不可达: {e}"}).encode()


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _send(self, code, body: bytes, ctype="text/html; charset=utf-8", cors=False):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        if cors:
            # 攻击者站点当然“欢迎”任何人读取它的响应
            self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        from urllib.parse import urlparse, parse_qs
        u = urlparse(self.path)
        if u.path == "/":
            self._send(200, PAGE.format(target=TARGET).encode())
        elif u.path == "/auto-form":
            self._send(200, AUTO_FORM.format(target=TARGET).encode())
        elif u.path == "/attacker-token":
            self._attacker_token()
        elif u.path == "/proxy-submit":
            mode = parse_qs(u.query).get("mode", ["forged-origin"])[0]
            self._proxy_submit(mode)
        else:
            self._send(404, b"not found", "text/plain")

    def _attacker_token(self):
        """攻击者以自己身份向目标站建立会话，拿到属于自己的合法 token。"""
        jar = SimpleCookie()
        req = urllib.request.Request(TARGET + "/api/session")
        try:
            with urllib.request.urlopen(req) as resp:
                for sc in resp.headers.get_all("Set-Cookie") or []:
                    jar.load(sc)
                data = json.loads(resp.read())
        except Exception as e:
            self._send(502, json.dumps({"error": str(e)}).encode(),
                       "application/json", cors=True)
            return
        out = {
            "attacker_session_cookie": jar.get("session_id").value if jar.get("session_id") else None,
            "attacker_csrf_token": data.get("csrf_token"),
            "hint": "这是攻击者自己会话的 token；用它搭配受害者的 Cookie 提交即为 token 固定攻击",
        }
        self._send(200, json.dumps(out, ensure_ascii=False).encode(),
                   "application/json; charset=utf-8", cors=True)

    def _proxy_submit(self, mode):
        headers = {}
        if mode == "forged-origin":
            headers["Origin"] = "http://evil.example"
        elif mode == "same-origin-spoof":
            headers["Origin"] = TARGET  # 伪造同源 Origin（但没有受害者 Cookie/token）
        # mode == "no-origin" 时什么头也不加
        body = b"name=proxy-attacker&message=forged-origin-test&csrf_token=fake"
        code, resp = _post_to_target("/api/submit", body, headers)
        out = {
            "mode": mode,
            "sent_headers": headers or "(无 Origin/Referer)",
            "target_status": code,
            "target_response": json.loads(resp or b"{}"),
        }
        self._send(200, json.dumps(out, ensure_ascii=False, indent=2).encode(),
                   "application/json; charset=utf-8", cors=True)


def main():
    httpd = ThreadingHTTPServer(("127.0.0.1", 9000), Handler)
    print("攻击者站点已启动: http://localhost:9000  (目标: %s)" % TARGET)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
