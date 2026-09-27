#!/usr/bin/env python3
"""CSRF 防护演示主服务 —— 仅使用 Python 标准库。

防护分层：
  1. SameSite=Lax 会话 Cookie（浏览器侧第一道闸门）
  2. 双重提交 Cookie + 会话绑定 token（HMAC(secret, sid)），防 token 固定
  3. Origin / Referer 校验，缺失时安全兜底拒绝

运行： python3 server.py  [port]   （默认 127.0.0.1:8000）
"""

import hashlib
import hmac
import json
import secrets
import threading
import time
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"

SESSION_COOKIE = "session_id"
CSRF_COOKIE = "csrf_token"
CSRF_HEADER = "x-csrf-token"
CSRF_BODY_FIELD = "csrf_token"

CONTENT_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".json": "application/json; charset=utf-8",
}


# ---------------------------------------------------------------------------
# 可信 Origin 匹配：支持精确项与 "scheme://*.example.com[:port]" 子域通配
# ---------------------------------------------------------------------------

def match_origin_pattern(pattern: str, origin: str) -> bool:
    p = urlparse(pattern)
    o = urlparse(origin)
    if not p.scheme or not p.hostname or not o.scheme or not o.hostname:
        return False
    if p.scheme != o.scheme:
        return False
    # 端口：模式显式给出则必须一致；未给出则要求双方都是该 scheme 的默认端口
    if p.port is not None:
        if o.port != p.port:
            return False
    elif o.port not in (None, 80 if o.scheme == "http" else 443):
        return False
    if p.hostname.startswith("*."):
        base = p.hostname[2:]
        # 仅匹配子域，不匹配裸域本身
        return o.hostname != base and o.hostname.endswith("." + base)
    return p.hostname == o.hostname


class CSRFApp:
    """应用状态与 CSRF 核心逻辑（与 HTTP 层解耦，便于测试）。"""

    def __init__(self, secret: bytes = None, trusted_origins=None):
        # 每次启动随机生成密钥；测试可注入固定密钥
        self.secret = secret or secrets.token_bytes(32)
        self.trusted_origins = list(trusted_origins or [])
        self.sessions = {}        # sid -> {"created": ts}
        self.submissions = []     # 已成功提交的表单
        self.lock = threading.Lock()

    # ---- 会话与 token -----------------------------------------------------

    def new_session(self) -> str:
        sid = secrets.token_urlsafe(24)
        with self.lock:
            self.sessions[sid] = {"created": time.time()}
        return sid

    def rotate_session(self, old_sid: str) -> str:
        with self.lock:
            self.sessions.pop(old_sid, None)
        return self.new_session()

    def has_session(self, sid: str) -> bool:
        with self.lock:
            return sid in self.sessions

    def csrf_token_for(self, sid: str) -> str:
        """token = HMAC(secret, sid)：与当前会话强绑定。

        攻击者用自己会话拿到的 token 是 HMAC(secret, attacker_sid)，
        与受害者会话 sid 计算出的期望值必然不同 —— token 固定攻击失效。
        """
        return hmac.new(self.secret, b"csrf:" + sid.encode(), hashlib.sha256).hexdigest()

    # ---- Origin / Referer -------------------------------------------------

    def origin_allowed(self, origin: str, host_header: str) -> bool:
        """同源（相对 Host 头）或显式可信子域才放行。"""
        o = urlparse(origin)
        if not o.scheme or not o.netloc:
            return False
        if o.scheme in ("http", "https") and o.netloc == host_header:
            return True
        return any(match_origin_pattern(pat, origin) for pat in self.trusted_origins)

    def check_csrf(self, *, method, origin, referer, host, sid,
                   cookie_token, presented_token):
        """返回 (ok, reason)。所有失败路径都给出可观测的原因。"""
        # 第二层：Origin / Referer
        if origin:
            if not self.origin_allowed(origin, host):
                return False, f"Origin 不可信: {origin}"
        elif referer:
            ref = urlparse(referer)
            ref_origin = f"{ref.scheme}://{ref.netloc}"
            if not self.origin_allowed(ref_origin, host):
                return False, f"Referer 来源不可信: {ref_origin}"
        else:
            # 安全兜底：缺失一律拒绝（宁可误伤，不可放行）
            return False, "缺少 Origin/Referer 头，按安全兜底策略拒绝"

        # 第一层：双重提交 Cookie + 会话绑定
        if not sid or not self.has_session(sid):
            return False, "无有效会话（会话 Cookie 缺失或已失效）"
        if not cookie_token or not presented_token:
            return False, "CSRF token 缺失（Cookie 与请求头/表单字段均需携带）"
        expected = self.csrf_token_for(sid)
        if not hmac.compare_digest(cookie_token, expected):
            return False, "Cookie 中的 token 与当前会话不匹配（疑似 token 固定攻击）"
        if not hmac.compare_digest(presented_token, expected):
            return False, "提交的 token 与 Cookie 中的 token 不一致"
        return True, "ok"


# ---------------------------------------------------------------------------
# HTTP 层
# ---------------------------------------------------------------------------

def make_handler(app: CSRFApp):
    class Handler(BaseHTTPRequestHandler):
        server_version = "CSRFDemo/1.0"
        protocol_version = "HTTP/1.1"

        # -- 工具 ----------------------------------------------------------

        def log_message(self, fmt, *args):  # 保持测试输出干净
            pass

        def _send(self, code, body: bytes, content_type, extra_headers=None):
            self.send_response(code)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            for k, v in (extra_headers or []):
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def _send_json(self, code, obj, extra_headers=None):
            self._send(code, json.dumps(obj, ensure_ascii=False).encode(),
                       "application/json; charset=utf-8", extra_headers)

        def _cookies(self):
            jar = SimpleCookie()
            raw = self.headers.get("Cookie")
            if raw:
                jar.load(raw)
            return jar

        def _session_cookie_headers(self, sid):
            token = app.csrf_token_for(sid)
            return [
                # 会话 Cookie：HttpOnly + SameSite=Lax（第一道防线）
                ("Set-Cookie",
                 f"{SESSION_COOKIE}={sid}; Path=/; HttpOnly; SameSite=Lax"),
                # token Cookie：JS 需读取，故不设 HttpOnly；SameSite=Lax
                ("Set-Cookie",
                 f"{CSRF_COOKIE}={token}; Path=/; SameSite=Lax"),
            ]

        def _read_body(self):
            length = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(length) if length else b""
            ctype = (self.headers.get("Content-Type") or "").split(";")[0].strip()
            if ctype == "application/json":
                try:
                    return json.loads(raw.decode() or "{}")
                except json.JSONDecodeError:
                    return {}
            return {k: v[0] for k, v in parse_qs(raw.decode()).items()}

        def _current_sid(self):
            morsel = self._cookies().get(SESSION_COOKIE)
            return morsel.value if morsel else None

        # -- 路由 ----------------------------------------------------------

        def do_GET(self):
            path = urlparse(self.path).path
            if path == "/":
                self._serve_static("index.html")
            elif path == "/api/session":
                self._handle_session()
            elif path == "/api/whoami":
                self._handle_whoami()
            elif path == "/api/submissions":
                with app.lock:
                    data = list(app.submissions)
                self._send_json(200, {"submissions": data})
            elif path.startswith("/static/"):
                self._serve_static(path[len("/static/"):])
            else:
                self._send_json(404, {"error": "not found"})

        def do_POST(self):
            path = urlparse(self.path).path
            if path == "/api/submit":
                self._handle_submit()
            elif path == "/api/session/rotate":
                self._handle_rotate()
            else:
                self._send_json(404, {"error": "not found"})

        # -- 处理器 --------------------------------------------------------

        def _serve_static(self, rel):
            target = (STATIC_DIR / rel).resolve()
            if not str(target).startswith(str(STATIC_DIR)) or not target.is_file():
                self._send_json(404, {"error": "not found"})
                return
            ctype = CONTENT_TYPES.get(target.suffix, "application/octet-stream")
            self._send(200, target.read_bytes(), ctype)

        def _handle_session(self):
            sid = self._current_sid()
            if not sid or not app.has_session(sid):
                sid = app.new_session()
            token = app.csrf_token_for(sid)
            self._send_json(200, {"csrf_token": token},
                            self._session_cookie_headers(sid))

        def _handle_whoami(self):
            # 用于 SameSite 演示：顶级导航 GET 会带 Cookie，跨站 POST 不会
            sid = self._current_sid()
            self._send_json(200, {
                "session_cookie_present": bool(sid and app.has_session(sid)),
                "note": "SameSite=Lax 下，顶级导航 GET 会携带会话 Cookie；跨站 POST 不会",
            })

        def _handle_rotate(self):
            old = self._current_sid()
            sid = app.rotate_session(old) if old else app.new_session()
            self._send_json(200, {"csrf_token": app.csrf_token_for(sid)},
                            self._session_cookie_headers(sid))

        def _handle_submit(self):
            body = self._read_body()
            jar = self._cookies()
            cookie_token = jar[CSRF_COOKIE].value if jar.get(CSRF_COOKIE) else None
            presented = (self.headers.get(CSRF_HEADER)
                         or body.get(CSRF_BODY_FIELD))
            ok, reason = app.check_csrf(
                method="POST",
                origin=self.headers.get("Origin"),
                referer=self.headers.get("Referer"),
                host=self.headers.get("Host", ""),
                sid=self._current_sid(),
                cookie_token=cookie_token,
                presented_token=presented,
            )
            if not ok:
                self._send_json(403, {"ok": False, "blocked": True, "reason": reason})
                return
            name = str(body.get("name", ""))[:100]
            message = str(body.get("message", ""))[:1000]
            if not name or not message:
                self._send_json(400, {"ok": False, "reason": "name 与 message 不能为空"})
                return
            with app.lock:
                app.submissions.append(
                    {"name": name, "message": message, "ts": time.time()})
            self._send_json(200, {"ok": True, "echo": {"name": name, "message": message}})

    return Handler


def create_server(host="127.0.0.1", port=8000, *, secret=None, trusted_origins=None):
    app = CSRFApp(secret=secret, trusted_origins=trusted_origins)
    httpd = ThreadingHTTPServer((host, port), make_handler(app))
    httpd.app = app  # 测试可直接访问应用状态
    return httpd


def main():
    import sys
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
    # 演示：显式信任一个子域通配（nip.io 通配 DNS，可真实访问）
    httpd = create_server(port=port, trusted_origins=[
        "http://*.127.0.0.1.nip.io:8000",
    ])
    print(f"主服务已启动:  http://127.0.0.1:{port}")
    print(f"可信子域示例:  http://app.127.0.0.1.nip.io:{port}")
    print("攻击者站点请另开终端运行: python3 attacker_server.py")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
