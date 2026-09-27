"""CSRF 防护核心逻辑（仅标准库）。

防护分层：
  第一层  Origin / Referer 校验：同源或显式可信（子）域才放行；两者都缺失时拒绝。
  第二层  会话 Cookie：SameSite=Lax 下跨站 POST 通常根本不携带会话 Cookie。
  第三层  双重提交 Cookie + 会话绑定 token：
          - Cookie 中的 token 与自定义头（X-CSRF-Token）中的 token 必须一致；
          - token = nonce + "." + HMAC_SHA256(secret, session_id + "." + nonce)，
            与服务器端会话密码学绑定 —— 攻击者自己会话签发的 token 无法通过
            受害者会话的校验，免疫 token 固定（token fixation）变体；
          - 服务端会话记录当前 nonce，签发新 token 即轮换，旧 token 立即失效。
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import threading
import time
from urllib.parse import urlparse

SESSION_COOKIE = "session_id"
CSRF_COOKIE = "csrf_token"
CSRF_HEADER = "x-csrf-token"  # 头名大小写不敏感，内部统一小写

SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
SESSION_TTL = 3600  # 秒


class SessionStore:
    """进程内会话存储（演示用；生产环境应使用共享存储如 Redis）。"""

    def __init__(self, ttl: int = SESSION_TTL):
        self.ttl = ttl
        self._sessions: dict[str, dict] = {}
        self._lock = threading.Lock()

    def create(self) -> str:
        sid = secrets.token_urlsafe(32)
        with self._lock:
            self._sessions[sid] = {"created": time.time(), "nonce": None}
        return sid

    def get(self, sid: str) -> dict | None:
        with self._lock:
            sess = self._sessions.get(sid)
            if sess is None:
                return None
            if time.time() - sess["created"] > self.ttl:
                del self._sessions[sid]
                return None
            return sess

    def set_nonce(self, sid: str, nonce: str) -> None:
        with self._lock:
            sess = self._sessions.get(sid)
            if sess is not None:
                sess["nonce"] = nonce


class CSRFProtection:
    def __init__(self, secret: bytes | None = None, trusted_hosts=()):
        # secret 为进程级随机值；生产环境应从密钥管理系统/环境变量注入
        self.secret = secret or secrets.token_bytes(32)
        # trusted_hosts: 显式可信的（子）域名，如 ("example.com",) 放行 api.example.com
        self.trusted_hosts = tuple(h.lower() for h in trusted_hosts)

    # ---- token：双重提交 + 会话绑定 ----

    def _mac(self, session_id: str, nonce: str) -> str:
        return hmac.new(
            self.secret, f"{session_id}.{nonce}".encode(), hashlib.sha256
        ).hexdigest()

    def issue_token(self, session_id: str) -> str:
        nonce = secrets.token_urlsafe(16)
        return f"{nonce}.{self._mac(session_id, nonce)}"

    def token_bound_to(self, session_id: str, token: str) -> bool:
        """token 的 HMAC 是否对应该会话（不检查 nonce 轮换）。"""
        try:
            nonce, mac = token.split(".", 1)
        except ValueError:
            return False
        if not nonce or not mac:
            return False
        return hmac.compare_digest(self._mac(session_id, nonce), mac)

    # ---- Origin / Referer ----

    def host_allowed(self, host: str, self_host: str) -> bool:
        host = host.lower()
        if host == self_host.lower():
            return True
        hostname = host.split(":", 1)[0]
        for trusted in self.trusted_hosts:
            if hostname == trusted or hostname.endswith("." + trusted):
                return True
        return False

    def origin_allowed(self, origin: str | None, self_host: str) -> bool:
        if not origin:
            return False
        parsed = urlparse(origin)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            return False
        return self.host_allowed(parsed.netloc, self_host)

    # ---- 完整校验链 ----

    def verify(self, sessions: SessionStore, method: str,
               headers: dict, cookies: dict, self_host: str):
        """对状态变更请求执行三层校验。

        headers 为小写头名 dict，cookies 为 dict。返回 (ok, reason)。
        """
        if method.upper() in SAFE_METHODS:
            return True, "安全方法，无需 CSRF 校验"

        # 第一层：Origin / Referer
        origin = headers.get("origin")
        referer = headers.get("referer")
        if origin:
            if not self.origin_allowed(origin, self_host):
                return False, f"第一层拦截：Origin 不可信（{origin}）"
        elif referer:
            parsed = urlparse(referer)
            ref_origin = f"{parsed.scheme}://{parsed.netloc}"
            if not self.origin_allowed(ref_origin, self_host):
                return False, f"第一层拦截：Referer 不可信（{referer}）"
        else:
            return False, "第一层拦截：缺少 Origin 与 Referer，按安全兜底拒绝"

        # 第二层：会话 Cookie（SameSite=Lax 下跨站 POST 通常在这里就失败了）
        sid = cookies.get(SESSION_COOKIE)
        if not sid or sessions.get(sid) is None:
            return False, "第二层拦截：缺少有效会话 Cookie"

        # 第三层：双重提交 + 会话绑定 + 轮换
        cookie_token = cookies.get(CSRF_COOKIE)
        header_token = headers.get(CSRF_HEADER)
        if not cookie_token or not header_token:
            return False, "第三层拦截：缺少双重提交 token（Cookie 或自定义头缺失）"
        if not hmac.compare_digest(cookie_token, header_token):
            return False, "第三层拦截：Cookie 与请求头中的 token 不一致"
        if not self.token_bound_to(sid, header_token):
            return False, "第三层拦截：token 未绑定当前会话（疑似 token 固定攻击）"
        nonce = header_token.split(".", 1)[0]
        sess = sessions.get(sid)
        if sess is None or sess.get("nonce") != nonce:
            return False, "第三层拦截：token 已轮换，旧 token 失效"
        return True, "校验通过：Origin 可信 + 双重提交一致 + token 绑定当前会话"
