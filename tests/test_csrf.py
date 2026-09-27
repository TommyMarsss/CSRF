"""CSRF 防护自动化测试：通过真实 HTTP 请求验证各防护层。

运行: python3 -m unittest discover -s tests -v
"""

import http.client
import json
import sys
import threading
import unittest
from http.cookies import SimpleCookie
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import server as app_server  # noqa: E402
from csrf import CSRFProtection  # noqa: E402


def parse_set_cookies(msg):
    """Set-Cookie 列表 -> {name: value}"""
    jar = {}
    for sc in msg.get_all("Set-Cookie") or []:
        c = SimpleCookie()
        c.load(sc)
        for name, morsel in c.items():
            jar[name] = morsel.value
    return jar


class SimulatedBrowser:
    """模拟浏览器在 SameSite=Lax 下的 Cookie 发送策略。

    - 同站请求：始终携带 Cookie；
    - 跨站请求：Lax 仅在“顶级导航 + 安全方法(GET/HEAD)”时携带，跨站 POST 不携带。
    """

    def __init__(self):
        self.cookies = {}  # name -> {"value": str, "samesite": str}

    def store(self, set_cookie_headers):
        for sc in set_cookie_headers:
            c = SimpleCookie()
            c.load(sc)
            for name, morsel in c.items():
                self.cookies[name] = {
                    "value": morsel.value,
                    # 现代浏览器对未显式声明 SameSite 的 Cookie 默认按 Lax 处理
                    "samesite": (morsel["samesite"] or "Lax").lower(),
                }

    def cookies_for(self, method, same_site, top_level):
        sent = {}
        for name, c in self.cookies.items():
            if same_site:
                sent[name] = c["value"]
            elif (c["samesite"] == "lax" and top_level
                    and method.upper() in ("GET", "HEAD")):
                sent[name] = c["value"]
            # Strict：跨站一律不发送；Lax 跨站 POST：不发送
        return sent


class CSRFHttpTest(unittest.TestCase):
    """对真实运行的服务发起 HTTP 请求。"""

    @classmethod
    def setUpClass(cls):
        cls.httpd = app_server.make_server(
            "127.0.0.1", 0, trusted_hosts=("trusted.example",))
        cls.port = cls.httpd.server_address[1]
        cls.host = f"127.0.0.1:{cls.port}"
        cls.origin = f"http://{cls.host}"
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.thread.join(timeout=5)

    # ---- helpers ----

    def request(self, method, path, body=None, headers=None, cookies=None):
        hdrs = dict(headers or {})
        if cookies:
            hdrs["Cookie"] = "; ".join(f"{k}={v}" for k, v in cookies.items())
        if isinstance(body, (dict, list)):
            body = json.dumps(body)
            hdrs.setdefault("Content-Type", "application/json")
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        conn.request(method, path, body=body, headers=hdrs)
        resp = conn.getresponse()
        raw = resp.read()
        raw_set_cookies = resp.msg.get_all("Set-Cookie") or []
        conn.close()
        try:
            data = json.loads(raw)
        except ValueError:
            data = raw.decode("utf-8", "replace")
        return resp.status, data, parse_set_cookies(resp.msg), raw_set_cookies

    def new_session(self):
        """领取会话 + token，返回 (cookies, token)。"""
        status, data, cookies, _ = self.request("GET", "/api/token")
        self.assertEqual(status, 200)
        return cookies, data["token"]

    def submit(self, cookies, token=None, extra_headers=None, cookie_token=None):
        jar = dict(cookies)
        if cookie_token is not None:
            jar["csrf_token"] = cookie_token
        headers = {"Origin": self.origin}
        if token is not None:
            headers["X-CSRF-Token"] = token
        if extra_headers:
            headers.update(extra_headers)
        return self.request("POST", "/api/submit",
                            body={"name": "n", "message": "m"},
                            headers=headers, cookies=jar)

    # ---- 核心场景 ----

    def test_legit_same_origin_submit(self):
        """合法同源提交成功。"""
        cookies, token = self.new_session()
        status, data, _, _ = self.submit(cookies, token)
        self.assertEqual(status, 200)
        self.assertTrue(data["ok"])

    def test_token_cookie_mismatch_rejected(self):
        """请求头 token 与 Cookie token 不一致被拒绝。"""
        cookies, token = self.new_session()
        status, data, _, _ = self.submit(cookies, token,
                                         cookie_token="AAAA.forged")
        self.assertEqual(status, 403)
        self.assertIn("不一致", data["reason"])

    def test_cross_site_origin_rejected(self):
        """跨站 Origin 被拒绝。"""
        cookies, token = self.new_session()
        status, data, _, _ = self.submit(
            cookies, token, extra_headers={"Origin": "http://evil.example"})
        self.assertEqual(status, 403)
        self.assertIn("Origin", data["reason"])

    def test_token_fixation_rejected(self):
        """token 固定变体：攻击者自己会话的 token + 受害者 Cookie 被拒绝。"""
        _, attacker_token = self.new_session()       # 攻击者会话的 token
        victim_cookies, _ = self.new_session()       # 受害者会话
        # Cookie 与请求头都用攻击者 token（双重提交比对通过），但绑定校验必须失败
        status, data, _, _ = self.submit(victim_cookies, attacker_token,
                                         cookie_token=attacker_token)
        self.assertEqual(status, 403)
        self.assertIn("未绑定", data["reason"])

    def test_missing_origin_and_referer_rejected(self):
        """Origin 与 Referer 都缺失时按安全兜底拒绝。"""
        cookies, token = self.new_session()
        status, data, _, _ = self.request(
            "POST", "/api/submit", body={"a": 1},
            headers={"X-CSRF-Token": token}, cookies=cookies)
        self.assertEqual(status, 403)
        self.assertIn("缺少 Origin", data["reason"])

    def test_missing_token_rejected(self):
        """缺少自定义头 token 被拒绝（经典 CSRF 表单即死于此）。"""
        cookies, _ = self.new_session()
        status, data, _, _ = self.submit(cookies, None)
        self.assertEqual(status, 403)
        self.assertIn("缺少双重提交", data["reason"])

    def test_stale_token_after_rotation_rejected(self):
        """token 轮换后旧 token 失效，新 token 仍可用。"""
        cookies, old_token = self.new_session()
        status, data, new_cookies, _ = self.request("GET", "/api/token",
                                                    cookies=cookies)
        self.assertEqual(status, 200)
        new_token = data["token"]
        cookies.update(new_cookies)
        # Cookie 与请求头都用旧 token（双重提交比对通过），但 nonce 已轮换
        status, data, _, _ = self.submit(cookies, old_token,
                                         cookie_token=old_token)
        self.assertEqual(status, 403)
        self.assertIn("轮换", data["reason"])
        # 新 token 正常工作
        status, data, _, _ = self.submit(cookies, new_token)
        self.assertEqual(status, 200)

    # ---- Origin/Referer 边界 ----

    def test_trusted_subdomain_origin_allowed(self):
        """显式配置的可信子域放行。"""
        cookies, token = self.new_session()
        status, _, _, _ = self.submit(
            cookies, token,
            extra_headers={"Origin": "http://api.trusted.example"})
        self.assertEqual(status, 200)

    def test_untrusted_subdomain_origin_rejected(self):
        cookies, token = self.new_session()
        status, _, _, _ = self.submit(
            cookies, token,
            extra_headers={"Origin": "http://evil.untrusted.example"})
        self.assertEqual(status, 403)

    def test_suffix_lookalike_origin_rejected(self):
        """evil-trusted.example 这类相似后缀不能绕过子域匹配。"""
        cookies, token = self.new_session()
        status, _, _, _ = self.submit(
            cookies, token,
            extra_headers={"Origin": "http://evil-trusted.example"})
        self.assertEqual(status, 403)

    def test_referer_fallback_when_origin_absent(self):
        """无 Origin 时回退校验 Referer：可信放行、不可信拒绝。"""
        cookies, token = self.new_session()
        headers = {"X-CSRF-Token": token, "Referer": self.origin + "/page"}
        status, _, _, _ = self.request("POST", "/api/submit", body={"a": 1},
                                       headers=headers, cookies=cookies)
        self.assertEqual(status, 200)
        headers["Referer"] = "http://evil.example/page"
        status, _, _, _ = self.request("POST", "/api/submit", body={"a": 1},
                                       headers=headers, cookies=cookies)
        self.assertEqual(status, 403)

    # ---- SameSite=Lax 交互边界（模拟浏览器） ----

    def test_samesite_lax_top_level_get_sends_cookies(self):
        """SameSite=Lax：跨站顶级导航 GET 仍携带 Cookie（放行）。"""
        browser = SimulatedBrowser()
        _, _, _, raw_sc = self.request("GET", "/api/token")
        browser.store(raw_sc)
        sent = browser.cookies_for("GET", same_site=False, top_level=True)
        self.assertIn("session_id", sent)
        status, _, _, _ = self.request("GET", "/", cookies=sent)
        self.assertEqual(status, 200)

    def test_samesite_lax_cross_site_post_withholds_cookies(self):
        """SameSite=Lax：跨站 POST 不携带 Cookie，服务端因无会话拒绝。"""
        browser = SimulatedBrowser()
        _, _, _, raw_sc = self.request("GET", "/api/token")
        browser.store(raw_sc)
        sent = browser.cookies_for("POST", same_site=False, top_level=True)
        self.assertEqual(sent, {})  # Lax 下跨站 POST 一个 Cookie 都不带
        status, data, _, _ = self.request(
            "POST", "/api/submit", body={"a": 1},
            headers={"Origin": "http://evil.example"}, cookies=sent)
        self.assertEqual(status, 403)

    def test_defense_in_depth_when_samesite_bypassed(self):
        """纵深防御：即使 SameSite 被绕过（Cookie 被带上），
        Origin 校验与 token 绑定仍会拦截。"""
        cookies, token = self.new_session()
        # 场景 A：Cookie 带上了，但 Origin 不可信 -> 第一层拦截
        status, _, _, _ = self.submit(
            cookies, token, extra_headers={"Origin": "http://evil.example"})
        self.assertEqual(status, 403)
        # 场景 B：Origin 同源（如可信子域被 XSS 攻陷场景之外的情况），
        # 但攻击者只有自己会话的 token -> 第三层绑定拦截
        _, attacker_token = self.new_session()
        status, _, _, _ = self.submit(cookies, attacker_token,
                                      cookie_token=attacker_token)
        self.assertEqual(status, 403)


class CSRFCoreTest(unittest.TestCase):
    """不依赖 HTTP 的核心逻辑单元测试。"""

    def test_token_binding(self):
        p = CSRFProtection(secret=b"test-secret")
        t = p.issue_token("session-a")
        self.assertTrue(p.token_bound_to("session-a", t))
        self.assertFalse(p.token_bound_to("session-b", t))
        self.assertFalse(p.token_bound_to("session-a", "garbage"))
        self.assertFalse(p.token_bound_to("session-a", "a.b.c"))

    def test_origin_rules(self):
        p = CSRFProtection(secret=b"x", trusted_hosts=("example.com",))
        self.assertTrue(p.origin_allowed("http://localhost:8000",
                                         "localhost:8000"))
        self.assertTrue(p.origin_allowed("https://api.example.com",
                                         "localhost:8000"))
        self.assertTrue(p.origin_allowed("https://example.com",
                                         "localhost:8000"))
        self.assertFalse(p.origin_allowed("https://evil-example.com",
                                          "localhost:8000"))
        self.assertFalse(p.origin_allowed("https://example.com.evil.io",
                                          "localhost:8000"))
        self.assertFalse(p.origin_allowed(None, "localhost:8000"))
        self.assertFalse(p.origin_allowed("", "localhost:8000"))
        self.assertFalse(p.origin_allowed("javascript:alert(1)",
                                          "localhost:8000"))


if __name__ == "__main__":
    unittest.main()
