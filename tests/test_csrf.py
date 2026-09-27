#!/usr/bin/env python3
"""CSRF 防护自动化测试 —— 仅标准库，真实 HTTP 请求。

运行： python3 -m unittest discover -s tests -v
"""

import http.client
import json
import threading
import unittest

from server import create_server, match_origin_pattern

SECRET = b"test-secret-key-for-csrf"
TRUSTED = ["https://*.example.com", "http://trusted.example.net:8443"]


class Client:
    """带 Cookie jar 的最小 HTTP 客户端，可精确控制每个请求头。"""

    def __init__(self, port):
        self.port = port
        self.cookies = {}

    def request(self, method, path, body=None, headers=None, use_cookies=True):
        hdrs = dict(headers or {})
        if use_cookies and self.cookies:
            hdrs["Cookie"] = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
        payload = None
        if body is not None:
            payload = json.dumps(body).encode()
            hdrs.setdefault("Content-Type", "application/json")
        conn = http.client.HTTPConnection("127.0.0.1", self.port)
        conn.request(method, path, body=payload, headers=hdrs)
        resp = conn.getresponse()
        raw = resp.read()
        for sc in resp.headers.get_all("Set-Cookie") or []:
            pair = sc.split(";")[0]
            k, _, v = pair.partition("=")
            self.cookies[k.strip()] = v.strip()
        conn.close()
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            data = raw.decode(errors="replace")
        return resp.status, data, dict(resp.headers.items())


class CSRFTestBase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.httpd = create_server(port=0, secret=SECRET, trusted_origins=TRUSTED)
        cls.port = cls.httpd.server_address[1]
        cls.origin = f"http://127.0.0.1:{cls.port}"
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()

    def new_client(self):
        c = Client(self.port)
        status, data, _ = c.request("GET", "/api/session")
        assert status == 200 and data["csrf_token"]
        return c

    def submit(self, client, token=None, extra_headers=None, use_cookies=True):
        headers = {"Origin": self.origin}
        if token is not None:
            headers["X-CSRF-Token"] = token
        headers.update(extra_headers or {})
        return client.request("POST", "/api/submit",
                              body={"name": "tester", "message": "hello"},
                              headers=headers, use_cookies=use_cookies)


class TestLegitSubmit(CSRFTestBase):
    def test_legit_same_origin_submit_succeeds(self):
        c = self.new_client()
        status, data, _ = self.submit(c, token=c.cookies["csrf_token"])
        self.assertEqual(status, 200)
        self.assertTrue(data["ok"])
        self.assertEqual(data["echo"]["name"], "tester")

    def test_set_cookie_has_samesite_lax(self):
        c = Client(self.port)
        _, _, headers = c.request("GET", "/api/session")
        # http.client 合并同名头时取最后一个，这里逐个检查原始响应
        conn = http.client.HTTPConnection("127.0.0.1", self.port)
        conn.request("GET", "/api/session")
        resp = conn.getresponse()
        resp.read()
        cookies = resp.headers.get_all("Set-Cookie")
        conn.close()
        self.assertTrue(any("SameSite=Lax" in sc for sc in cookies))
        self.assertTrue(any("HttpOnly" in sc and "session_id" in sc for sc in cookies))
        # token Cookie 不能是 HttpOnly（前端 JS 需要读取）
        self.assertTrue(any("csrf_token" in sc and "HttpOnly" not in sc for sc in cookies))


class TestDoubleSubmitCookie(CSRFTestBase):
    def test_token_cookie_mismatch_rejected(self):
        c = self.new_client()
        status, data, _ = self.submit(c, token="totally-wrong-token")
        self.assertEqual(status, 403)
        self.assertIn("不一致", data["reason"])

    def test_missing_token_header_rejected(self):
        c = self.new_client()
        status, data, _ = self.submit(c, token=None)
        self.assertEqual(status, 403)
        self.assertIn("缺失", data["reason"])

    def test_tampered_cookie_token_rejected(self):
        c = self.new_client()
        c.cookies["csrf_token"] = "forged-cookie-token"
        status, data, _ = self.submit(c, token="forged-cookie-token")
        self.assertEqual(status, 403)
        self.assertIn("不匹配", data["reason"])

    def test_token_fixation_rejected(self):
        """攻击者会话的 token + 受害者的 Cookie —— 必须拒绝。"""
        victim = self.new_client()
        attacker = self.new_client()  # 攻击者自己的合法会话与 token
        attacker_token = attacker.cookies["csrf_token"]
        self.assertNotEqual(attacker_token, victim.cookies["csrf_token"])
        # 攻击者诱骗受害者浏览器提交：带的是受害者 Cookie + 攻击者 token
        status, data, _ = self.submit(victim, token=attacker_token)
        self.assertEqual(status, 403)
        self.assertIn("不一致", data["reason"])

    def test_stale_token_after_rotation_rejected(self):
        c = self.new_client()
        old_token = c.cookies["csrf_token"]
        status, _, _ = c.request("POST", "/api/session/rotate")
        self.assertEqual(status, 200)
        self.assertNotEqual(c.cookies["csrf_token"], old_token)
        status, data, _ = self.submit(c, token=old_token)
        self.assertEqual(status, 403)


class TestOriginReferer(CSRFTestBase):
    def test_cross_site_origin_rejected(self):
        c = self.new_client()
        status, data, _ = self.submit(c, token=c.cookies["csrf_token"],
                                      extra_headers={"Origin": "http://evil.example"})
        self.assertEqual(status, 403)
        self.assertIn("Origin", data["reason"])

    def test_missing_origin_and_referer_rejected(self):
        """安全兜底：两者都缺失时拒绝而非放行。"""
        c = self.new_client()
        conn = http.client.HTTPConnection("127.0.0.1", self.port)
        body = json.dumps({"name": "t", "message": "m"})
        conn.request("POST", "/api/submit", body=body, headers={
            "Content-Type": "application/json",
            "Cookie": "; ".join(f"{k}={v}" for k, v in c.cookies.items()),
            "X-CSRF-Token": c.cookies["csrf_token"],
        })
        resp = conn.getresponse()
        data = json.loads(resp.read())
        conn.close()
        self.assertEqual(resp.status, 403)
        self.assertIn("兜底", data["reason"])

    def test_valid_referer_fallback_accepted(self):
        """Origin 缺失但 Referer 同源时放行（浏览器旧行为兼容）。"""
        c = self.new_client()
        headers = {"Referer": self.origin + "/form-page"}
        status, data, _ = self.submit(c, token=c.cookies["csrf_token"],
                                      extra_headers=headers)
        # submit() 默认带 Origin，这里显式移除以走 Referer 分支
        # —— 重新发一个不带 Origin 的请求：
        conn = http.client.HTTPConnection("127.0.0.1", self.port)
        body = json.dumps({"name": "t", "message": "m"})
        conn.request("POST", "/api/submit", body=body, headers={
            "Content-Type": "application/json",
            "Cookie": "; ".join(f"{k}={v}" for k, v in c.cookies.items()),
            "X-CSRF-Token": c.cookies["csrf_token"],
            "Referer": self.origin + "/form-page",
        })
        resp = conn.getresponse()
        data = json.loads(resp.read())
        conn.close()
        self.assertEqual(resp.status, 200, data)
        self.assertTrue(data["ok"])

    def test_untrusted_subdomain_rejected(self):
        c = self.new_client()
        status, data, _ = self.submit(c, token=c.cookies["csrf_token"],
                                      extra_headers={"Origin": "https://evil.example.com.evil.io"})
        self.assertEqual(status, 403)

    def test_trusted_subdomain_allowed(self):
        c = self.new_client()
        status, data, _ = self.submit(c, token=c.cookies["csrf_token"],
                                      extra_headers={"Origin": "https://app.example.com"})
        self.assertEqual(status, 200, data)

    def test_trusted_origin_wrong_port_rejected(self):
        c = self.new_client()
        status, _, _ = self.submit(c, token=c.cookies["csrf_token"],
                                   extra_headers={"Origin": "http://trusted.example.net:9999"})
        self.assertEqual(status, 403)

    def test_trusted_origin_right_port_allowed(self):
        c = self.new_client()
        status, data, _ = self.submit(c, token=c.cookies["csrf_token"],
                                      extra_headers={"Origin": "http://trusted.example.net:8443"})
        self.assertEqual(status, 200, data)


class TestSameSiteBoundary(CSRFTestBase):
    """模拟 SameSite=Lax 的浏览器行为边界（Cookie 是否附带由浏览器决定，
    测试通过“是否发送 Cookie”来模拟两种场景）。"""

    def test_toplevel_navigation_get_with_cookies_ok(self):
        """顶级导航 GET：Lax 放行 Cookie —— whoami 应看到会话。"""
        c = self.new_client()
        status, data, _ = c.request("GET", "/api/whoami")
        self.assertEqual(status, 200)
        self.assertTrue(data["session_cookie_present"])

    def test_cross_site_post_without_cookies_rejected(self):
        """跨站 POST：Lax 不附 Cookie —— 即使 token 被猜中/泄漏也无会话可用。"""
        victim = self.new_client()
        leaked_token = victim.cookies["csrf_token"]
        # 模拟浏览器在跨站 POST 中剥离 SameSite=Lax Cookie
        c2 = Client(self.port)  # 全新空 jar
        status, data, _ = c2.request(
            "POST", "/api/submit",
            body={"name": "evil", "message": "csrf"},
            headers={"Origin": "http://evil.example",
                     "X-CSRF-Token": leaked_token},
            use_cookies=False)
        self.assertEqual(status, 403)
        # 被 Origin 层拦截
        self.assertIn("Origin", data["reason"])

    def test_cross_site_post_no_cookies_no_origin_rejected(self):
        """跨站 POST 且连 Origin 都没有（如某些导航场景）：兜底拒绝。"""
        victim = self.new_client()
        c2 = Client(self.port)
        status, data, _ = c2.request(
            "POST", "/api/submit",
            body={"name": "evil", "message": "csrf",
                  "csrf_token": victim.cookies["csrf_token"]},
            use_cookies=False)
        self.assertEqual(status, 403)


class TestOriginPatternMatching(unittest.TestCase):
    def test_wildcard_matches_subdomain(self):
        self.assertTrue(match_origin_pattern("https://*.example.com", "https://a.example.com"))
        self.assertTrue(match_origin_pattern("https://*.example.com", "https://a.b.example.com"))

    def test_wildcard_rejects_bare_domain_and_lookalikes(self):
        self.assertFalse(match_origin_pattern("https://*.example.com", "https://example.com"))
        self.assertFalse(match_origin_pattern("https://*.example.com", "https://example.com.evil.io"))
        self.assertFalse(match_origin_pattern("https://*.example.com", "https://notexample.com"))

    def test_scheme_and_port_must_match(self):
        self.assertFalse(match_origin_pattern("https://*.example.com", "http://a.example.com"))
        self.assertTrue(match_origin_pattern("http://x.example.com:8443", "http://x.example.com:8443"))
        self.assertFalse(match_origin_pattern("http://x.example.com:8443", "http://x.example.com:443"))


if __name__ == "__main__":
    unittest.main()
