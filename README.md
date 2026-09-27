# CSRF 防护演示（纯标准库 + 原生前端）

一个真实前后端联调的表单提交服务，**不依赖任何框架与第三方库**手工实现 CSRF 防护：

- 后端：Python 标准库（`http.server` / `hmac` / `secrets`），`server.py`
- 前端：原生 HTML/CSS/JavaScript，`static/`
- 攻击者模拟站点：`attacker_server.py`（独立端口，构成真实跨站环境）
- 自动化测试：`tests/test_csrf.py`（20 个用例，真实 HTTP 请求）

## 快速开始

```bash
python3 server.py            # 主服务  http://127.0.0.1:8000
python3 attacker_server.py   # 攻击者  http://localhost:9000 （另开终端）
python3 -m unittest discover -s tests -v   # 运行测试
```

打开 `http://127.0.0.1:8000`：左侧正常提交留言，右侧五个按钮真实触发各类攻击并展示拦截原因。打开 `http://localhost:9000` 可查看 SameSite 边界对比演示（顶级导航 GET vs 跨站 POST）。

> 演示特意用 `127.0.0.1`（主服务）与 `localhost`（攻击者）两个 host：它们是**不同 site**，浏览器会真实地执行 SameSite 与 Origin 语义，无需任何 mock。

## 防护分层策略

### 第一层：SameSite=Lax 会话 Cookie（浏览器侧闸门）

```
Set-Cookie: session_id=...; Path=/; HttpOnly; SameSite=Lax
Set-Cookie: csrf_token=...; Path=/; SameSite=Lax
```

- 跨站 **POST**（如攻击者页面的自动提交表单）：浏览器**不附带**这两个 Cookie → 服务端连会话都看不到，直接 403。
- 顶级导航 **GET**（用户点击链接跳转）：Lax 放行 Cookie → 正常可用，不影响用户体验。
- 会话 Cookie 为 `HttpOnly`（防 XSS 窃取）；token Cookie 必须可被 JS 读取（双重提交需要），但它本身不含敏感信息——没有对应的会话 Cookie 它毫无用处。

### 第二层：双重提交 Cookie + 会话绑定 token

token 不是随机数直接下发，而是：

```
csrf_token = HMAC-SHA256(server_secret, "csrf:" + session_id)
```

校验要求三者一致（`hmac.compare_digest` 防时序攻击）：

```
Cookie 中的 token  ==  请求头 X-CSRF-Token（或表单字段）  ==  HMAC(secret, 当前会话 sid)
```

- **经典 CSRF** 失败：攻击者页面读不到受害者的 token Cookie（同源策略），无法构造第二份。
- **Token 固定（token fixation）变体**失败：攻击者用*自己会话*换来的合法 token 是 `HMAC(secret, attacker_sid)`，与受害者会话的期望值 `HMAC(secret, victim_sid)` 必然不同。即使攻击者能通过子域 XSS 或 Cookie 投掷把*自己那份 token* 写进受害者的 Cookie jar，它也对不上受害者的会话。这是纯随机双重提交方案的经典漏洞，会话绑定（HMAC）将其堵死。
- token 无状态：服务端不存 token 表，重启换密钥即全部失效。

### 第三层：Origin / Referer 校验

对所有状态变更请求（POST）：

1. 有 `Origin` → 必须命中白名单：**同源**（相对请求 `Host` 头）或**显式配置的可信子域**（支持 `https://*.example.com` 通配，严格校验 scheme/host/port，拒绝 `example.com.evil.io` 这类形似域名）。
2. 无 `Origin` 但有 `Referer` → 提取其 origin 做同样校验（兼容旧浏览器）。
3. **两者都缺失 → 拒绝**（安全兜底，不放行）。curl/脚本类客户端会被误伤，但对表单服务而言这是正确取舍。

## SameSite 边界与本机制的交互

| 场景 | SameSite=Lax 行为 | 本服务的最终结果 |
|---|---|---|
| 顶级导航 GET（点链接进来） | 附带 Cookie | 正常（GET 本就不做状态变更） |
| 跨站 POST 表单/fetch | **不附** Cookie | 403：无有效会话 |
| 跨站 POST 且 Cookie 被放行（如 Lax+2 分钟宽限、或显式 SameSite=None 的遗留 Cookie） | 可能附带 | 仍被 token 层 + Origin 层拦截 |
| 同 site 跨 origin（如 `a.example.com` → `b.example.com`） | 附带 Cookie | 依赖 Origin 白名单拦截——**SameSite 对子域间攻击无效**，这正是需要第二、三层的原因 |

结论：SameSite 是有价值的第一道闸门，但**不能单独依赖**——它不覆盖同 site 子域互攻、GET 型状态变更、以及 Lax 的各种边界情形。

## 已知局限

- **会话与提交数据存于内存**，重启即失；生产应换持久化存储。
- **无 HTTPS**：本地演示用明文 HTTP。生产必须 HTTPS，否则 Cookie 可被网络中间人窃取/改写（且应加 `Secure` 属性、考虑 `__Host-` 前缀）。
- **token 不轮换、无过期**：演示中 token 随会话生命周期有效。更高安全级别可加入时间戳/nonce 并定期轮换（`POST /api/session/rotate` 演示了轮换使旧 token 立即失效）。
- **Origin 缺失即拒绝**对非浏览器客户端不友好；真实 API 通常改用 Bearer token 认证（无 Cookie 即无 CSRF）。
- **GET 请求未做防护**：本服务所有状态变更都走 POST。切勿在 GET 上实现状态变更，否则 SameSite=Lax 会放行跨站 GET 导航。
- **子域信任是攻击面**：任何可信子域被 XSS 攻陷，双重提交即被绕过（攻击者可读 token Cookie 并伪造头）。白名单应最小化。
- 内存会话表无淘汰机制，长期运行会缓慢增长（演示可接受）。

## 测试覆盖（`tests/test_csrf.py`，20 例）

| 类别 | 用例 |
|---|---|
| 合法路径 | 同源提交成功；`Set-Cookie` 属性断言（SameSite=Lax / HttpOnly 分布） |
| 双重提交 | token 与 Cookie 不一致 403；缺 token 头 403；篡改 token Cookie 403；**token 固定变体 403**；轮换后旧 token 403 |
| Origin/Referer | 跨站 Origin 403；Origin+Referer 双缺失兜底 403；同源 Referer 回退放行；可信子域放行；形似域名/错误端口 403 |
| SameSite 边界 | 顶级导航 GET 带 Cookie 正常；跨站 POST 无 Cookie 403（即使 token 泄漏）；无 Cookie 无 Origin 兜底 403 |
| 匹配引擎 | 通配子域正/反例、scheme/port 严格性 |
