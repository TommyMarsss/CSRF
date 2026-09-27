# CSRF 防护演示（纯标准库后端 + 原生前端）

一个真实前后端联调的表单提交服务，**不依赖任何框架与第三方库**（后端仅 Python 标准库，
前端仅原生 HTML/CSS/JavaScript），自行实现分层 CSRF 防护，并附带攻击模拟与自动化测试。

## 运行

```bash
python3 server.py            # 主应用 :8000，攻击者站 :8001
python3 server.py 9000 9001  # 自定义端口
```

- 主应用：http://localhost:8000/ —— 正常表单、攻击模拟按钮、实时拦截日志
- 攻击者站：http://localhost:8001/ —— 模拟跨站攻击页面（独立端口 = 独立 Origin）

## 测试

```bash
python3 -m unittest discover -s tests -v
```

16 个测试全部通过真实 HTTP 请求验证，覆盖：

| 场景 | 预期 |
|---|---|
| 合法同源提交 | 200 放行 |
| 请求头 token 与 Cookie token 不一致 | 403 |
| 跨站 Origin | 403 |
| token 固定（攻击者会话 token + 受害者 Cookie） | 403 |
| Origin/Referer 均缺失 | 403（安全兜底） |
| 缺少自定义头 token（经典 CSRF 表单） | 403 |
| token 轮换后旧 token | 403，新 token 仍可用 |
| 可信子域 Origin / 相似后缀域名 | 放行 / 拒绝 |
| 无 Origin 时 Referer 回退 | 可信放行、不可信拒绝 |
| SameSite=Lax 顶级导航 GET / 跨站 POST | 携带 Cookie / 不携带 |
| SameSite 被绕过时的纵深防御 | 后续层仍拦截 |

## 防护分层策略

```
请求 → 第一层 Origin/Referer → 第二层 会话 Cookie → 第三层 双重提交+会话绑定 token → 业务
```

**第一层：Origin / Referer 校验**（`CSRFProtection.verify`）
- 非安全方法（POST 等）必须携带可信 `Origin`：同源（与 Host 一致）或显式配置的
  可信（子）域名（`trusted_hosts`，如 `example.com` 放行 `api.example.com`，
  但 `evil-example.com`、`example.com.evil.io` 均被拒绝）。
- `Origin` 缺失时回退校验 `Referer` 的来源。
- 两者都缺失时**拒绝而非放行**（安全兜底）。

**第二层：会话 Cookie**
- `session_id`：`HttpOnly; SameSite=Lax`。SameSite=Lax 下跨站 POST 根本不携带
  会话 Cookie，多数经典 CSRF 在此层即失效。

**第三层：双重提交 Cookie + 会话绑定 token**
- token 格式：`nonce.HMAC_SHA256(secret, session_id + "." + nonce)`，
  同时通过 `csrf_token` Cookie（非 HttpOnly，前端 JS 可读）和
  `X-CSRF-Token` 自定义头提交，两者必须一致。
- token 与**服务端会话密码学绑定**：攻击者用自己会话换取的 token，
  在受害者会话下 HMAC 校验必然失败 —— 免疫 **token 固定（fixation）变体**
  （攻击者下发自己 token 搭配受害者 Cookie 的攻击）。
- 服务端会话记录当前 nonce，每次 `/api/token` 签发即**轮换**，旧 token 立即失效。

## SameSite 边界与本机制的交互

测试中的 `SimulatedBrowser` 实现了 SameSite=Lax 的 Cookie 发送策略，用于精确演示边界：

| 场景 | Lax 是否携带 Cookie | 结果 |
|---|---|---|
| 同站请求 | 是 | 进入 token 校验 |
| 跨站顶级导航 GET | 是（Lax 的放行口） | GET 属安全方法，无需 CSRF 校验 |
| 跨站 POST（含 iframe 表单） | 否 | 服务端看不到会话，直接拒绝 |

要点：

- **SameSite 是浏览器侧防线，不是服务端可依赖的唯一机制**。`localhost:8000` 与
  `localhost:8001` 属同一 site（site 不含端口），本机演示中跨站攻击页的 POST 实际
  **会**携带 Cookie —— 此时 Origin 校验与 token 绑定仍然拦截，体现纵深防御的价值。
- Lax 的“顶级导航 GET 放行”意味着：**绝不能用 GET 做状态变更**，否则该放行口
  就是漏洞。本服务所有状态变更只走 POST。
- 即使 SameSite 被绕过（旧浏览器、`SameSite=None` 的子域 XSS 等），
  第一、三层依然独立成立（见测试 `test_defense_in_depth_when_samesite_bypassed`）。

## 前端攻击模拟说明

主页面按钮均通过真实 HTTP 请求触发防护：

1. **轮换 token / 旧 token 提交** —— 演示 nonce 轮换使旧 token 失效；
2. **篡改 Cookie 中的 token** —— 演示双重提交一致性比对；
3. **token 固定攻击** —— 经 `/api/attacker-token`（演示专用接口）获取攻击者会话的
   token，搭配受害者 Cookie 提交，被会话绑定校验拒绝；
4. **不带 token 提交** —— 等价于经典 CSRF 表单（无法设置自定义头）；
5. **伪造 Origin** —— 浏览器禁止 JS 修改 `Origin`，页面给出等效 curl 命令；
6. **跨站攻击页**（:8001）—— 真实跨 Origin：iframe 自动提交表单、
   `fetch credentials:'include'`、内嵌攻击者 token 的 fixation 表单，
   拦截结果实时显示在主页面日志中。

## 已知局限

- **会话与密钥在进程内**：重启即失效，不适用于多实例部署；生产应使用共享会话
  存储与外部注入的密钥。
- **单 nonce 轮换**：同一时刻仅最新 token 有效，多标签页同时操作会互相踢掉
  （生产可改为 nonce 集合或滑动窗口）。
- **Referer 回退的弱点**：Referer 可被隐私策略剥离（此时按兜底拒绝，可能误伤
  少数合法客户端）；且 Referer 校验历史上存在开放重定向等绕过面，仅作兜底。
- **可信子域列表是双刃剑**：任一可信子域被 XSS 攻陷，CSRF 防护即形同虚设
  （token 可被同源脚本读取）。最小化可信列表。
- **未启用 HTTPS/`Secure` 属性**：本地演示用 HTTP；生产必须 HTTPS，否则 Cookie
  可被网络中间人改写（cookie tossing 等）。
- **`/api/attacker-token` 仅为演示 fixation 而存在**，生产代码中不应出现。
- 演示未实现 `Origin: null`（沙箱 iframe、重定向链）的细分策略，当前一律拒绝。
