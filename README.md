# ctbu-wired-login

重庆工商大学（CTBU）**有线网络**一键认证：ePortal + 统一身份认证（CAS SSO），支持 **Windows / macOS / Linux**。

零第三方依赖，纯 Python 标准库，单文件。

---

## 一、为什么需要这个工具

宿舍/教学楼的有线口是**认证端口**：插上网线能拿到 DHCP 地址（`10.102.x.x/15`），但在认证之前，
这块网卡上的流量全部被 AC（锐捷）拦下来：

| 协议 | 未认证时的表现 |
| --- | --- |
| HTTP | 被 302 / JS 跳到 `http://211.83.192.55/eportal/index.jsp?...` |
| HTTPS | 被设备中间人，证书 subject 是 `ruijie`（跳过校验后能拿到真实页面） |

只有完成 ePortal 认证，这个口才真正放行。

### 为什么不能直接在门户页面输学号密码

学号属于**统一身份体系**。ePortal 的「经典表单」通道对学生号一律返回：

```
用户不允许使用本服务!
```

五个出口（default / 电信 / 移动 / 联通 / 校园网）全试过都一样，**密码错了也是这句** ——
说明它先做服务校验、比对密码还早。学生必须走 **SSO（CAS / OAuth2）** 通道，
门户的 `pageInfo` 也明确写着 `isSsoAuth=true`。

### 为什么不能直接跑，要先绑网卡

笔记本通常还连着 Wi-Fi 或手机热点，**默认路由不在有线口上**。认证请求必须从有线口发出，
否则门户看到的源 IP 是别的网段，认证不会落在有线口上（会认证到 Wi-Fi 那张网卡）。

本工具**只绑定 socket 到指定网卡**，不改路由、不切默认网关，所以过程中不会断网：

| 系统 | 绑定方式 |
| --- | --- |
| macOS | `IP_BOUND_IF` = (IPPROTO_IP, 25)，值为 `if_nametoindex()` |
| Windows | `IP_UNICAST_IF` = (IPPROTO_IP, 31)，值为接口索引（DWORD） |
| Linux | `SO_BINDTODEVICE` = (SOL_SOCKET, 25)，值为接口名 |

> 只 `bind((源IP, 0))` 在 macOS 上**不管用**，必须用上面的选项，否则包还是从默认路由走。

---

## 二、快速开始

### Windows

1. 装 Python 3.8+（安装时勾选 **Add Python to PATH**）。
2. 双击 `启动-Windows.bat`（或以管理员身份运行 PowerShell 再执行它）。
3. 脚本自动找有线网卡 → 抓认证参数 → 弹出验证码图片 → 输入 4 位验证码 → 完成。

命令行用法：

```bat
python ctbu_wired_login.py                :: 自动找网卡并登录
python ctbu_wired_login.py --check        :: 只检查状态
python ctbu_wired_login.py --iface 12     :: 指定网卡（用 Get-NetIPAddress 里的 InterfaceIndex）
python ctbu_wired_login.py -u 学号 -p 密码
```

查看网卡序号：

```powershell
Get-NetIPAddress -AddressFamily IPv4 | Select-Object InterfaceIndex,InterfaceAlias,IPAddress
```

### macOS

```bash
python3 ctbu_wired_login.py            # 自动
python3 ctbu_wired_login.py --iface en0
python3 ctbu_wired_login.py --check
```

也可以双击 `启动-macOS.command`（首次需 `chmod +x`）。

### Linux

```bash
python3 ctbu_wired_login.py --iface eth0     # 需要 root 才能 SO_BINDTODEVICE
```

---

## 三、配置（可选）

复制 `config.example.json` 为 `config.json`（和脚本同目录）：

```json
{
  "username": "2025410030",
  "password": "你的统一身份认证密码",
  "interface": "en0",
  "service_keyword": "移动",
  "max_attempts": 6
}
```

* `interface` 留空 = 自动探测（优先校园网段 10.102.0.0/15、10.203.0.0/17 的地址，排除 Wi-Fi / utun / bridge）。
* `service_keyword`：出口关键字，`移动` / `电信` / `联通` / `校园网` / `default`。
* `config.json` 已在 `.gitignore` 里，不会被提交。

---

## 四、认证流程（给想改源码的人）

```
GET http://captive.apple.com/hotspot-detect.html   (不跟随跳转)
  └─ Location 的 query 就是 queryString（wlanuserip/wlanacname/nasip…）

POST http://211.83.192.55/eportal/InterFace.do?method=getServices&queryString=<QS>
  └─ body 为空，返回 5 个出口 HTML，按关键字挑出「学生移动出口」→ service

GET  http://211.83.192.55/eportal/login_sso.jsp?<QS>&serviceName=<双重 URL 编码的 service>
  └─ 302 到 https://cas.ctbu.edu.cn/lyuapServer/login?service=...
  └─ 页面里取 <input name="execution" value="...">

GET  https://cas.ctbu.edu.cn/lyuapServer/kaptcha?time=<毫秒>        → 验证码 JPEG
GET  https://cas.ctbu.edu.cn/lyuapServer/v2/getPubKey               → {modulus, exponent} (512bit)

POST https://cas.ctbu.edu.cn/lyuapServer/login
     username / password / authcode / execution / _eventId=submit / rememberMe=true

密码算法：password = RSA( reverse(明文) ) ，锐捷 Shapiro 小端分块，输出空格分隔的十六进制。
成功后 302 → http://211.83.192.55/eportal/./success.jsp?userIndex=...
最终用 generate_204 二次确认：返回 204 才算真的通。
```

---

## 五、常见问题

### 1. 一插网线整台电脑就断网

系统把**未认证的有线口**当成了默认路由，所有流量都从那个只会跳转的门户口出去了。

* Windows：`网络和共享中心 → 更改适配器设置 → 高级 → 高级设置`，把「以太网」排在 Wi-Fi **下面**；
  或调跃点：`netsh interface ipv4 set interface "以太网" metric=50`、`netsh interface ipv4 set interface "WLAN" metric=10`。
* macOS：`系统设置 → 网络 → 右下角「…」→ 设定服务顺序`，把 Wi-Fi 放第一位；
  或命令行：`networksetup -ordernetworkservices "Wi-Fi" "Ethernet"`。

本工具只绑 socket，不会动默认路由，但**系统本身**路由错了照样会断网，所以先把顺序调对。

### 2. 拿不到 10.x 地址（169.254.x.x）

DHCP 没成功：换根网线 / 换个口 / 让交换机端口重新认证（拔插等 10 秒），
或先用系统自带的网络诊断重置 DHCP。

### 3. 验证码老是错

`/kaptcha` 是 4 位、200×50、带干扰线的图。输错会自动换一张重来，最多 `max_attempts` 次。
图看不清时脚本会把 JPEG 存到临时目录，可以手动打开放大。

### 4. 提示「用户不允许使用本服务」

说明请求走到了经典表单通道，或 `serviceName` 没拼对。确认脚本走的是 `login_sso.jsp`
（能看到 CAS 页面就是对的），并检查 `service_keyword` 与账号所属运营商是否匹配。

### 5. 开了代理 / VPN / TUN 之后失败

TUN 模式（Clash / Shadowrocket 的「增强模式」）会把 DNS 变成假 IP（如 `198.18.x.x`），
CAS 域名解析失败。跑本脚本前请关掉 TUN；脚本本身已经禁用 urllib 的代理。

### 6. HTTPS 证书报错

门户设备对有线口做中间人（证书 subject 是 `ruijie`）。脚本对 CAS 使用
「不校验证书」的 SSL 上下文，这是**故意的** —— 流量本来就在校园网设备里终结。
如果你不接受这一点，就别用有线口。

### 7. 提示「这块网卡的地址不在校园网段」

脚本拒绝把 Wi-Fi / 手机热点当成有线口去认证。看到这条说明**有线口还没起来**：
网线没插好、链路没协商、或 DHCP 没成功（`ifconfig <网卡>` 里没有 `10.102.x.x`）。
把网线插回有线口、等几秒 DHCP 完成再跑。用 `--iface` 手动指定时只会警告，不会拦你。

### 8. 在另一台电脑上登录后，这台掉线了

同一账号一般是**单终端**的：新登录会把旧会话顶掉，这是学校侧策略，不是脚本的问题。
把网线插回这台机器，重跑一次脚本，就会把这台重新认证、同时把对面顶下去。

### 9. 认证成功但过一会儿又掉

`maxLeavingTime` 约 27 天，正常不会掉。掉线一般是 DHCP 续租或交换机状态变化，
重跑一次脚本即可，不需要重启。

---

## 六、文件说明

| 文件 | 作用 |
| --- | --- |
| `ctbu_wired_login.py` | 主程序（跨平台单文件） |
| `config.example.json` | 配置模板 |
| `启动-Windows.bat` | Windows 双击启动 |
| `启动-macOS.command` | macOS 双击启动 |
| `tests/offline_test.py` | 离线自测（RSA、CIDR、出口解析），不联网 |

---

## 七、免责声明

仅用于本人校园网账号在本人设备上的认证，方便自己少点几次页面。
不要把别人的账号密码写进任何仓库；`config.json` 默认已被忽略。
认证机制、接口地址、RSA 公钥均来自公开的门户前端代码，本仓库不包含任何绕过计费/绕过认证的功能。
