# campus-wired-login

> 校园网**有线**自动认证：锐捷 ePortal + 统一身份认证（CAS / SSO），Windows / macOS / Linux 通用。

插上网线却上不了网？浏览器没弹认证页？认证页输学号说"用户不允许使用本服务"？
这个脚本帮你把这几步一次性走完，**只绑定网卡、不改路由，不会把你正在用的 Wi-Fi 顶掉**。

零第三方依赖，纯 Python 标准库，单文件，两百多行核心逻辑。

---

## 它解决什么问题

宿舍、实验室、教学楼的有线口大多是**认证端口**。插上网线能拿到 DHCP 地址，
但在认证之前，这块网卡上的流量全部被 AC（接入控制器）拦住：

| 协议 | 未认证时的表现 |
| --- | --- |
| HTTP | 302 / JS 跳转到门户页面（`http://<portal>/eportal/index.jsp?...`） |
| HTTPS | 被设备中间人，证书 issuer 里带 `ruijie` |
| 其他端口 | 直接丢包 |

只有完成 ePortal 认证，这个口才真正放行。脚本做的事就是：**从有线口发出认证请求**。

### 三个常见坑，脚本都处理了

**1. 认证请求必须从有线口出去。**
笔记本通常还连着 Wi-Fi 或手机热点，默认路由在有线口上时反而会断网。
脚本只把 socket 绑定到指定网卡（macOS `IP_BOUND_IF` / Windows `IP_UNICAST_IF` / Linux `SO_BINDTODEVICE`），
不发包、不改路由、不动默认网关。仅 `bind(源IP)` 在 macOS 上不够，必须用这些 socket 选项。

**2. 学生号走不了门户的经典表单。**
很多学校把学号放在统一身份认证里，ePortal 的经典表单通道只认本地账号，学生会收到
「用户不允许使用本服务！」（而且密码错了也是这句，因为它先校验服务再比密码）。
这种情况必须走 SSO 通道（门户 `pageInfo` 里 `isSsoAuth=true`），脚本走的就是这条。

**3. 别把 Wi-Fi / 热点当成有线口。**
脚本要求目标网卡的地址落在你配置的校园网段里，否则直接报错退出，
不会出现"看起来登录成功、其实用的是热点"的假象。

---

## 快速开始

### Windows

1. 安装 Python 3.8+（勾选 **Add Python to PATH**）
2. 双击 `start-windows.bat`
3. 脚本自动找有线口 → 抓认证参数 → 弹出验证码图片 → 输入 4 位 → 完成

```bat
python campus_login.py                     :: 自动
python campus_login.py --check             :: 只检查状态
python campus_login.py --iface 12          :: 指定网卡（InterfaceIndex）
python campus_login.py -u 学号 -p 密码
```

查网卡序号：`Get-NetIPAddress -AddressFamily IPv4 | Select-Object InterfaceIndex,InterfaceAlias,IPAddress`

### macOS

```bash
python3 campus_login.py
python3 campus_login.py --iface en0 --check
```

也可以双击 `start-macos.command`（首次 `chmod +x start-macos.command`）。

### Linux

```bash
sudo python3 campus_login.py --iface eth0     # SO_BINDTODEVICE 需要 root
```

---

## 换到自己学校：只要三个值

脚本自带一份示例档案（重庆工商大学，`--profile ctbu`）。换学校就改这三个：

| 值 | 怎么找 |
| --- | --- |
| **门户地址** `portal` | 有线未认证时用浏览器随便开个 http 网站，看跳转到的地址，取 `http://x.x.x.x` 这一段 |
| **统一认证地址** `cas_base` | 门户页点登录后跳到统一身份认证的地址，例如 `https://cas.xxx.edu.cn/lyuapServer` |
| **校园网段** `campus_cidrs` | 有线口拿到地址后 `ifconfig` / `ipconfig` 看 IP 和掩码，例如 `10.102.177.74/15` → `10.102.0.0/15` |

三种给法，任选：

```bash
# 1) 命令行
python3 campus_login.py --portal http://10.10.10.10 \
    --cas https://cas.example.edu.cn/lyuapServer --cidr 10.10.0.0/16

# 2) config.json（复制 config.example.json）
# 3) profiles/我的学校.json，然后 --profile 我的学校
```

其余字段（验证码路径、公钥路径、登录路径、密码是否倒序）默认按锐捷 CAS 的通用实现，
大多数学校不用改。真要改就写在档案里：

```json
{
  "portal": "http://10.10.10.10",
  "cas_base": "https://cas.example.edu.cn/lyuapServer",
  "campus_cidrs": ["10.10.0.0/16"],
  "service_keyword": "移动",
  "password_reverse": true,
  "captcha_path": "/kaptcha",
  "pubkey_path": "/v2/getPubKey",
  "login_path": "/login"
}
```

---

## 认证流程

```
GET  http://<任意 http 站点>              (不跟随跳转)
  └─ Location 的 query 就是 queryString（wlanuserip / wlanacname / nasip…）

POST http://<portal>/eportal/InterFace.do?method=getServices&queryString=<QS>
  └─ body 为空，返回各运营商出口，按关键字挑一个（学生移动出口 → 移动）

GET  http://<portal>/eportal/login_sso.jsp?<QS>&serviceName=<双重 URL 编码>
  └─ 302 到 https://<cas>/login?service=...
  └─ 页面里取 <input name="execution" value="...">

GET  https://<cas>/kaptcha?time=<毫秒>     → 验证码图片（人工输入）
GET  https://<cas>/v2/getPubKey            → {modulus, exponent}

POST https://<cas>/login
     username / password / authcode / execution / _eventId=submit / rememberMe=true
     其中 password = RSA( reverse(明文) )，锐捷 Shapiro 小端分块，空格分隔的十六进制

302 → http://<portal>/eportal/./success.jsp?userIndex=...
最后用 generate_204 二次确认：真的返回 204 才算成功
```

---

## 常见问题

**Q. 一插网线整台电脑就断网？**
系统把未认证的有线口当成了默认路由。
Windows：适配器「高级 → 高级设置」把以太网排在 Wi-Fi 下面，或
`netsh interface ipv4 set interface "以太网" metric=50`（WLAN 设成 10）。
macOS：`系统设置 → 网络 → … → 设定服务顺序` 把 Wi-Fi 放第一，
或 `networksetup -ordernetworkservices "Wi-Fi" "Ethernet"`。
脚本只绑 socket，不会改这些，但系统路由错了照样断。

**Q. 提示「这块网卡的地址不在校园网段」？**
有线口还没拿到校园网地址：网线没插好 / 链路没协商 / DHCP 没成功。
等 `ifconfig` 里出现配置的网段地址再跑。用 `--iface` 手动指定时只警告不拦。

**Q. 验证码老是输错？**
脚本会把图片存到临时目录，输错会自动换一张重来（默认 6 次）。
图太小看不清就先打开那个 jpg 再输。

**Q. 提示「用户不允许使用本服务」？**
请求走到了经典表单通道，或 `serviceName` 拼错了。确认走的是 `login_sso.jsp`
（能看到统一认证页就是对的），并检查 `service_keyword` 和账号所属运营商。

**Q. 开了代理 / VPN / TUN 之后失败？**
TUN 模式（Clash、Shadowrocket 的增强模式）会把 DNS 变成假 IP（`198.18.x.x`），
统一认证域名解析不到。跑之前关掉 TUN；脚本本身已经禁用 urllib 的代理。

**Q. HTTPS 证书报错？**
校园网设备对有线口做中间人（证书 issuer 带 `ruijie`）。脚本对认证流程使用
不校验证书的 SSL 上下文——流量本来就在校园网设备里终结。不接受就别用有线口。

**Q. 在另一台电脑上登录后，这台掉线了？**
同一账号通常是单终端的，新登录会把旧会话顶掉（学校侧策略）。
把这台的网线插好、重跑一次，就会把这台重新认证。

**Q. 认证成功后还会掉吗？**
会话一般能挂很久（有的学校给到 27 天）。掉了重跑即可，不用重启。

---

## 文件说明

| 文件 | 作用 |
| --- | --- |
| `campus_login.py` | 主程序，跨平台单文件 |
| `config.example.json` | 配置模板（复制成 `config.json`） |
| `profiles/example.json` | 学校档案模板（复制成 `profiles/<名字>.json`） |
| `start-windows.bat` / `start-macos.command` | 双击启动 |
| `tests/offline_test.py` | 离线自测：CIDR、RSA 分块、出口解析、档案覆盖，不联网 |

`config.json` 在 `.gitignore` 里，不会被提交。

---

## 已验证

* **重庆工商大学**（`--profile ctbu`）：macOS 有线口实测通过，认证后 `generate_204` 返回 204，
  门户 `getOnlineUserInfo` 显示当前账号、IP、运营商出口正确。
* Windows / Linux 的网卡绑定路径按各自 socket API 编写，未在真机验证；跑不通请开 issue，带上报错。

---

## 免责声明

仅供本人在自己设备上认证自己的校园网账号使用，省几次手动点击。
接口地址、验证码路径、RSA 公钥均来自门户公开的前端代码；仓库不含任何绕过计费、
绕过认证或共享账号的功能。不要把别人的账号密码写进任何仓库。
