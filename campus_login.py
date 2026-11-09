#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""校园网有线认证（锐捷 ePortal + 统一身份认证 CAS/SSO）

宿舍有线口通常是认证端口：插上网线能拿到 DHCP 地址，但认证前所有流量都会被
AC 劫持 —— HTTP 被跳转到门户页面，HTTPS 被设备中间人（证书 issuer 带 ruijie）。
只有完成 ePortal 认证，这个口才真正放行。

为什么不能直接在门户页输学号密码：
  很多学校把学号放在统一身份认证（CAS / OAuth2）里，ePortal 的经典表单通道
  只认本地/运营商账号，学生号会被回「用户不允许使用本服务！」。
  这种情况必须走 SSO 通道（门户 pageInfo 里 isSsoAuth=true）。

为什么不能直接跑，要先绑网卡：
  笔记本通常还连着 Wi-Fi 或热点，默认路由不在有线口上。认证请求必须从有线口
  发出，否则门户看到的源 IP 是别的网段，认证不会落在有线口上。
  本工具只把 socket 绑定到指定网卡，不改路由、不切默认网关，所以不会断网：
    macOS   : IP_BOUND_IF       (IPPROTO_IP, 25)
    Windows : IP_UNICAST_IF     (IPPROTO_IP, 31)
    Linux   : SO_BINDTODEVICE   (SOL_SOCKET, 25)

适配其他学校：
  内置 profile 只有一所学校（ctbu）。别的学校只需要三样东西：
    1. 未认证时被跳转到的门户地址   -> --portal 或 config.json 的 "portal"
    2. 统一身份认证地址（CAS 根）    -> --cas
    3. 有线口拿到的网段             -> --cidr（可重复）
  或者写一个 profiles/你的学校.json，用 --profile 你的学校 加载。

用法：
  python3 campus_login.py                     # 用默认 profile 登录
  python3 campus_login.py --check             # 只检查状态
  python3 campus_login.py --portal http://1.2.3.4 --cas https://cas.x.edu.cn/lyuapServer --cidr 10.0.0.0/8
  python3 campus_login.py --iface en0 -u 学号 -p 密码
  python3 campus_login.py --profile ctbu

零第三方依赖，只用标准库。
"""
import argparse
import getpass
from http.cookiejar import CookieJar
import json
import os
import platform
import re
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

VERSION = "1.1.0"
USER_AGENT = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")

# 内置档案。加一所学校 = 往这里加一条，或写 profiles/<名字>.json。
# portal / cas_base / campus_cidrs 是必须改的三项，其余给的是锐捷的通用默认值。
DEFAULT_PROFILE = "ctbu"
PROFILES = {
    "ctbu": {
        "_name": "重庆工商大学（随仓库附带的示例）",
        "portal": "http://211.83.192.55",
        "cas_base": "https://cas.ctbu.edu.cn/lyuapServer",
        "campus_cidrs": ["10.102.0.0/15", "10.203.0.0/17", "211.83.0.0/16"],
        "service_keyword": "移动",
        "password_reverse": True,
        "captcha_path": "/kaptcha",
        "pubkey_path": "/v2/getPubKey",
        "login_path": "/login",
    },
}

P = dict(PROFILES[DEFAULT_PROFILE])


def resolve_profile(cfg):
    """把 config / 命令行里的覆盖项合并进全局档案 P。"""
    name = (cfg or {}).get("profile") or DEFAULT_PROFILE
    prof = PROFILES.get(name)
    if prof is None:
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "profiles", name + ".json")
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    prof = json.load(fh)
            except Exception as e:
                log("档案文件读取失败：%s" % e, "WARN")
    if prof:
        P.update(prof)
    for key in ("portal", "cas_base", "service_keyword", "password_reverse"):
        if (cfg or {}).get(key):
            P[key] = cfg[key]
    if (cfg or {}).get("campus_cidrs"):
        P["campus_cidrs"] = cfg["campus_cidrs"]
    return P

IS_WIN = platform.system() == "Windows"
IS_MAC = platform.system() == "Darwin"
IS_LINUX = platform.system() == "Linux"


# --------------------------------------------------------------------------
# 输出
# --------------------------------------------------------------------------
def log(msg="", level="INFO"):
    line = "%s %s" % (time.strftime("%H:%M:%S"), msg)
    if level == "ERR":
        line = "%s [错误] %s" % (time.strftime("%H:%M:%S"), msg)
    elif level == "WARN":
        line = "%s [注意] %s" % (time.strftime("%H:%M:%S"), msg)
    elif level == "OK":
        line = "%s [成功] %s" % (time.strftime("%H:%M:%S"), msg)
    try:
        print(line, flush=True)
    except UnicodeEncodeError:
        print(line.encode("utf-8", "replace").decode("utf-8", "replace"), flush=True)


# --------------------------------------------------------------------------
# 网卡发现
# --------------------------------------------------------------------------
def _run(cmd, timeout=8):
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                           timeout=timeout)
        return p.stdout.decode("utf-8", "replace")
    except Exception:
        return ""


def list_interfaces():
    """返回 [(name, ip, desc)]，只含 IPv4。"""
    out = []
    if IS_WIN:
        script = ("Get-NetIPAddress -AddressFamily IPv4 | "
                  "Select-Object InterfaceIndex,InterfaceAlias,IPAddress | ConvertTo-Json")
        raw = _run(["powershell", "-NoProfile", "-NonInteractive", "-Command", script])
        if not raw.strip():
            raw = _run(["powershell", "-NoProfile", "-NonInteractive",
                        "-ExecutionPolicy", "Bypass", "-Command", script])
        try:
            data = json.loads(raw)
            if isinstance(data, dict):
                data = [data]
            for it in data:
                ip = it.get("IPAddress") or ""
                if ip.startswith("127.") or ip.startswith("169.254."):
                    continue
                out.append((str(it.get("InterfaceIndex")), ip,
                            it.get("InterfaceAlias") or ""))
        except Exception:
            pass
        if not out:  # 老系统兜底：解析 ipconfig
            txt = _run(["ipconfig"])
            cur = ""
            for line in txt.splitlines():
                if "adapter" in line.lower():
                    cur = line.strip()
                m = re.search(r"IPv4[^:]*:\s*([0-9.]+)", line)
                if m and not m.group(1).startswith("169.254."):
                    out.append((m.group(1), m.group(1), cur))
    elif IS_MAC:
        txt = _run(["ifconfig"])
        name = ip = ""
        for line in txt.splitlines():
            m = re.match(r"^(\w+):", line)
            if m:
                name, ip = m.group(1), ""
            m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", line)
            if m:
                ip = m.group(1)
                if name and not ip.startswith("127.") and not ip.startswith("169.254."):
                    out.append((name, ip, ""))
    elif IS_LINUX:
        txt = _run(["ip", "-4", "addr"])
        name = ""
        for line in txt.splitlines():
            m = re.match(r"^\d+:\s+(\S+):", line)
            if m:
                name = m.group(1)
            m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", line)
            if m and not m.group(1).startswith("127."):
                out.append((name, m.group(1), ""))
    return out


def ip_in_cidr(ip, cidr):
    try:
        a, bits = cidr.split("/")
        bits = int(bits)
        ipn = struct.unpack("!I", socket.inet_aton(ip))[0]
        an = struct.unpack("!I", socket.inet_aton(a))[0]
        mask = (0xFFFFFFFF << (32 - bits)) & 0xFFFFFFFF
        return (ipn & mask) == (an & mask)
    except Exception:
        return False


WIFI_WORDS = ("wi-fi", "wifi", "wlan", "无线", "wireless", "airport")


def pick_interface(prefer=None):
    """选有线网卡：优先校园网段内的 IP，且名字/别名不像 Wi-Fi。"""
    cands = list_interfaces()
    if prefer:
        for name, ip, desc in cands:
            if prefer == name or prefer == ip or (desc and prefer in desc):
                return name, ip, desc
        return prefer, None, ""

    def score(item):
        name, ip, desc = item
        s = 0
        if any(ip_in_cidr(ip, c) for c in P["campus_cidrs"]):
            s += 10
        blob = ("%s %s" % (name, desc)).lower()
        if any(w in blob for w in WIFI_WORDS):
            s -= 5
        if re.search(r"(^| )(以太网|ethernet|en\d+|eth\d+)($| )", blob):
            s += 3
        if re.match(r"(utun|bridge|llw|awdl|lo)", name):
            s -= 8
        return s

    if not cands:
        return None, None, ""
    cands.sort(key=score, reverse=True)
    return cands[0]


# --------------------------------------------------------------------------
# 网卡绑定（不改路由）
# --------------------------------------------------------------------------
def make_socket(iface, local_ip):
    """创建已绑定到指定网卡的 TCP socket。"""
    idx = None
    if IS_WIN:
        try:
            idx = int(iface)
        except ValueError:
            # 别名 -> 序号
            for name, ip, desc in list_interfaces():
                if iface in (name, desc):
                    idx = int(name)
                    break
    elif not IS_LINUX:
        try:
            idx = socket.if_nametoindex(iface)
        except Exception:
            idx = None

    def _factory(address, timeout=None, source_address=None, *a, **k):
        host, port = address
        last = None
        for res in socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM):
            af, socktype, proto, _, sa = res
            s = None
            try:
                s = socket.socket(af, socktype, proto)
                if IS_MAC and idx:
                    s.setsockopt(socket.IPPROTO_IP, 25, idx)          # IP_BOUND_IF
                elif IS_WIN and idx:
                    # IP_UNICAST_IF：文档要求网络字节序，但部分版本接受主机序，
                    # 两种都试，谁的接口索引合法就用谁。
                    for fmt in ("!I", "I"):
                        try:
                            s.setsockopt(socket.IPPROTO_IP, 31, struct.pack(fmt, idx))
                            break
                        except OSError:
                            continue
                elif IS_LINUX:
                    s.setsockopt(socket.SOL_SOCKET, 25,
                                 (iface + "\0").encode())              # SO_BINDTODEVICE
                if local_ip:
                    try:
                        s.bind((local_ip, 0))
                    except OSError:
                        pass
                s.settimeout(min(timeout or 10, 15))
                s.connect(sa)
                return s
            except OSError as e:
                last = e
                if s:
                    s.close()
        raise last
    return _factory


# --------------------------------------------------------------------------
# HTTP
# --------------------------------------------------------------------------
_CTX = ssl.create_default_context()
_CTX.check_hostname = False
_CTX.verify_mode = ssl.CERT_NONE


def http(url, data=None, timeout=20, jar=None, headers=None, redirect=True):
    """返回 (code, headers, body_bytes, final_url)。"""
    handlers = [urllib.request.ProxyHandler({}),
                urllib.request.HTTPSHandler(context=_CTX)]
    if jar is not None:
        handlers.append(urllib.request.HTTPCookieProcessor(jar))
    if not redirect:
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, hdrs, newurl):
                return None
        handlers.append(NoRedirect())
    opener = urllib.request.build_opener(*handlers)
    hdrs = {"User-Agent": USER_AGENT, "Accept": "*/*"}
    if headers:
        hdrs.update(headers)
    body = None
    if data is not None:
        body = urllib.parse.urlencode(data).encode("utf-8")
    req = urllib.request.Request(url, data=body, headers=hdrs)
    try:
        with opener.open(req, timeout=timeout) as resp:
            return resp.getcode(), dict(resp.headers), resp.read(), resp.geturl()
    except urllib.error.HTTPError as e:
        try:
            return e.code, dict(e.headers or {}), e.read(), url
        except Exception:
            return e.code, {}, b"", url
    except Exception:
        return None, {}, b"", url


def decode(raw):
    if not raw:
        return ""
    for enc in ("utf-8", "gbk", "latin-1"):
        try:
            return raw.decode(enc)
        except Exception:
            continue
    return raw.decode("utf-8", "replace")


def js_encode(s):
    return urllib.parse.quote(s, safe="-_.!~*'()")


# --------------------------------------------------------------------------
# 门户
# --------------------------------------------------------------------------
def capture_querystring(timeout=15):
    """未认证时 AC 会把 http 求情跳到门户，Location 的 query 就是 queryString。"""
    tries = ["http://captive.apple.com/hotspot-detect.html",
             "http://connect.rom.miui.com/generate_204",
             "http://www.baidu.com/"]
    keys = ("wlanuserip", "wlanacname", "nasip")
    for url in tries:
        code, headers, body, final = http(url, timeout=timeout, redirect=False)
        loc = headers.get("Location") or headers.get("location") or ""
        q = urllib.parse.urlsplit(loc).query
        if q and any(k in q for k in keys):
            return q
        m = re.search(r"(wlanuserip=[^\"'\s<>&]+(?:&[^\"'\s<>&]+)*)", decode(body))
        if m:
            return m.group(1)
    return None


def online_info(timeout=15, jar=None):
    code, h, body, f = http(P["portal"] + "/eportal/InterFace.do?method=getOnlineUserInfo",
                            timeout=timeout, jar=jar)
    try:
        d = json.loads(decode(body))
        return d
    except Exception:
        return {}


def get_services(querystring, timeout=15, jar=None):
    url = (P["portal"] + "/eportal/InterFace.do?method=getServices"
           + "&queryString=" + (querystring or ""))
    code, h, body, f = http(url, data=b"", timeout=timeout, jar=jar,
                            headers={"Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                                     "Referer": P["portal"] + "/eportal/index.jsp"})
    return decode(body)


def pick_service(page_text, keyword):
    """从 getServices 的 HTML 里挑出口，返回服务名（如 移动）。

    真实页面里出口写成「学生移动出口 / 学生电信出口 / …」，
    所以优先匹配这个固定句式，避免被 "default" 之类占位文字干扰。
    """
    kw = (keyword or "移动").strip()
    if not page_text:
        return kw
    names = re.findall(r'学生\s*(移动|电信|联通)\s*出口', page_text)
    if kw in names:
        return kw
    if names:
        return names[0]
    if kw and kw in page_text:
        return kw
    for k in ("移动", "电信", "联通", "校园网", "default"):
        if k in page_text:
            return k
    return kw


# --------------------------------------------------------------------------
# RSA（锐捷 Shapiro RSAUtils 同款）
# --------------------------------------------------------------------------
def rsa_encrypt(text, modulus_hex, exponent_hex):
    n = int(modulus_hex, 16)
    e = int(exponent_hex, 16)
    hi = (n.bit_length() + 15) // 16 - 1
    while hi > 0 and ((n >> (16 * hi)) & 0xFFFF) == 0:
        hi -= 1
    chunk = 2 * hi
    data = text.encode("latin-1", "replace")
    while len(data) % chunk:
        data += b"\x00"
    parts = []
    for i in range(0, len(data), chunk):
        c = pow(int.from_bytes(data[i:i + chunk], "little"), e, n)
        h = "%x" % c
        if len(h) % 4:
            h = h.rjust(len(h) + (4 - len(h) % 4), "0")
        parts.append(h)
    return " ".join(parts)


# --------------------------------------------------------------------------
# 验证码
# --------------------------------------------------------------------------
def show_captcha(img_bytes):
    path = os.path.join(tempfile.gettempdir(), "ctbu_cas_captcha.jpg")
    with open(path, "wb") as f:
        f.write(img_bytes)
    log("验证码已保存：%s" % path)
    try:
        if IS_WIN:
            os.startfile(path)          # noqa
        elif IS_MAC:
            subprocess.Popen(["open", path])
        else:
            subprocess.Popen(["xdg-open", path])
    except Exception:
        pass
    try:
        return input("请输入图片里的 4 位验证码：").strip()
    except EOFError:
        return ""


# --------------------------------------------------------------------------
# 登录主流程
# --------------------------------------------------------------------------
def do_login(cfg, check_only=False):
    resolve_profile(cfg)
    iface, ip, desc = pick_interface(cfg.get("interface") or None)
    if not iface:
        log("没找到可用的网卡，请检查网线是否插好、是否已获取 DHCP 地址。", "ERR")
        return 2
    log("使用网卡：%s  IP=%s  %s" % (iface, ip or "?", desc or ""))

    explicit = bool(cfg.get("interface"))
    campus = bool(ip) and any(ip_in_cidr(ip, c) for c in P["campus_cidrs"])
    if not campus:
        log("这块网卡的地址 %s 不在校园网段（%s）。" % (ip or "无", "、".join(P["campus_cidrs"])), "ERR")
        if not explicit:
            log("有线口还没拿到 10.x 地址：网线没插好 / 链路没起来 / DHCP 没成功。", "ERR")
            log("本工具只认证有线口，不会把 Wi-Fi 或手机热点当成有线去登录。", "ERR")
            log("把网线插回有线口，等 ifconfig 里出现 10.x 地址后再跑。", "ERR")
            return 3
        log("你手动指定的网卡不在校园网段，继续尝试，但登录大概率会失败。", "WARN")

    jar = CookieJar()
    conn_factory = make_socket(iface, ip)
    socket.create_connection = conn_factory
    socket.getaddrinfo  # noqa

    info = online_info(jar=jar)
    if info.get("result") == "success":
        log("门户显示已在线：账号 %s  IP %s" % (info.get("userId"), info.get("userIp")), "OK")
        return 0

    qs = capture_querystring()
    if not qs:
        if verify_online():
            log("外网已通，无需认证。", "OK")
            return 0
        log("没抓到 queryString：未认证时 AC 一定会跳转，抓不到说明请求没走这块网卡。", "ERR")
        log("请确认网线插在校园网口、已获取 10.x 的 DHCP 地址，并关掉 VPN / 代理 / TUN。", "ERR")
        return 3
    log("queryString 长度 %d" % len(qs))

    page = get_services(qs, jar=jar)
    svc = pick_service(page, cfg.get("service_keyword") or P.get("service_keyword") or "移动")
    log("出口 service = %s" % svc)

    if check_only:
        log("--check 模式：只报告，不登录。")
        return 0

    user = cfg.get("username") or ""
    pwd = cfg.get("password") or ""
    if not user:
        user = input("学号：").strip()
    if not pwd:
        pwd = getpass.getpass("统一身份认证密码：")

    attempts = int(cfg.get("max_attempts", 6))
    for i in range(1, attempts + 1):
        log("—— 第 %d/%d 次尝试 ——" % (i, attempts))
        ok, why = sso_once(qs, svc, user, pwd, jar)
        if ok:
            log(why, "OK")
            return 0
        log(why, "WARN")
        if "密码" in why or "账号" in why:
            log("账号或密码被拒，停止重试。", "ERR")
            return 4
        if i < attempts:
            fresh = capture_querystring()
            if fresh:
                qs = fresh
            time.sleep(0.8)
    return 5


def sso_once(qs, svc, user, pwd, jar):
    # 1. 门户 SSO 入口 -> CAS 登录页
    entry = "%s/eportal/login_sso.jsp?%s&serviceName=%s" % (P["portal"], qs, js_encode(js_encode(svc)))
    code, h, body, final = http(entry, timeout=30, jar=jar)
    html = decode(body)
    m = re.search(r'name="execution"\s+value="([^"]+)"', html)
    if not m:
        code, h, body, final = http(P["cas_base"] + P["login_path"], timeout=30, jar=jar)
        html = decode(body)
        m = re.search(r'name="execution"\s+value="([^"]+)"', html)
    if not m:
        return False, "拿不到 CAS 的 execution 令牌（code=%s）" % code
    execution = m.group(1)

    # 2. 验证码
    ccode, ch, cbody, cf = http("%s%s?time=%d" % (P["cas_base"], P["captcha_path"], int(time.time() * 1000)),
                                timeout=30, jar=jar,
                                headers={"Referer": P["cas_base"] + P["login_path"], "Accept": "image/*"})
    if ccode != 200 or not cbody:
        return False, "验证码下载失败（code=%s）" % ccode
    captcha = show_captcha(cbody)
    if not captcha:
        return False, "没有输入验证码"

    # 3. 公钥
    kcode, kh, kbody, kf = http(P["cas_base"] + P["pubkey_path"], timeout=30, jar=jar)
    try:
        pk = json.loads(decode(kbody))
        modulus, exponent = pk["modulus"], pk["exponent"]
    except Exception:
        return False, "拿不到 RSA 公钥（code=%s）" % kcode

    enc_pwd = rsa_encrypt(pwd[::-1] if P.get("password_reverse", True) else pwd,
                          modulus, exponent)
    data = {"username": user, "password": enc_pwd, "authcode": captcha,
            "execution": execution, "_eventId": "submit", "rememberMe": "true"}
    pcode, ph, pbody, ptext = http(P["cas_base"] + P["login_path"], data=data, timeout=30, jar=jar,
                                   headers={"Referer": P["cas_base"] + P["login_path"],
                                            "Origin": P["cas_base"].split("/lyuapServer")[0],
                                            "Content-Type": "application/x-www-form-urlencoded"})
    page = decode(pbody)

    for pat in (r'id="pwderrormsg"[^>]*>(.*?)</', r'id="yzmErrormsg"[^>]*>(.*?)</',
                r'id="errormsg"[^>]*>(.*?)</'):
        for mm in re.finditer(pat, page, re.S):
            t = re.sub(r"<[^>]+>|\s+", " ", mm.group(1)).strip()
            if not t:
                continue
            if "验证码" in t:
                return False, "验证码错误（%s）" % t
            if "密码" in t or "账号" in t or "用户" in t:
                return False, "账号或密码错误（%s）" % t

    if "success.jsp" in (ptext or "") or "登录成功" in page:
        # 二次确认
        for _ in range(3):
            if verify_online():
                return True, "SSO 登录成功，有线已可上网"
            time.sleep(1.5)
        return False, "流程走完但外网探测仍未通过"
    if "ticket=" in (ptext or ""):
        for _ in range(3):
            if verify_online():
                return True, "SSO 登录成功，有线已可上网"
            time.sleep(1.5)
        return False, "拿到了 ticket 但外网仍未通"
    return False, "CAS 未接受登录（最终地址 %s）" % (ptext or "")[:120]


def verify_online(timeout=10):
    for url in ("http://connect.rom.miui.com/generate_204",
                "http://captive.apple.com/hotspot-detect.html"):
        code, h, body, final = http(url, timeout=timeout, redirect=False)
        if code == 204:
            return True
        if code == 200:
            t = decode(body)
            if "Success" in t or len(t) < 300:
                return True
    return False


# --------------------------------------------------------------------------
def load_config(path):
    cfg = {}
    if path and os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                cfg = json.load(f)
        except Exception as e:
            log("配置文件读取失败：%s" % e, "WARN")
    return cfg


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="校园网有线认证：锐捷 ePortal + 统一身份认证（CAS SSO）")
    ap.add_argument("--iface", default=None, help="指定网卡（默认自动找有线口）")
    ap.add_argument("--check", action="store_true", help="只检查状态，不登录")
    ap.add_argument("-u", "--username", default=None)
    ap.add_argument("-p", "--password", default=None)
    ap.add_argument("-c", "--config", default="config.json")
    ap.add_argument("--profile", default=None,
                    help="使用哪套配置档案：内置名（ctbu）或 profiles/<名字>.json")
    ap.add_argument("--portal", default=None,
                    help="门户地址，如 http://10.10.10.10（未认证时被跳转到的那个）")
    ap.add_argument("--cas", default=None,
                    help="统一身份认证地址，如 https://cas.example.edu.cn/lyuapServer")
    ap.add_argument("--cidr", action="append", default=None,
                    help="校园网段，可重复，如 --cidr 10.102.0.0/15")
    ap.add_argument("--service", default=None,
                    help="运营商出口关键字：移动 / 电信 / 联通 / 校园网 / default")
    ap.add_argument("--version", action="version", version=VERSION)
    args = ap.parse_args(argv)

    if IS_WIN:
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except Exception:
            pass

    cfg = load_config(os.path.join(os.path.dirname(os.path.abspath(__file__)), args.config))
    if args.iface:
        cfg["interface"] = args.iface
    if args.username:
        cfg["username"] = args.username
    if args.password:
        cfg["password"] = args.password
    if args.profile:
        cfg["profile"] = args.profile
    if args.portal:
        cfg["portal"] = args.portal
    if args.cas:
        cfg["cas_base"] = args.cas
    if args.cidr:
        cfg["campus_cidrs"] = args.cidr
    if args.service:
        cfg["service_keyword"] = args.service

    resolve_profile(cfg)

    try:
        return do_login(cfg, check_only=args.check)
    except KeyboardInterrupt:
        log("已取消。", "WARN")
        return 130


if __name__ == "__main__":
    sys.exit(main())
