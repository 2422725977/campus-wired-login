#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""离线自测：不联网，只验证纯函数逻辑。

    python3 tests/offline_test.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import campus_login as m  # noqa: E402

FAIL = []


def check(name, cond, extra=""):
    if cond:
        print("  PASS  %s" % name)
    else:
        print("  FAIL  %s %s" % (name, extra))
        FAIL.append(name)


print("[1] CIDR 判断")
check("10.102.177.74 在 10.102.0.0/15", m.ip_in_cidr("10.102.177.74", "10.102.0.0/15"))
check("10.103.255.254 在 10.102.0.0/15", m.ip_in_cidr("10.103.255.254", "10.102.0.0/15"))
check("172.20.10.2 不在校园网段", not m.ip_in_cidr("172.20.10.2", "10.102.0.0/15"))
check("211.83.192.55 在 211.83.0.0/16", m.ip_in_cidr("211.83.192.55", "211.83.0.0/16"))

print("[2] RSA 加密（结构）")
n = "c1e3" * 16          # 假 512bit 模数
e = "10001"
out = m.rsa_encrypt("Qq46478602..", n, e)
parts = out.split(" ")
check("分块数量合理", 1 <= len(parts) <= 8, str(len(parts)))
check("全为十六进制", all(p and all(c in "0123456789abcdef" for c in p) for p in parts))
check("每块都小于模数", all(int(p, 16) < int(n, 16) for p in parts))
check("确定性输出", out == m.rsa_encrypt("Qq46478602..", n, e))
check("不同明文不同密文", out != m.rsa_encrypt("Qq46478602..x", n, e))

print("[3] 出口解析")
html = ('<html><div>default</div><div>学生电信出口</div>'
        '<div class="x">学生移动出口</div><div>校园网</div></html>')
check("关键字 移动 命中移动出口", m.pick_service(html, "移动") == "移动")
check("关键字 电信 命中电信", m.pick_service(html, "电信") == "电信")
check("关键字缺失时回退到已有出口",
      m.pick_service(html, "联通") in ("电信", "移动"))
check("单标签页面直接命中", m.pick_service("<div>电信</div>", "电信") == "电信")
check("空内容回退默认值", m.pick_service("", "移动") == "移动")

print("[4] URL 编码")
check("双重编码 hello world",
      m.js_encode(m.js_encode("hello world")) == "hello%2520world")

print("[5] 档案覆盖")
m.resolve_profile({"portal": "http://10.10.10.10", "cas_base": "https://cas.example.edu.cn/lyuapServer",
                   "campus_cidrs": ["10.10.0.0/16"], "service_keyword": "电信"})
check("portal 覆盖生效", m.P["portal"] == "http://10.10.10.10")
check("cas_base 覆盖生效", m.P["cas_base"].endswith("/lyuapServer"))
check("网段覆盖生效", m.P["campus_cidrs"] == ["10.10.0.0/16"])
check("新网段参与判断", m.ip_in_cidr("10.10.5.5", m.P["campus_cidrs"][0]))
check("旧网段不再命中", not m.ip_in_cidr("10.102.177.74", m.P["campus_cidrs"][0]))

print()
if FAIL:
    print("失败 %d 项：%s" % (len(FAIL), ", ".join(FAIL)))
    sys.exit(1)
print("全部通过 ✅")
