#!/usr/bin/env python3
"""
生成 OIDC 会话 cookie（测试用）

═══════════════════════════════════════════════════════════════════════════════
为什么需要这个
═══════════════════════════════════════════════════════════════════════════════

真实角色（赵雷/刘立业/苏虎虎）**没有 HiMarket apikey**，
他们通过 **Keycloak OIDC 登录管理台** → 拿到会话 cookie。

要端到端测试"维度管理员"路径，就需要一个合法的会话 cookie。
本脚本用与服务器**相同的算法**（HMAC-SHA256 签名）签发一个，
等价于"该用户已通过 Keycloak 登录"。

⚠️ 这不是绕过安全 —— 签名密钥来自 K8S Secret，本就是服务端凭据；
   用它签发 cookie 等同于模拟一次真实登录。
   伪造者拿不到密钥，因此这**不削弱**安全性。

用法：
    python3 mint_session.py <username> [name] [email] [phone]
    → 输出 cookie 值（可直接放进 Cookie: wiki_session=...）
"""

import base64
import hashlib
import hmac
import json
import os
import sys
import time

# 与 oidc.py 保持一致
SESSION_TTL = 8 * 3600
SESSION_COOKIE = "wiki_session"


def sign(payload: str, key: str) -> str:
    sig = hmac.new(key.encode(), payload.encode(), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(sig).decode().rstrip("=")


def make_session(username: str, key: str, name: str | None = None,
                 email: str | None = None, phone: str | None = None,
                 sub: str = "") -> str:
    body = base64.urlsafe_b64encode(json.dumps({
        "u": username, "n": name, "e": email, "p": phone, "s": sub,
        "x": int(time.time()) + SESSION_TTL,
    }, ensure_ascii=False).encode()).decode().rstrip("=")
    return f"{body}.{sign(body, key)}"


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("用法: mint_session.py <username> [name] [email] [phone]", file=sys.stderr)
        sys.exit(1)

    key = os.environ.get("WIKI_OIDC_SESSION_KEY", "")
    if not key:
        print("❌ 缺少环境变量 WIKI_OIDC_SESSION_KEY", file=sys.stderr)
        sys.exit(1)

    un = sys.argv[1]
    nm = sys.argv[2] if len(sys.argv) > 2 else None
    em = sys.argv[3] if len(sys.argv) > 3 else None
    ph = sys.argv[4] if len(sys.argv) > 4 else None
    print(make_session(un, key, nm, em, ph))
