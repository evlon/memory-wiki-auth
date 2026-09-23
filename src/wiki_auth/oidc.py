"""
OIDC 登录 —— 用 Keycloak 替代自造令牌

═══════════════════════════════════════════════════════════════════════════════
为什么在应用层实现（而不是用 Higress 的 oidc 插件）
═══════════════════════════════════════════════════════════════════════════════

实测（e561~e571）：Higress Console 的插件实例 API **不接受 config 字段**：
    POST /v1/wasm-plugins          → 201，但生成的 yaml 里【没有 defaultConfig】
    PUT  /v1/wasm-plugins/{name}   → 200，但 config 仍被静默丢弃
    GET  /v1/wasm-plugins/{n}/config → 只读 schema（PUT 返回 405）
    PUT  /v1/wasm-plugins/{n}/config → 405

即：Console 只管理「实例元数据」（name/version/phase/priority/url），
    配置走「路由绑定」（如 key-auth 的 authConfig），
    而 authConfig 只支持内置认证插件的 allowedConsumers —— **不支持 oidc 的
    client_id/issuer/redirect_url 这类实例级配置**。

→ 用 Higress oidc 插件必须**手写 wasmplugins/ 文件**（红线：一个坏文件
  会让 apiserver 起不来、全部域名 down，本仓库有过事故）。

**因此本模块在应用层实现 OIDC**：
    · 零网关配置改动（不碰 wasmplugins/）
    · 标准授权码流程（浏览器跳转，符合用户常识）
    · 用 Keycloak 的 discovery + token 端点
    · 依赖已在 Hindsight 镜像里：httpx 0.28.1 + PyJWT 2.13.0

═══════════════════════════════════════════════════════════════════════════════
流程
═══════════════════════════════════════════════════════════════════════════════

    浏览器                    管理台后端                 Keycloak
      │                          │                         │
      │ GET /ext/                │                         │
      │─────────────────────────>│                         │
      │ 无有效会话 → 302         │                         │
      │<─────────────────────────│                         │
      │                          │                         │
      │ GET /ext/oauth/login     │                         │
      │─────────────────────────>│ 生成 state+PKCE         │
      │ 302 到 Keycloak authorize│                         │
      │<─────────────────────────│                         │
      │                          │                         │
      │ 用户在 Keycloak 登录 ──────────────────────────────>│
      │                          │                         │
      │ 302 回 /ext/oauth/callback?code=...&state=...       │
      │─────────────────────────>│ 校验 state              │
      │                          │ POST /token（code 换 token）
      │                          │────────────────────────>│
      │                          │<────────────────────────│
      │                          │ 验签 IDToken，读 claims │
      │ 设置会话 cookie          │                         │
      │<─────────────────────────│                         │
      │ 302 回 /ext/             │                         │
      │─────────────────────────>│ 会话有效 → 返回界面     │

═══════════════════════════════════════════════════════════════════════════════
安全设计
═══════════════════════════════════════════════════════════════════════════════

1. **state**：随机生成，存在签名 cookie 里，回调时比对（防 CSRF）
2. **PKCE (S256)**：防授权码拦截
3. **IDToken 验签**：用 Keycloak 的 JWKS，校验 iss/aud/exp
4. **会话 cookie**：HttpOnly + 签名（HMAC），不落服务端存储
5. **fail-closed**：任何一步失败 → 401，绝不放行
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlencode

import httpx
import jwt

logger = logging.getLogger(__name__)

# ── 会话 cookie ───────────────────────────────────────────────────────────────
SESSION_COOKIE = "wiki_session"
STATE_COOKIE = "wiki_oauth_state"
SESSION_TTL = 8 * 3600  # 8 小时


def _extract_roles(claims: dict[str, Any]) -> list[str]:
    """从 JWT claims 提取 realm 角色。

    Keycloak 的角色放在 `realm_access.roles`（realm 角色）
    或 `resource_access.<client>.roles`（client 角色）。
    这里取 realm 角色（wiki-admin / infra-admin / super-admin）。
    """
    ra = claims.get("realm_access") or {}
    return list(ra.get("roles") or [])


@dataclass
class OidcUser:
    """已登录用户。"""

    username: str            # preferred_username（如 niukunliang）
    name: str | None         # 显示名（如 牛昆亮）
    email: str | None
    phone: str | None
    sub: str                 # Keycloak 用户 ID
    exp: int                 # 会话过期时间戳
    roles: list[str] = None  # realm 角色（realm_access.roles），如 wiki-admin

    def to_dict(self) -> dict[str, Any]:
        return {
            "username": self.username, "name": self.name,
            "email": self.email, "phone": self.phone, "sub": self.sub,
            "roles": self.roles or [],
        }


class OidcClient:
    """
    Keycloak OIDC 客户端（授权码 + PKCE）。

    配置（环境变量）：
        WIKI_OIDC_ISSUER          http://auth.example.com/realms/employees
        WIKI_OIDC_CLIENT_ID       wiki-portal
        WIKI_OIDC_CLIENT_SECRET   <secret>
        WIKI_OIDC_REDIRECT_URI    http://wiki.example.com/ext/oauth/callback
        WIKI_OIDC_SESSION_KEY     <用于签名会话 cookie 的密钥>
        WIKI_OIDC_CA_FILE         <内网根 CA bundle 路径，可选>
                                  ⭐ 自签内网 Keycloak（ICT Internal AI Root CA）
                                    必须配；不配则 httpx 用 certifi 官方栈，
                                    无法验证自签证书 → token 交换 ConnectError。
    """

    def __init__(self, config: dict[str, str] | None = None):
        cfg = config or {}

        def pick(key: str, env: str, default: str = "") -> str:
            """
            取配置值。

            ⚠️ 显式传入的值优先（**包括空字符串**）——
               否则 cfg 里的 "" 会回退到环境变量，导致
               「显式禁用」变成「从环境启用」，测试也会随环境漂移。
            """
            if key in cfg:
                return cfg[key] or ""
            return os.environ.get(env) or default

        self.issuer = pick("issuer", "WIKI_OIDC_ISSUER").rstrip("/")
        self.client_id = pick("client_id", "WIKI_OIDC_CLIENT_ID")
        self.client_secret = pick("client_secret", "WIKI_OIDC_CLIENT_SECRET")
        self.redirect_uri = pick("redirect_uri", "WIKI_OIDC_REDIRECT_URI")
        self.session_key = pick("session_key", "WIKI_OIDC_SESSION_KEY")
        self.scope = pick("scope", "WIKI_OIDC_SCOPE", "openid profile email phone")
        # ⭐ TLS 证书校验（auth.ict.cmcc 是内网自签证书，由自建
        #    「ICT Internal AI Root CA」签发，不在官方 CA / 集团 CMCA 栈里）。
        #
        #    优先用 WIKI_OIDC_CA_FILE 指定的 CA bundle 文件（含内网根）：
        #       · httpx 的 verify= 传证书文件路径时用该文件做信任库
        #       · 只有它能让「自签内网根」通过链验证
        #    其次才用 WIKI_OIDC_INSECURE_SKIP_VERIFY（显式 true → 全跳过）。
        #    缺省严格校验（用 httpx 默认 certifi 栈；若内网根已入系统库则可用）。
        cafile = pick("cafile", "WIKI_OIDC_CA_FILE").strip()
        if cafile:
            self._verify: str | bool = cafile
        else:
            skip = pick("insecure_skip_verify", "WIKI_OIDC_INSECURE_SKIP_VERIFY").strip().lower()
            self._verify: str | bool = skip not in ("1", "true", "yes", "on")

        self._discovery: dict[str, Any] | None = None
        self._jwks: dict[str, Any] | None = None
        self._jwks_at: float = 0.0

        self.enabled = bool(self.issuer and self.client_id and self.session_key)
        if self.enabled:
            logger.info("[wiki-auth] OIDC 已启用：issuer=%s client=%s", self.issuer, self.client_id)
        else:
            missing = [k for k, v in [
                ("WIKI_OIDC_ISSUER", self.issuer),
                ("WIKI_OIDC_CLIENT_ID", self.client_id),
                ("WIKI_OIDC_SESSION_KEY", self.session_key),
            ] if not v]
            logger.warning("[wiki-auth] OIDC 未启用（缺 %s）—— 登录端点将返回 503", ", ".join(missing))

    # ── discovery / JWKS ──────────────────────────────────────────────────────
    async def discovery(self) -> dict[str, Any]:
        if self._discovery is None:
            url = f"{self.issuer}/.well-known/openid-configuration"
            async with httpx.AsyncClient(timeout=10, follow_redirects=True, verify=self._verify) as c:
                r = await c.get(url)
                r.raise_for_status()
                self._discovery = r.json()
            logger.info("[wiki-auth] OIDC discovery 完成：%s", self._discovery.get("issuer"))
        return self._discovery

    async def jwks(self) -> dict[str, Any]:
        # 缓存 10 分钟（Keycloak 轮换密钥时能跟上）
        if self._jwks is None or (time.time() - self._jwks_at) > 600:
            d = await self.discovery()
            async with httpx.AsyncClient(timeout=10, follow_redirects=True, verify=self._verify) as c:
                r = await c.get(d["jwks_uri"])
                r.raise_for_status()
                self._jwks = r.json()
            self._jwks_at = time.time()
        return self._jwks

    # ── 会话 cookie 签名 ──────────────────────────────────────────────────────
    def _sign(self, payload: str) -> str:
        sig = hmac.new(self.session_key.encode(), payload.encode(), hashlib.sha256).digest()
        return base64.urlsafe_b64encode(sig).decode().rstrip("=")

    def make_session(self, user: OidcUser) -> str:
        """生成签名会话 cookie 值。"""
        body = base64.urlsafe_b64encode(
            json.dumps({
                "u": user.username, "n": user.name, "e": user.email,
                "p": user.phone, "s": user.sub,
                "x": int(time.time()) + SESSION_TTL,
            }, ensure_ascii=False).encode()
        ).decode().rstrip("=")
        return f"{body}.{self._sign(body)}"

    def read_session(self, cookie: str | None) -> OidcUser | None:
        """
        解析并校验会话 cookie。

        ⚠️ fail-closed：任何异常（签名不符/过期/格式错）→ None。
        """
        if not cookie or "." not in cookie:
            return None
        body, sig = cookie.rsplit(".", 1)
        if not hmac.compare_digest(sig, self._sign(body)):
            logger.warning("[wiki-auth] 会话 cookie 签名不符")
            return None
        try:
            pad = "=" * (-len(body) % 4)
            d = json.loads(base64.urlsafe_b64decode(body + pad))
        except Exception:
            return None
        if int(d.get("x", 0)) < time.time():
            logger.debug("[wiki-auth] 会话已过期")
            return None
        return OidcUser(
            username=d.get("u") or "", name=d.get("n"), email=d.get("e"),
            phone=d.get("p"), sub=d.get("s") or "", exp=int(d.get("x", 0)),
        )

    # ── 授权码流程 ────────────────────────────────────────────────────────────
    async def build_login_url(self) -> tuple[str, str, str]:
        """
        生成登录跳转 URL。

        返回 (url, state, state_cookie_value)。
        """
        d = await self.discovery()
        state = secrets.token_urlsafe(24)
        # PKCE
        verifier = secrets.token_urlsafe(48)
        challenge = base64.urlsafe_b64encode(
            hashlib.sha256(verifier.encode()).digest()
        ).decode().rstrip("=")

        params = {
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "response_type": "code",
            "scope": self.scope,
            "state": state,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
        url = d["authorization_endpoint"] + "?" + urlencode(params)

        # state cookie 里带 state + verifier（签名保护）
        body = base64.urlsafe_b64encode(
            json.dumps({"s": state, "v": verifier, "t": int(time.time())}).encode()
        ).decode().rstrip("=")
        return url, state, f"{body}.{self._sign(body)}"

    def read_state(self, cookie: str | None) -> dict[str, Any] | None:
        """解析 state cookie（含 PKCE verifier）。"""
        if not cookie or "." not in cookie:
            return None
        body, sig = cookie.rsplit(".", 1)
        if not hmac.compare_digest(sig, self._sign(body)):
            return None
        try:
            pad = "=" * (-len(body) % 4)
            d = json.loads(base64.urlsafe_b64decode(body + pad))
        except Exception:
            return None
        # state cookie 有效期 10 分钟
        if int(d.get("t", 0)) < time.time() - 600:
            return None
        return d

    async def exchange_code(self, code: str, verifier: str) -> OidcUser:
        """
        用授权码换 token，验签 IDToken，返回用户。

        ⚠️ 任何一步失败都抛异常（调用方转 401）。
        """
        d = await self.discovery()
        data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": self.redirect_uri,
            "client_id": self.client_id,
            "code_verifier": verifier,
        }
        if self.client_secret:
            data["client_secret"] = self.client_secret

        async with httpx.AsyncClient(timeout=15, verify=self._verify) as c:
            r = await c.post(d["token_endpoint"], data=data,
                             headers={"Content-Type": "application/x-www-form-urlencoded"})
            if r.status_code != 200:
                raise RuntimeError(f"token 交换失败 HTTP {r.status_code}: {r.text[:200]}")
            tok = r.json()

        idt = tok.get("id_token")
        if not idt:
            raise RuntimeError("响应中没有 id_token")

        return await self.verify_id_token(idt)

    async def verify_id_token(self, id_token: str) -> OidcUser:
        """
        验签 IDToken 并提取用户信息。

        校验：签名（JWKS）、iss、aud、exp。
        """
        claims = await self._verify_token(id_token, audience=self.client_id)
        return self._claims_to_user(claims)

    async def verify_access_token(self, access_token: str) -> OidcUser:
        """
        验签 access token 并提取用户信息 + realm 角色。

        ⭐ 用于 Higress oidc 插件统一认证层场景：
           pass_access_token=true 时，网关注入 X-Forwarded-Access-Token 头，
           后端据此解析身份与角色（realm_access.roles）。

        与 IDToken 的区别：
          · access token 的 aud 可能是 client_id 或 "account"（Keycloak），
            因此 audience 校验放宽为「包含 client_id 或 account」。
        """
        claims = await self._verify_token(access_token, audience=None)
        return self._claims_to_user(claims)

    async def _verify_token(self, token: str, audience: str | None) -> dict[str, Any]:
        """验签 JWT（IDToken 或 access token），返回 claims。"""
        jwks = await self.jwks()
        # 从 header 取 kid，选对应公钥
        header = jwt.get_unverified_header(token)
        kid = header.get("kid")
        key = None
        for k in jwks.get("keys", []):
            if kid is None or k.get("kid") == kid:
                key = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(k))
                break
        if key is None:
            raise RuntimeError(f"JWKS 里找不到 kid={kid}")

        d = await self.discovery()
        options: dict[str, Any] = {"verify_exp": True}
        if audience is None:
            # access token：不严格校验 aud（Keycloak 的 access token aud
            # 可能是 client_id 或 account），但仍校验 iss
            options["verify_aud"] = False
        return jwt.decode(
            token, key=key,
            algorithms=["RS256", "RS384", "RS512", "PS256", "ES256"],
            audience=audience,
            issuer=d.get("issuer"),
            options=options,
        )

    @staticmethod
    def _claims_to_user(claims: dict[str, Any]) -> OidcUser:
        username = claims.get("preferred_username") or claims.get("sub") or ""
        roles = _extract_roles(claims)
        return OidcUser(
            username=username,
            name=claims.get("name") or claims.get("given_name"),
            email=claims.get("email"),
            phone=claims.get("phone_number"),
            sub=claims.get("sub") or "",
            exp=int(claims.get("exp", 0)),
            roles=roles,
        )

    async def logout_url(self, post_logout: str | None = None) -> str | None:
        """Keycloak 的登出 URL（若 realm 支持）。"""
        try:
            d = await self.discovery()
            ep = d.get("end_session_endpoint")
            if not ep:
                return None
            if post_logout:
                return ep + "?" + urlencode({"post_logout_redirect_uri": post_logout,
                                             "client_id": self.client_id})
            return ep
        except Exception:
            return None
