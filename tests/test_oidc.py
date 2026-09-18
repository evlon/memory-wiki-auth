"""
OIDC 登录模块测试

覆盖：
    · 会话 cookie 签名/验签/过期（fail-closed）
    · state cookie（含 PKCE verifier）
    · 未启用 OIDC 时的行为
    · 管理 API 的 Cookie 认证路径（不依赖真实 Keycloak）
"""

from __future__ import annotations

import base64
import json
import time

import pytest

from wiki_auth.oidc import SESSION_COOKIE, STATE_COOKIE, OidcClient, OidcUser

# ⚠️ 测试必须与环境隔离：容器里真实设置了 WIKI_OIDC_* / WIKI_ADMIN_USERS，
#    若不清理，配置项会回退到环境变量 → 断言结果随环境变化（假绿/假红）。
_OIDC_ENV = [
    "WIKI_OIDC_ISSUER", "WIKI_OIDC_CLIENT_ID", "WIKI_OIDC_CLIENT_SECRET",
    "WIKI_OIDC_REDIRECT_URI", "WIKI_OIDC_SESSION_KEY", "WIKI_ADMIN_USERS",
    "WIKI_AUTH_ADMIN_TOKEN",
]


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    """每个用例都在「无 OIDC 环境变量」的干净环境下运行。"""
    for k in _OIDC_ENV:
        monkeypatch.delenv(k, raising=False)


def make_client(**over) -> OidcClient:
    cfg = {
        "issuer": "http://auth.example.com/realms/test",
        "client_id": "wiki-portal",
        "client_secret": "s3cret",
        "redirect_uri": "http://wiki.example.com/ext/oauth/callback",
        "session_key": "test-session-key-0123456789",
    }
    cfg.update(over)
    return OidcClient(cfg)


# ══════════════════════════════════════════════════════════════════════════════
# 启用判定
# ══════════════════════════════════════════════════════════════════════════════

class TestEnabled:
    def test_all_config_present_enables(self):
        assert make_client().enabled is True

    @pytest.mark.parametrize("missing", ["issuer", "client_id", "session_key"])
    def test_missing_required_disables(self, missing):
        """缺任何一项都不启用（fail-closed，不半开）。"""
        assert make_client(**{missing: ""}).enabled is False

    def test_client_secret_optional(self):
        """client_secret 缺失不影响启用（public client 场景）。"""
        assert make_client(client_secret="").enabled is True


# ══════════════════════════════════════════════════════════════════════════════
# 会话 cookie
# ══════════════════════════════════════════════════════════════════════════════

class TestSession:
    def test_roundtrip(self):
        c = make_client()
        u = OidcUser(username="niukunliang", name="牛昆亮",
                     email="niu@x.com", phone="13933167152", sub="abc", exp=0)
        got = c.read_session(c.make_session(u))
        assert got is not None
        assert got.username == "niukunliang"
        assert got.name == "牛昆亮"
        assert got.phone == "13933167152"

    def test_tampered_signature_rejected(self):
        """⭐ 篡改签名必须被拒（否则可伪造任意用户）。"""
        c = make_client()
        cookie = c.make_session(OidcUser("niu", None, None, None, "s", 0))
        body, _ = cookie.rsplit(".", 1)
        assert c.read_session(f"{body}.forged-signature") is None

    def test_tampered_body_rejected(self):
        """⭐ 篡改内容（改成管理员）必须被拒。"""
        c = make_client()
        cookie = c.make_session(OidcUser("niu", None, None, None, "s", 0))
        _, sig = cookie.rsplit(".", 1)
        evil = base64.urlsafe_b64encode(json.dumps({
            "u": "attacker", "x": int(time.time()) + 9999,
        }).encode()).decode().rstrip("=")
        assert c.read_session(f"{evil}.{sig}") is None

    def test_different_key_rejected(self):
        """用别的密钥签的 cookie 必须被拒。"""
        a, b = make_client(), make_client(session_key="other-key-9999999999")
        cookie = a.make_session(OidcUser("niu", None, None, None, "s", 0))
        assert b.read_session(cookie) is None

    def test_expired_rejected(self):
        """过期会话必须被拒。"""
        c = make_client()
        # 手工构造一个已过期的会话
        body = base64.urlsafe_b64encode(json.dumps({
            "u": "niu", "x": int(time.time()) - 10,
        }).encode()).decode().rstrip("=")
        assert c.read_session(f"{body}.{c._sign(body)}") is None

    @pytest.mark.parametrize("bad", [None, "", "no-dot", ".", "abc.", ".def"])
    def test_malformed_rejected(self, bad):
        """⭐ fail-closed：任何畸形输入都返回 None，绝不抛异常。"""
        assert make_client().read_session(bad) is None


# ══════════════════════════════════════════════════════════════════════════════
# state cookie（CSRF 防护 + PKCE）
# ══════════════════════════════════════════════════════════════════════════════

class TestState:
    def test_roundtrip(self):
        c = make_client()
        body = base64.urlsafe_b64encode(json.dumps({
            "s": "the-state", "v": "the-verifier", "t": int(time.time()),
        }).encode()).decode().rstrip("=")
        got = c.read_state(f"{body}.{c._sign(body)}")
        assert got is not None
        assert got["s"] == "the-state"
        assert got["v"] == "the-verifier"

    def test_tampered_rejected(self):
        c = make_client()
        body = base64.urlsafe_b64encode(json.dumps({
            "s": "x", "v": "y", "t": int(time.time()),
        }).encode()).decode().rstrip("=")
        assert c.read_state(f"{body}.bad") is None

    def test_stale_rejected(self):
        """state cookie 超过 10 分钟必须失效。"""
        c = make_client()
        body = base64.urlsafe_b64encode(json.dumps({
            "s": "x", "v": "y", "t": int(time.time()) - 700,
        }).encode()).decode().rstrip("=")
        assert c.read_state(f"{body}.{c._sign(body)}") is None

    @pytest.mark.parametrize("bad", [None, "", "nodot"])
    def test_malformed_rejected(self, bad):
        assert make_client().read_state(bad) is None


# ══════════════════════════════════════════════════════════════════════════════
# 登录 URL 构造
# ══════════════════════════════════════════════════════════════════════════════

class TestLoginUrl:
    @pytest.mark.asyncio
    async def test_build_login_url_contains_pkce_and_state(self, monkeypatch):
        """⭐ 必须带 state + PKCE(S256) —— 缺一则安全性下降。"""
        c = make_client()

        async def fake_discovery():
            return {"authorization_endpoint": "http://auth.example.com/auth"}
        monkeypatch.setattr(c, "discovery", fake_discovery)

        url, state, state_cookie = await c.build_login_url()
        assert "code_challenge=" in url
        assert "code_challenge_method=S256" in url
        assert f"state={state}" in url
        assert "client_id=wiki-portal" in url
        # state cookie 里应含 verifier
        st = c.read_state(state_cookie)
        assert st is not None and st["s"] == state and st["v"]

    @pytest.mark.asyncio
    async def test_scope_requests_phone(self, monkeypatch):
        """⭐ scope 必须含 phone —— 否则 token 里没有手机号。"""
        c = make_client()

        async def fake_discovery():
            return {"authorization_endpoint": "http://auth.example.com/auth"}
        monkeypatch.setattr(c, "discovery", fake_discovery)

        url, _, _ = await c.build_login_url()
        assert "phone" in url


# ══════════════════════════════════════════════════════════════════════════════
# 管理 API 的 Cookie 认证路径
# ══════════════════════════════════════════════════════════════════════════════

class TestAdminAuthWithOidc:
    def test_session_identity_and_admin_flag(self):
        from wiki_auth.admin_auth import AdminAuth

        class FakeStore:
            async def connect(self): ...
        oidc = make_client()
        a = AdminAuth(FakeStore(), oidc=oidc)

        user = OidcUser("niukunliang", "牛昆亮", "x@y.com", "139", "sub1", 0)
        ident, is_admin = a.identity_from_session(user)
        assert ident.consumer_id == "niukunliang"
        assert ident.username == "niukunliang"
        assert ident.source == "oidc"
        # WIKI_ADMIN_USERS 未配 → 不是管理员（fail-closed）
        assert is_admin is False

    def test_admin_users_list(self, monkeypatch):
        from wiki_auth.admin_auth import AdminAuth

        class FakeStore: ...
        a = AdminAuth(FakeStore(), oidc=make_client(),
                      admin_users="niukunliang, other.user")

        assert a._is_admin_user("niukunliang") is True
        assert a._is_admin_user("NIUKUNLIANG") is True   # 大小写不敏感
        assert a._is_admin_user("other.user") is True
        assert a._is_admin_user("attacker") is False
        assert a._is_admin_user(None) is False
        assert a._is_admin_user("") is False

    def test_admin_users_substring_not_matched(self, monkeypatch):
        """⭐ 前缀/子串不能误判为管理员。"""
        from wiki_auth.admin_auth import AdminAuth

        class FakeStore: ...
        a = AdminAuth(FakeStore(), oidc=make_client(), admin_users="niu")
        assert a._is_admin_user("niu") is True
        assert a._is_admin_user("niukunliang") is False   # 不是子串匹配

    def test_admin_by_role_wiki_admin(self):
        """⭐ 角色判断：wiki-admin 角色 → 管理员（标准授权）。"""
        from wiki_auth.admin_auth import AdminAuth

        class FakeStore: ...
        # 名单为空 → 只有角色能判为管理员
        a = AdminAuth(FakeStore(), oidc=make_client(), admin_users="")
        assert a._is_admin_user("niukunliang", roles=["wiki-admin", "infra-admin"]) is True
        assert a._is_admin_user("suhuhu", roles=["infra-admin"]) is False
        assert a._is_admin_user("zhaolei", roles=[]) is False
        assert a._is_admin_user("someone", roles=None) is False

    def test_role_priority_over_list(self):
        """⭐ 角色优先于名单：有角色时不再依赖名单。"""
        from wiki_auth.admin_auth import AdminAuth

        class FakeStore: ...
        # 名单里没有 niukunliang，但角色有 wiki-admin → 仍是管理员
        a = AdminAuth(FakeStore(), oidc=make_client(), admin_users="other.user")
        assert a._is_admin_user("niukunliang", roles=["wiki-admin"]) is True
        # 名单有 other.user，但角色无 wiki-admin → 仍按名单放行（兼容回退）
        assert a._is_admin_user("other.user", roles=[]) is True

    def test_oidc_user_roles_in_session(self):
        """⭐ 会话里角色字段的读写一致。"""
        user = OidcUser("niukunliang", "牛昆亮", "x@y.com", "139", "sub1", 0,
                        roles=["wiki-admin"])
        assert user.roles == ["wiki-admin"]
        assert user.to_dict()["roles"] == ["wiki-admin"]

    def test_identity_from_session_uses_role(self):
        """⭐ identity_from_session 用角色判定管理员。"""
        from wiki_auth.admin_auth import AdminAuth

        class FakeStore: ...
        a = AdminAuth(FakeStore(), oidc=make_client(), admin_users="")
        user = OidcUser("niukunliang", "牛昆亮", "x@y.com", "139", "sub1", 0,
                        roles=["wiki-admin"])
        ident, is_admin = a.identity_from_session(user)
        assert ident.consumer_id == "niukunliang"
        assert is_admin is True


# ══════════════════════════════════════════════════════════════════════════════
# 常量
# ══════════════════════════════════════════════════════════════════════════════

def test_cookie_names():
    assert SESSION_COOKIE == "wiki_session"
    assert STATE_COOKIE == "wiki_oauth_state"
