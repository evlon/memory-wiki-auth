"""
身份别名测试 —— OIDC username 与 HiMarket consumer 归并为同一人

═══════════════════════════════════════════════════════════════════════════════
为什么需要这组测试
═══════════════════════════════════════════════════════════════════════════════

同一个人有**两种身份表示**：

    路径              身份字符串                     来源
    ────────────────  ─────────────────────────────  ──────────────────
    管理台（OIDC）     zhaolei                        Keycloak username
    MCP（apikey）      consumer-a8238936cb1147...     HiMarket consumer

授权表 `dim_grant.consumer_id` 只能存一个值 → 若不做归并，
"用 A 授权、用 B 登录"就查不到，功能看起来像坏了。

⚠️ 本文件重点验证**不扩大权限**：
   别名只把「同一个人」的两种写法归并，绝不让不同人互相看到对方的授权。
"""

from __future__ import annotations

import pytest

from wiki_auth.store import DimAccess
from wiki_auth.validator import DimAuthValidator

from test_validator import CONSUMER_A, CONSUMER_B, FakeStore


@pytest.fixture
def store():
    return FakeStore()


def make_validator(store) -> DimAuthValidator:
    return DimAuthValidator({"schema": "wiki_auth", "enforce": True, "cache_ttl": "30"})


# ══════════════════════════════════════════════════════════════════════════════
# resolve_aliases 语义
# ══════════════════════════════════════════════════════════════════════════════

class TestResolveAliases:
    @pytest.mark.asyncio
    async def test_self_always_included(self, store):
        """⭐ 恒等：查任何身份，结果必须含自身（否则会误判为无授权）。"""
        store.link_identity("zhaolei", "consumer-aaa")
        aliases = await store.resolve_aliases("zhaolei")
        assert "zhaolei" in aliases

    @pytest.mark.asyncio
    async def test_unknown_identity_returns_self(self, store):
        """未登记的身份 → 至少返回自身，不返回空。"""
        assert await store.resolve_aliases("nobody") == ["nobody"]

    @pytest.mark.asyncio
    async def test_empty_returns_empty(self, store):
        """空身份 → 空（调用方据此判定"未认证"）。"""
        assert await store.resolve_aliases("") == []

    @pytest.mark.asyncio
    async def test_bidirectional(self, store):
        """别名双向：从任一端都能查到另一端。"""
        store.link_identity("zhaolei", "consumer-aaa")
        assert "consumer-aaa" in await store.resolve_aliases("zhaolei")
        assert "zhaolei" in await store.resolve_aliases("consumer-aaa")

    @pytest.mark.asyncio
    async def test_multiple_consumers_same_user(self, store):
        """一人多个 consumer（如主账号 + 系统账号）都归到同一组。"""
        store.link_identity("niukunliang", "consumer-a823")
        store.link_identity("niukunliang", "consumer-5031")
        aliases = await store.resolve_aliases("niukunliang")
        assert {"niukunliang", "consumer-a823", "consumer-5031"} <= set(aliases)


# ══════════════════════════════════════════════════════════════════════════════
# 授权查询经别名展开
# ══════════════════════════════════════════════════════════════════════════════

class TestAccessViaAlias:
    @pytest.mark.asyncio
    async def test_grant_by_consumer_visible_via_username(self, store):
        """
        ⭐ 核心场景：授权存的是 consumer，用 username 登录也要能看到。
        """
        store.link_identity("zhaolei", "consumer-aaa")
        store.grant("consumer-aaa", "product-p1", "product-p1", "team-kb", "write")

        access = await store.load_access("zhaolei")
        assert [a.dim_id for a in access] == ["product-p1"]

    @pytest.mark.asyncio
    async def test_grant_by_username_visible_via_consumer(self, store):
        """反向：授权存的是 username，用 consumer 也要能看到。"""
        store.link_identity("zhaolei", "consumer-aaa")
        store.grant("zhaolei", "product-p1", "product-p1", "team-kb", "read")

        access = await store.load_access("consumer-aaa")
        assert [a.dim_id for a in access] == ["product-p1"]

    @pytest.mark.asyncio
    async def test_project_expansion_across_alias(self, store):
        """
        ⭐ 项目展开也要跨别名生效：
           授权存在 username 上，项目关联在产品维度上，展开后能拿到产品。
        """
        store.link_identity("liuliye", "consumer-ll")
        store.grant("liuliye", "project-prj1", "project-prj1", "team-kb", "read")
        store.grant("liuliye", "product-p1", "product-p1", "team-kb", "read")
        store.grant("liuliye", "product-p2", "product-p2", "team-kb", "read")
        store.add_project_member("project-prj1", ["product-p1", "product-p2"])

        access = await store.load_access("consumer-ll")
        dims = {a.dim_id for a in access}
        assert {"project-prj1", "product-p1", "product-p2"} <= dims


# ══════════════════════════════════════════════════════════════════════════════
# ⚠️ 安全：别名绝不扩大权限
# ══════════════════════════════════════════════════════════════════════════════

class TestAliasDoesNotLeak:
    @pytest.mark.asyncio
    async def test_unrelated_identity_gets_nothing(self, store):
        """⭐ 未登记的第三方身份，拿不到任何授权。"""
        store.link_identity("zhaolei", "consumer-aaa")
        store.grant("consumer-aaa", "product-p1", "product-p1", "team-kb", "write")

        assert await store.load_access("attacker") == []

    @pytest.mark.asyncio
    async def test_two_users_not_merged(self, store):
        """⭐ 两个不同的人各有别名，不能互相看到。"""
        store.link_identity("zhaolei", "consumer-aaa")
        store.link_identity("liuliye", "consumer-bbb")
        store.grant("consumer-aaa", "product-p1", "product-p1", "team-kb", "write")
        store.grant("consumer-bbb", "tech-ops", "tech-ops", "team-kb", "write")

        a_dims = {x.dim_id for x in await store.load_access("zhaolei")}
        b_dims = {x.dim_id for x in await store.load_access("liuliye")}
        assert a_dims == {"product-p1"}
        assert b_dims == {"tech-ops"}
        assert not (a_dims & b_dims)

    @pytest.mark.asyncio
    async def test_substring_alias_not_matched(self, store):
        """
        ⭐ 别名必须**精确相等**，不能前缀/子串匹配。
           （否则 'niu' 会命中 'niukunliang'，等于越权）
        """
        store.link_identity("niukunliang", "consumer-niu")
        store.grant("consumer-niu", "product-p1", "product-p1", "team-kb", "write")

        # 'niu' 不是 'niukunliang' 的别名 → 什么都拿不到
        assert await store.load_access("niu") == []

    @pytest.mark.asyncio
    async def test_alias_does_not_widen_permission(self, store):
        """别名只影响"看到哪些维度"，不影响权限强度。"""
        store.link_identity("zhaolei", "consumer-aaa")
        store.grant("consumer-aaa", "product-p1", "product-p1", "team-kb", "read")

        access = await store.load_access("zhaolei")
        assert access[0].permission == "read"   # 不是 write
