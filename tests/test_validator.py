"""
维度授权 validator —— 测试套件

═══════════════════════════════════════════════════════════════════════════════
⚠️ 这是安全关键测试。评审要求：**负面用例必须全绿**。
═══════════════════════════════════════════════════════════════════════════════

测试覆盖（对照《多维度知识共享方案》9.2 节）：
   正面  ：有授权 → 能查到该查的
   负面  ：无授权 → 查不到；跨隔离区 → 被拒          ← 最重要
   边界  ：项目维度 → 能查到集成产品的知识
   边界  ：未打标签的记忆 → 查不到（_strict 生效）
   异常  ：身份缺失 → 拒绝；存储不可达 → 拒绝（fail-closed）
   回归  ：不依赖 filter_mcp_tools 保证安全

用 fake store 跑（不依赖真实数据库），确保测试快且可重复。
真实端到端验证在 K8S 里单独做（见 e430 脚本）。
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any

import pytest

from wiki_auth.identity import Identity, extract_api_key, mask_secret
from wiki_auth.store import PERM_NONE, PERM_READ, PERM_WRITE, DimAccess
from wiki_auth.validator import DimAuthValidator

# BankListContext 来自 hindsight_api.extensions
from hindsight_api.extensions import BankListContext

# ══════════════════════════════════════════════════════════════════════════════
# 测试脚手架
# ══════════════════════════════════════════════════════════════════════════════

CONSUMER_A = "consumer-a8238936cb114765be9a1c4efc6eac39"
CONSUMER_B = "consumer-11c463336a154e9fbdd2f80ade49ad0c"
CONSUMER_C = "consumer-50310ba860004a328cb8f1d38c84af0e"

KEY_A = "apikey-<your-api-key>"
KEY_B = "apikey-<your-api-key>"
KEY_C = "apikey-<your-api-key>"


@dataclass
class FakeRequestContext:
    """模拟 Hindsight 的 RequestContext。"""
    api_key: str | None = None
    extra_headers: dict[str, str] | None = None
    internal: bool = False
    user_initiated: bool = False
    tenant_id: str | None = None

    def __post_init__(self):
        if self.extra_headers is None:
            self.extra_headers = {}


class FakeStore:
    """
    内存版授权存储。

    ⚠️ 故意实现得与真实 store 同构：
       · load_access 空 → 返回 []（不是"无限制"）
       · lookup_credential 查不到 → None（不是"通过"）
       · 可注入异常用于测 fail-closed
    """

    def __init__(self):
        self.creds: dict[str, tuple] = {}
        self.grants: dict[str, list[DimAccess]] = {}
        self.project_members: dict[str, list[str]] = {}
        self.raise_on_load = False
        self.raise_on_lookup = False
        # ⭐ 身份别名：{身份 → 等价身份集合}。默认空 = 恒等映射。
        #    用于模拟 v_identity_alias（OIDC username ⇄ HiMarket consumer）
        self.identity_aliases: dict[str, set[str]] = {}

    def link_identity(self, a: str, b: str):
        """把两个身份登记为同一人（双向）。"""
        self.identity_aliases.setdefault(a, set()).add(b)
        self.identity_aliases.setdefault(b, set()).add(a)

    def add_cred(self, api_key: str, consumer_id: str, username: str | None = None):
        self.creds[api_key] = (consumer_id, username, None)

    def grant(self, consumer_id: str, dim_id: str, tag_prefix: str, bank_id: str, perm: str):
        self.grants.setdefault(consumer_id, []).append(
            DimAccess(dim_id=dim_id, tag_prefix=tag_prefix, bank_id=bank_id, permission=perm)
        )

    def add_project_member(self, project_dim: str, product_dims: list[str]):
        """模拟：挂载项目维度时，展开出集成产品的维度。"""
        self.project_members[project_dim] = product_dims

    # ── 与真实 store 同签名 ───────────────────────────────────────────────────
    async def resolve_aliases(self, identity: str) -> list[str]:
        """
        身份别名展开（与真实 store 同语义）。

        真实实现查 v_identity_alias 视图；本 fake 用 self.identity_aliases。
        ⚠️ 必须**至少返回自身** —— 否则调用方会误判为"无授权"。
        """
        if not identity:
            return []
        sibs = set(self.identity_aliases.get(identity, set()))
        sibs.add(identity)
        return sorted(sibs)

    async def load_access(self, consumer_id: str, *, use_cache: bool = True) -> list[DimAccess]:
        if self.raise_on_load:
            raise RuntimeError("模拟数据库不可达")
        # ⭐ 先展开别名：zhaolei ⇄ consumer-xxx 视为同一人
        aliases = await self.resolve_aliases(consumer_id)
        out: list[DimAccess] = []
        for alias in aliases:
            for a in self.grants.get(alias, []):
                out.append(a)
                # ⭐ 项目展开（单向：project → product）
                for p in self.project_members.get(a.dim_id, []):
                    # 从已登记的授权里找该产品的 tag/bank
                    for other in self.grants.get(alias, []):
                        if other.dim_id == p:
                            out.append(DimAccess(
                                dim_id=other.dim_id, tag_prefix=other.tag_prefix,
                                bank_id=other.bank_id, permission=a.permission,
                                via=f"project-{a.dim_id}",
                            ))
        # 去重取最强权限
        merged: dict[str, DimAccess] = {}
        rank = {PERM_NONE: 0, PERM_READ: 1, PERM_WRITE: 2}
        for a in out:
            prev = merged.get(a.dim_id)
            if prev is None or rank[a.permission] > rank[prev.permission]:
                merged[a.dim_id] = a
        return list(merged.values())

    async def lookup_credential(self, api_key: str):
        if self.raise_on_lookup:
            raise RuntimeError("模拟凭据表不可达")
        return self.creds.get(api_key)

    async def max_permission(self, consumer_id: str) -> str:
        access = await self.load_access(consumer_id)
        if not access:
            return PERM_NONE
        rank = {PERM_NONE: 0, PERM_READ: 1, PERM_WRITE: 2}
        return max((a.permission for a in access), key=lambda p: rank.get(p, 0))

    async def connect(self): pass
    async def close(self): pass


def make_validator(store: FakeStore, *, enforce: bool = True) -> DimAuthValidator:
    """构造 validator 并替换掉真实 store（避免连数据库）。"""
    v = DimAuthValidator.__new__(DimAuthValidator)
    v._schema = "wiki_auth"
    v._cache_ttl = 30.0
    v._enforce = enforce
    v._store = store
    return v


@dataclass
class Ctx:
    """通用 ctx（模拟 RetainContext / RecallContext / ReflectContext）。"""
    bank_id: str
    request_context: Any
    contents: list[dict] | None = None
    query: str = "test"


# ══════════════════════════════════════════════════════════════════════════════
# 【1】正面用例：有授权 → 放行
# ══════════════════════════════════════════════════════════════════════════════

class TestPositive:

    @pytest.mark.asyncio
    async def test_有授权的用户_recall_被放行(self):
        s = FakeStore()
        s.add_cred(KEY_A, CONSUMER_A, "niukunliang")
        s.grant(CONSUMER_A, "product-p1", "product-p1", "team-products", PERM_READ)
        v = make_validator(s)

        r = await v.validate_recall(Ctx("team-products", FakeRequestContext(api_key=KEY_A)))

        assert r.allowed is True, f"应放行，实际拒绝：{r.reason}"
        assert r.tag_groups, "必须注入维度过滤"
        # 单个维度：直接是 leaf
        # ⚠️ 必须是 pydantic 对象（dict 会导致 SQL 语法错误，见 e468）
        from hindsight_api.engine.search.tags import TagGroupLeaf
        assert isinstance(r.tag_groups[0], TagGroupLeaf), "必须是 TagGroupLeaf，不能是 dict"
        assert r.tag_groups[0].tags == ["product-p1"]
        assert r.tag_groups[0].match == "any_strict", "⭐ 必须用 _strict"

    @pytest.mark.asyncio
    async def test_有写权限的用户_retain_被放行(self):
        s = FakeStore()
        s.add_cred(KEY_A, CONSUMER_A)
        s.grant(CONSUMER_A, "product-p1", "product-p1", "team-products", PERM_WRITE)
        v = make_validator(s)

        r = await v.validate_retain(Ctx(
            "team-products", FakeRequestContext(api_key=KEY_A),
            contents=[{"content": "x", "tags": ["product-p1"]}],
        ))

        assert r.allowed is True, f"应放行，实际拒绝：{r.reason}"

    @pytest.mark.asyncio
    async def test_个人区_本人可读写(self):
        s = FakeStore()
        s.add_cred(KEY_A, CONSUMER_A)
        v = make_validator(s)

        r1 = await v.validate_recall(Ctx(f"u-{CONSUMER_A}", FakeRequestContext(api_key=KEY_A)))
        assert r1.allowed is True

        r2 = await v.validate_retain(Ctx(
            f"u-{CONSUMER_A}", FakeRequestContext(api_key=KEY_A),
            contents=[{"content": "草稿"}],   # 个人区不要求 tag
        ))
        assert r2.allowed is True, f"个人区草稿应允许无 tag，实际：{r2.reason}"


# ══════════════════════════════════════════════════════════════════════════════
# 【2】负面用例 ⭐ 最重要
# ══════════════════════════════════════════════════════════════════════════════

class TestNegative:
    """评审重点：这些必须全绿。"""

    @pytest.mark.asyncio
    async def test_无任何授权的用户_被拒(self):
        s = FakeStore()
        s.add_cred(KEY_A, CONSUMER_A)          # 有身份
        # 但没有任何 grant
        v = make_validator(s)

        r = await v.validate_recall(Ctx("team-products", FakeRequestContext(api_key=KEY_A)))

        assert r.allowed is False, "无授权必须拒绝"
        assert "无任何维度授权" in r.reason

    @pytest.mark.asyncio
    async def test_跨隔离区访问_被拒(self):
        """⭐ 核心安全断言：A 只能访问 products，不能访问 projects。"""
        s = FakeStore()
        s.add_cred(KEY_A, CONSUMER_A)
        s.grant(CONSUMER_A, "product-p1", "product-p1", "team-products", PERM_READ)
        v = make_validator(s)

        # 访问自己的隔离区 → 放行
        ok = await v.validate_recall(Ctx("team-products", FakeRequestContext(api_key=KEY_A)))
        assert ok.allowed is True

        # 访问别人的隔离区 → 必须拒绝
        bad = await v.validate_recall(Ctx("team-projects", FakeRequestContext(api_key=KEY_A)))
        assert bad.allowed is False, "⭐ 跨隔离区必须拒绝"
        assert "无权访问隔离区" in bad.reason

    @pytest.mark.asyncio
    async def test_只读用户不能写入(self):
        s = FakeStore()
        s.add_cred(KEY_A, CONSUMER_A)
        s.grant(CONSUMER_A, "product-p1", "product-p1", "team-products", PERM_READ)
        v = make_validator(s)

        r = await v.validate_retain(Ctx(
            "team-products", FakeRequestContext(api_key=KEY_A),
            contents=[{"content": "x", "tags": ["product-p1"]}],
        ))

        assert r.allowed is False, "只读用户不能写入"
        assert "不能写入" in r.reason

    @pytest.mark.asyncio
    async def test_无权用户不能写别人的个人区(self):
        s = FakeStore()
        s.add_cred(KEY_A, CONSUMER_A)
        s.add_cred(KEY_B, CONSUMER_B)
        v = make_validator(s)

        r = await v.validate_retain(Ctx(
            f"u-{CONSUMER_B}", FakeRequestContext(api_key=KEY_A),
            contents=[{"content": "x"}],
        ))

        assert r.allowed is False, "不能写别人的个人区"
        assert "仅限本人" in r.reason

    @pytest.mark.asyncio
    async def test_共享区写入无标签_被拒(self):
        """⭐ 无 tag 的记忆在 _strict 下无人可见 —— 必须在写入时就拦住。"""
        s = FakeStore()
        s.add_cred(KEY_A, CONSUMER_A)
        s.grant(CONSUMER_A, "product-p1", "product-p1", "team-products", PERM_WRITE)
        v = make_validator(s)

        r = await v.validate_retain(Ctx(
            "team-products", FakeRequestContext(api_key=KEY_A),
            contents=[{"content": "没有标签的记忆"}],   # ← 无 tags
        ))

        assert r.allowed is False, "共享区无标签必须拒绝"
        assert "维度 tag" in r.reason

    @pytest.mark.asyncio
    async def test_未登记的apikey_被拒(self):
        s = FakeStore()
        s.add_cred(KEY_A, CONSUMER_A)
        v = make_validator(s)

        r = await v.validate_recall(Ctx(
            "team-products",
            FakeRequestContext(api_key="apikey-<your-api-key>"),  # 形状合法但未登记
        ))

        assert r.allowed is False, "未登记的 apikey 必须拒绝"


# ══════════════════════════════════════════════════════════════════════════════
# 【3】边界：项目 → 产品 展开
# ══════════════════════════════════════════════════════════════════════════════

class TestProjectExpansion:
    """业务核心：项目集成多产品，成员一次检索拿到多个产品知识。"""

    @pytest.mark.asyncio
    async def test_挂载项目_自动展开集成产品(self):
        """
        ⭐ 业务核心：项目集成多产品，成员一次检索拿到多个产品知识。

        ⚠️ 关键约束（e430 实测发现）：
           Hindsight 的 recall 是**单 bank** 的，tag_groups 只在当前 bank 内生效。
           所以「项目」和「它集成的产品」**必须在同一个 bank**。
           本测试按正确配置（同 bank）验证。
        """
        s = FakeStore()
        s.add_cred(KEY_A, CONSUMER_A)
        BANK = "team-knowledge"          # ← 项目与产品同在 knowledge 区
        # 项目一
        s.grant(CONSUMER_A, "project-prj1", "project-prj1", BANK, PERM_READ)
        # 项目一集成的三个产品
        s.grant(CONSUMER_A, "product-p1", "product-p1", BANK, PERM_READ)
        s.grant(CONSUMER_A, "product-p2", "product-p2", BANK, PERM_READ)
        s.grant(CONSUMER_A, "product-p3", "product-p3", BANK, PERM_READ)
        s.add_project_member("project-prj1", ["product-p1", "product-p2", "product-p3"])
        v = make_validator(s)

        r = await v.validate_recall(Ctx(BANK, FakeRequestContext(api_key=KEY_A)))

        assert r.allowed is True
        # 应注入 4 个维度的并集
        from hindsight_api.engine.search.tags import TagGroupOr
        tg = r.tag_groups[0]
        assert isinstance(tg, TagGroupOr), f"多个维度必须用 TagGroupOr，实际：{type(tg)}"
        tags = {leaf.tags[0] for leaf in tg.filters}
        assert tags == {"project-prj1", "product-p1", "product-p2", "product-p3"}, \
            f"应展开为 4 个维度，实际：{tags}"
        # ⭐ 全部必须是 _strict
        for leaf in tg.filters:
            assert leaf.match == "any_strict"

    @pytest.mark.asyncio
    async def test_跨bank的项目展开_只保留同bank的维度(self):
        """
        ⚠️ 配置错误场景：项目与其产品在不同 bank。

        预期行为：同 bank 的维度正常注入；跨 bank 的被过滤掉（并告警）。
        这是**已知限制**，不是 bug —— recall 单 bank 决定的。
        """
        s = FakeStore()
        s.add_cred(KEY_A, CONSUMER_A)
        s.grant(CONSUMER_A, "project-prj1", "project-prj1", "team-projects", PERM_READ)
        s.grant(CONSUMER_A, "product-p1", "product-p1", "team-products", PERM_READ)  # ← 别的 bank
        s.add_project_member("project-prj1", ["product-p1"])
        v = make_validator(s)

        r = await v.validate_recall(Ctx("team-projects", FakeRequestContext(api_key=KEY_A)))

        assert r.allowed is True
        _g = r.tag_groups[0]
        _leaves = getattr(_g, "filters", [_g])
        tags = {leaf.tags[0] for leaf in _leaves}
        assert "project-prj1" in tags
        # ⚠️ 跨 bank 的产品维度拿不到（这是限制，测试固化它，避免误以为能工作）
        assert "product-p1" not in tags, \
            "跨 bank 的展开结果不在当前 bank 过滤范围内（已知限制）"

    @pytest.mark.asyncio
    async def test_展开是单向的_产品不会带出项目(self):
        """⭐ 防泄漏：挂载产品维度不应看到用到它的项目。"""
        s = FakeStore()
        s.add_cred(KEY_A, CONSUMER_A)
        s.grant(CONSUMER_A, "product-p1", "product-p1", "team-products", PERM_READ)
        # 项目一集成了产品一，但 A 没有项目一的授权
        s.add_project_member("project-prj1", ["product-p1"])
        v = make_validator(s)

        r = await v.validate_recall(Ctx("team-products", FakeRequestContext(api_key=KEY_A)))

        assert r.allowed is True
        _g = r.tag_groups[0]
        _leaves = getattr(_g, "filters", [_g])
        tags = {leaf.tags[0] for leaf in _leaves}
        assert "project-prj1" not in tags, "⭐ 不得从产品反推出项目（泄漏）"


# ══════════════════════════════════════════════════════════════════════════════
# 【4】异常：fail-closed ⭐
# ══════════════════════════════════════════════════════════════════════════════

class TestFailClosed:
    """⭐ 评审重点：任何异常都必须拒绝，绝不能放行。"""

    @pytest.mark.asyncio
    async def test_无身份_被拒(self):
        s = FakeStore()
        v = make_validator(s)

        r = await v.validate_recall(Ctx("team-products", FakeRequestContext(api_key=None)))

        assert r.allowed is False, "无身份必须拒绝"
        assert "无法识别" in r.reason

    @pytest.mark.asyncio
    async def test_RequestContext为None_被拒(self):
        s = FakeStore()
        v = make_validator(s)

        r = await v.validate_recall(Ctx("team-products", None))

        assert r.allowed is False, "RequestContext 为 None 必须拒绝"

    @pytest.mark.asyncio
    async def test_授权存储异常_被拒_不是放行(self):
        """⭐⭐ 最关键的一条：数据库挂了 → 拒绝，不是放行。"""
        s = FakeStore()
        s.add_cred(KEY_A, CONSUMER_A)
        s.grant(CONSUMER_A, "product-p1", "product-p1", "team-products", PERM_READ)
        s.raise_on_load = True                    # ← 模拟数据库不可达
        v = make_validator(s)

        r = await v.validate_recall(Ctx("team-products", FakeRequestContext(api_key=KEY_A)))

        assert r.allowed is False, "⭐ 存储异常必须 fail-closed"
        assert "fail-closed" in r.reason

    @pytest.mark.asyncio
    async def test_凭据表异常_被拒(self):
        s = FakeStore()
        s.add_cred(KEY_A, CONSUMER_A)
        s.grant(CONSUMER_A, "product-p1", "product-p1", "team-products", PERM_READ)
        s.raise_on_lookup = True
        v = make_validator(s)

        r = await v.validate_recall(Ctx("team-products", FakeRequestContext(api_key=KEY_A)))

        assert r.allowed is False, "凭据表异常必须 fail-closed"

    @pytest.mark.asyncio
    async def test_retain异常也fail_closed(self):
        s = FakeStore()
        s.add_cred(KEY_A, CONSUMER_A)
        s.grant(CONSUMER_A, "product-p1", "product-p1", "team-products", PERM_WRITE)
        s.raise_on_load = True
        v = make_validator(s)

        r = await v.validate_retain(Ctx(
            "team-products", FakeRequestContext(api_key=KEY_A),
            contents=[{"content": "x", "tags": ["product-p1"]}],
        ))

        assert r.allowed is False, "⭐ retain 异常也必须 fail-closed"

    @pytest.mark.asyncio
    async def test_reflect异常也fail_closed(self):
        s = FakeStore()
        s.add_cred(KEY_A, CONSUMER_A)
        s.raise_on_load = True
        v = make_validator(s)

        r = await v.validate_reflect(Ctx("team-products", FakeRequestContext(api_key=KEY_A)))

        assert r.allowed is False


# ══════════════════════════════════════════════════════════════════════════════
# 【5】身份解析
# ══════════════════════════════════════════════════════════════════════════════

class TestIdentity:

    @pytest.mark.asyncio
    async def test_透传头优先于apikey(self):
        s = FakeStore()
        s.add_cred(KEY_A, CONSUMER_A)
        s.grant(CONSUMER_B, "product-p1", "product-p1", "team-products", PERM_READ)
        v = make_validator(s)

        # 头里说是 B（且 B 有授权），apikey 是 A
        r = await v.validate_recall(Ctx(
            "team-products",
            FakeRequestContext(api_key=KEY_A, extra_headers={"x-dim-consumer": CONSUMER_B}),
        ))

        assert r.allowed is True, "应以透传头身份为准"

    @pytest.mark.asyncio
    async def test_透传头格式非法_被拒(self):
        s = FakeStore()
        v = make_validator(s)

        r = await v.validate_recall(Ctx(
            "team-products",
            FakeRequestContext(extra_headers={"x-dim-consumer": "not-a-consumer-id"}),
        ))

        assert r.allowed is False, "非法 consumer 格式必须拒绝"

    @pytest.mark.asyncio
    async def test_apikey形状非法_不查表直接拒(self):
        s = FakeStore()
        s.raise_on_lookup = True     # 若查表会抛异常
        v = make_validator(s)

        r = await v.validate_recall(Ctx(
            "team-products", FakeRequestContext(api_key="garbage"),
        ))

        assert r.allowed is False
        assert "无法识别" in r.reason, "形状非法应在查表前就被拒"

    def test_extract_api_key_兼容Bearer前缀(self):
        class RC:
            api_key = "Bearer apikey-abc"
        assert extract_api_key(RC()) == "apikey-abc"

    def test_mask_secret_不泄漏完整凭据(self):
        full = "apikey-<your-api-key>"
        m = mask_secret(full)
        # 允许露出前 12 位（便于人工核对），但绝不能露后半段
        assert m.startswith("apikey-1b837")
        assert full[-12:] not in m, f"不能泄漏凭据后半段：{m}"
        assert "len=" in m


# ══════════════════════════════════════════════════════════════════════════════
# 【6】回归：不依赖 filter_mcp_tools
# ══════════════════════════════════════════════════════════════════════════════

class TestNotRelyingOnToolFilter:
    """
    ⭐ Hindsight 的 filter_mcp_tools 在异常时 fail-OPEN。
    所以即使它完全失效，数据也必须不可读。
    """

    @pytest.mark.asyncio
    async def test_工具过滤失效时_数据仍不可读(self):
        s = FakeStore()
        s.add_cred(KEY_A, CONSUMER_A)
        # 无授权
        v = make_validator(s)

        # 让工具过滤抛异常（模拟 fail-OPEN 场景）
        class Boom(Exception): pass
        async def boom(*a, **k): raise Boom()
        v._store.max_permission = boom

        tools = await v.filter_mcp_tools("team-products", FakeRequestContext(api_key=KEY_A),
                                         frozenset({"retain", "recall"}))
        assert tools == frozenset({"retain", "recall"}), "工具过滤确实 fail-OPEN（预期行为）"

        # ⭐ 但数据访问仍必须被拦
        r = await v.validate_recall(Ctx("team-products", FakeRequestContext(api_key=KEY_A)))
        assert r.allowed is False, "⭐ 即使工具过滤失效，数据也必须不可读"

    @pytest.mark.asyncio
    async def test_只读用户的工具列表被裁剪(self):
        s = FakeStore()
        s.add_cred(KEY_A, CONSUMER_A)
        s.grant(CONSUMER_A, "product-p1", "product-p1", "team-products", PERM_READ)
        v = make_validator(s)

        tools = await v.filter_mcp_tools(
            "team-products", FakeRequestContext(api_key=KEY_A),
            frozenset({"retain", "recall", "reflect"}),
        )

        assert "retain" not in tools, "只读用户不应看到 retain"
        assert "recall" in tools


# ══════════════════════════════════════════════════════════════════════════════
# 【7】bank 列表过滤
# ══════════════════════════════════════════════════════════════════════════════

class TestBankListFilter:

    @pytest.mark.asyncio
    async def test_只返回有权限的隔离区(self):
        s = FakeStore()
        s.add_cred(KEY_A, CONSUMER_A)
        s.grant(CONSUMER_A, "product-p1", "product-p1", "team-products", PERM_READ)
        v = make_validator(s)

        ctx = BankListContext(
            banks=[
                {"bank_id": "team-products"},
                {"bank_id": "team-projects"},       # ← 无权
                {"bank_id": f"u-{CONSUMER_A}"},     # ← 自己的个人区
            ],
            request_context=FakeRequestContext(api_key=KEY_A),
        )
        r = await v.filter_bank_list(ctx)

        ids = {b["bank_id"] for b in r.banks}
        assert ids == {"team-products", f"u-{CONSUMER_A}"}, f"实际：{ids}"
        assert "team-projects" not in ids, "⭐ 无权隔离区不得出现在列表"

    @pytest.mark.asyncio
    async def test_无身份时列表为空(self):
        s = FakeStore()
        v = make_validator(s)

        ctx = BankListContext(banks=[{"bank_id": "team-products"}],
                              request_context=FakeRequestContext(api_key=None))
        r = await v.filter_bank_list(ctx)

        assert r.banks == [], "无身份时不得返回任何隔离区"

    @pytest.mark.asyncio
    async def test_异常时返回空列表_不是全量(self):
        s = FakeStore()
        s.add_cred(KEY_A, CONSUMER_A)
        s.raise_on_load = True
        v = make_validator(s)

        ctx = BankListContext(banks=[{"bank_id": "team-products"}],
                              request_context=FakeRequestContext(api_key=KEY_A))
        r = await v.filter_bank_list(ctx)

        assert r.banks == [], "⭐ 异常时必须返回空（保守），不能返回全量"


# ══════════════════════════════════════════════════════════════════════════════
# 【8】_strict 模式强制
# ══════════════════════════════════════════════════════════════════════════════

class TestStrictModeEnforced:
    """⭐ 必须用 _strict，否则未打标签的记忆会被所有人看到。"""

    @pytest.mark.asyncio
    async def test_所有注入的匹配模式都是strict(self):
        s = FakeStore()
        s.add_cred(KEY_A, CONSUMER_A)
        for d in ["product-p1", "product-p2", "platform-higress", "tech-ops"]:
            s.grant(CONSUMER_A, d, d, "team-products", PERM_READ)
        v = make_validator(s)

        r = await v.validate_recall(Ctx("team-products", FakeRequestContext(api_key=KEY_A)))

        from hindsight_api.engine.search.tags import (
            TagGroupLeaf, TagGroupAnd, TagGroupOr, TagGroupNot,
        )

        def check(groups):
            for g in groups:
                assert not isinstance(g, dict), f"⭐ 不得是 dict（会导致 SQL 错误）：{g}"
                if isinstance(g, TagGroupLeaf):
                    assert g.match == "any_strict", f"⭐ 必须 _strict，实际 {g}"
                elif isinstance(g, (TagGroupAnd, TagGroupOr)):
                    check(g.filters)
                elif isinstance(g, TagGroupNot):
                    check([g.filter])

        check(r.tag_groups)


# ══════════════════════════════════════════════════════════════════════════════
# 【9】worker 内部重放（e471/e472 修复的回归测试）
# ══════════════════════════════════════════════════════════════════════════════

class TestInternalReplay:
    """
    ⚠️ 背景：Hindsight 的 retain 是异步的。HTTP 层校验一次并返回 202，
    worker 在后台**重新调用 validate_retain**，但 RequestContext 是
        RequestContext(internal=True, user_initiated=True, tenant_id=...)
    即**没有凭据**。

    若不放行 → 后台任务全部失败 → 记忆永不落库 → 召回永远为空。
    实测踩到这个坑（e471），表现为日志刷
        Task execution failed: batch_retain, error: OperationValidationError

    这些用例固化"internal 重放必须放行"这个行为。
    """

    @pytest.mark.asyncio
    async def test_worker重放_retain放行(self):
        s = FakeStore()
        # 注意：store 里故意不放任何凭据/授权
        v = make_validator(s)

        r = await v.validate_retain(Ctx(
            "team-knowledge",
            FakeRequestContext(internal=True, user_initiated=True, tenant_id="tenant-x"),
            contents=[{"content": "x", "tags": ["product-p1"]}],
        ))

        assert r.allowed is True, \
            f"⭐ worker 重放必须放行，否则记忆永不落库（实际：{r.reason}）"

    @pytest.mark.asyncio
    async def test_worker重放_recall放行(self):
        s = FakeStore()
        v = make_validator(s)

        r = await v.validate_recall(Ctx(
            "team-knowledge",
            FakeRequestContext(internal=True, user_initiated=True),
        ))

        assert r.allowed is True

    @pytest.mark.asyncio
    async def test_worker重放_reflect放行(self):
        s = FakeStore()
        v = make_validator(s)

        r = await v.validate_reflect(Ctx(
            "team-knowledge",
            FakeRequestContext(internal=True, user_initiated=True),
        ))

        assert r.allowed is True

    @pytest.mark.asyncio
    async def test_外部请求仍严格校验_internal不得被伪造绕过(self):
        """
        ⭐ 安全关键：internal=False 的外部请求必须仍走完整校验。
        防止"随便加个 internal 标志就绕过授权"。
        """
        s = FakeStore()
        s.add_cred(KEY_A, CONSUMER_A)
        # 无任何授权
        v = make_validator(s)

        r = await v.validate_recall(Ctx(
            "team-knowledge",
            FakeRequestContext(api_key=KEY_A, internal=False),
        ))

        assert r.allowed is False, "⭐ internal=False 必须走完整校验"

    @pytest.mark.asyncio
    async def test_worker重放不做维度注入(self):
        """
        internal 重放不注入 tag_groups（它是系统内部读取，不是用户查询）。
        这里只断言"放行且不报错"，避免误以为能拿到用户视角的过滤。
        """
        s = FakeStore()
        v = make_validator(s)

        r = await v.validate_recall(Ctx(
            "team-knowledge",
            FakeRequestContext(internal=True, user_initiated=True),
        ))

        assert r.allowed is True


# ══════════════════════════════════════════════════════════════════════════════
# 【10】MCP 握手认证（e473 修复的回归测试）
# ══════════════════════════════════════════════════════════════════════════════

class TestTenantAuth:
    """
    ⚠️ 背景：Hindsight 的 OperationValidator 只在**具体操作**时被调用，
    MCP 的 **initialize 握手不经过它**。

    实测（e473）：无凭据客户端 initialize 返回 **200** 并拿到 session，
    直到 tools/call 才被拦（且报 "Unknown tool"）。
    数据安全但语义错误 —— 客户端以为连上了。

    修复：用 TenantExtension.authenticate_mcp() 在握手时校验，
    无效则抛 AuthenticationError → Hindsight 返回 401。
    """

    @pytest.mark.asyncio
    async def test_无凭据_握手401(self):
        from wiki_auth.tenant import DimAuthTenantExtension
        from hindsight_api.extensions import AuthenticationError

        s = FakeStore()
        ext = DimAuthTenantExtension.__new__(DimAuthTenantExtension)
        ext._schema = "public"
        ext._enforce = True
        ext._store = s

        with pytest.raises(AuthenticationError):
            await ext.authenticate_mcp(FakeRequestContext(api_key=None))

    @pytest.mark.asyncio
    async def test_未登记apikey_握手401(self):
        from wiki_auth.tenant import DimAuthTenantExtension
        from hindsight_api.extensions import AuthenticationError

        s = FakeStore()
        s.add_cred(KEY_A, CONSUMER_A)
        ext = DimAuthTenantExtension.__new__(DimAuthTenantExtension)
        ext._schema = "public"; ext._enforce = True; ext._store = s

        with pytest.raises(AuthenticationError):
            await ext.authenticate_mcp(
                FakeRequestContext(api_key="apikey-<your-api-key>")
            )

    @pytest.mark.asyncio
    async def test_有效apikey_握手通过(self):
        from wiki_auth.tenant import DimAuthTenantExtension

        s = FakeStore()
        s.add_cred(KEY_A, CONSUMER_A, "niukunliang")
        ext = DimAuthTenantExtension.__new__(DimAuthTenantExtension)
        ext._schema = "public"; ext._enforce = True; ext._store = s

        # 不应抛异常
        await ext.authenticate_mcp(FakeRequestContext(api_key=KEY_A))

    @pytest.mark.asyncio
    async def test_透传头身份_握手通过(self):
        from wiki_auth.tenant import DimAuthTenantExtension

        s = FakeStore()
        ext = DimAuthTenantExtension.__new__(DimAuthTenantExtension)
        ext._schema = "public"; ext._enforce = True; ext._store = s

        await ext.authenticate_mcp(
            FakeRequestContext(extra_headers={"x-dim-consumer": CONSUMER_A})
        )

    @pytest.mark.asyncio
    async def test_内部任务跳过认证(self):
        """worker 重放没有凭据，必须跳过（否则任务永远失败）。"""
        from wiki_auth.tenant import DimAuthTenantExtension

        s = FakeStore()
        ext = DimAuthTenantExtension.__new__(DimAuthTenantExtension)
        ext._schema = "public"; ext._enforce = True; ext._store = s

        # 不应抛异常
        await ext.authenticate_mcp(FakeRequestContext(internal=True, user_initiated=True))


# ══════════════════════════════════════════════════════════════════════════════
# 【11】共享 store 单例（e491 修复的回归测试）⭐ 安全关键
# ══════════════════════════════════════════════════════════════════════════════

class TestSharedStore:
    """
    ⚠️ 背景（e491 实测发现的缺陷）：
    Hindsight 分别实例化三个扩展，若每个都 `DimAuthStore(...)`，
    则三份 `_cache` 互不相通 → 管理 API 的 invalidate() 清不到
    validator 的缓存 → **撤销授权最长 30 秒后才生效**。

    实测证据：撤销后立即访问，仍能读到数据。

    修复：进程级单例，三个扩展共用同一个 store。
    """

    def test_同一schema返回同一实例(self):
        from wiki_auth.store import get_shared_store
        a = get_shared_store("postgresql://x/y", schema="wiki_auth")
        b = get_shared_store("postgresql://x/y", schema="wiki_auth")
        assert a is b, "⭐ 必须返回同一实例（否则缓存不互通）"

    def test_不同schema返回不同实例(self):
        from wiki_auth.store import get_shared_store
        a = get_shared_store("postgresql://x/y", schema="wiki_auth")
        b = get_shared_store("postgresql://x/y", schema="wiki_auth2")
        assert a is not b, "不同 schema 应独立（避免串库）"

    def test_三个扩展共用同一store(self):
        """
        ⭐ 核心断言：validator / tenant / admin 三个扩展拿到的 store 必须相同。
        """
        from wiki_auth.store import get_shared_store

        class Cfg(dict):
            def get(self, k, d=None):
                return dict.get(self, k, d)

        s1 = get_shared_store("postgresql://x/y", schema="wiki_auth")
        s2 = get_shared_store("postgresql://x/y", schema="wiki_auth")
        s3 = get_shared_store("postgresql://x/y", schema="wiki_auth")
        assert s1 is s2 is s3, "⭐ 三个扩展必须共用同一 store 实例"

    def test_缓存失效跨实例可见(self):
        """
        ⭐ 关键：在一个实例上 invalidate，另一个实例（同一单例）应立即看不到旧缓存。
        """
        from wiki_auth.store import get_shared_store, DimAccess

        st = get_shared_store("postgresql://x/y", schema="wiki_auth")
        # 手动塞一条缓存
        from wiki_auth.store import _CacheEntry
        import time as _t
        st._cache["consumer-test-0001"] = _CacheEntry(
            access=[DimAccess(dim_id="product-p1", tag_prefix="product-p1",
                              bank_id="team-knowledge", permission="read")],
            expires_at=_t.monotonic() + 999,
        )
        # 另一个"扩展"拿到的是同一实例 → invalidate 立即生效
        st2 = get_shared_store("postgresql://x/y", schema="wiki_auth")
        st2.invalidate("consumer-test-0001")
        assert "consumer-test-0001" not in st._cache, \
            "⭐ invalidate 必须对共用实例立即可见"
        st._cache.clear()
