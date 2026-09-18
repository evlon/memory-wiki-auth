"""
HiMarket 凭据同步测试

⚠️ 重点：解析器必须对**认不出的结构返回 None**（跳过），
   绝不猜测 —— 否则会把错误凭据写进授权表，造成越权或拒绝服务。
"""

from __future__ import annotations

import pytest

from wiki_auth.cred_sync import parse_himarket_apikey, sync_credentials
from test_admin_api import AdminFakeStore


# ══════════════════════════════════════════════════════════════════════════════
# 【1】apikey_config 解析（真实结构 + 边界）
# ══════════════════════════════════════════════════════════════════════════════

class TestParseApikey:

    def test_真实结构_credentials数组(self):
        """HiMarket 实测结构：{"credentials":[{"apiKey":"apikey-..."}]}"""
        cfg = {"credentials": [{"apiKey": "apikey-<your-api-key>"}]}
        assert parse_himarket_apikey(cfg) == "apikey-<your-api-key>"

    def test_单对象写法(self):
        assert parse_himarket_apikey({"apiKey": "apikey-aaaa"}) == "apikey-aaaa"

    def test_纯字符串(self):
        assert parse_himarket_apikey("apikey-bbbb") == "apikey-bbbb"

    def test_credentials为空_返回None(self):
        assert parse_himarket_apikey({"credentials": []}) is None

    def test_结构不认识_返回None_不猜测(self):
        """⭐ 关键：认不出必须返回 None（跳过），不能瞎猜"""
        assert parse_himarket_apikey({"foo": "bar"}) is None
        assert parse_himarket_apikey({"credentials": [{"wrong": "x"}]}) is None
        assert parse_himarket_apikey(None) is None
        assert parse_himarket_apikey(123) is None
        assert parse_himarket_apikey([]) is None

    def test_非apikey前缀_返回None(self):
        """⭐ 不是 apikey- 开头的值不能被当成凭据"""
        assert parse_himarket_apikey("sk-123456") is None
        assert parse_himarket_apikey({"apiKey": "Bearer xxx"}) is None

    def test_取第一个credential(self):
        cfg = {"credentials": [
            {"apiKey": "apikey-first000000000000"},
            {"apiKey": "apikey-second00000000000"},
        ]}
        assert parse_himarket_apikey(cfg) == "apikey-first000000000000"


# ══════════════════════════════════════════════════════════════════════════════
# 【2】批量同步（幂等 + 跳过非法行）
# ══════════════════════════════════════════════════════════════════════════════

class TestSyncCredentials:

    @pytest.mark.asyncio
    async def test_正常同步(self):
        s = AdminFakeStore()
        rows = [
            {"consumer_id": "consumer-a8238936cb114765be9a1c4efc6eac39",
             "developer_id": "dev-9fa771", "username": "corp-sso_niukunliang",
             "apikey_config": {"credentials": [{"apiKey": "apikey-<your-api-key>"}]}},
            {"consumer_id": "consumer-11c463336a154e9fbdd2f80ade49ad0c",
             "username": "corp-sso_douyi",
             "apikey_config": {"credentials": [{"apiKey": "apikey-<your-api-key>"}]}},
        ]
        r = await sync_credentials(s, rows)
        assert r.received == 2
        assert r.upserted == 2
        assert r.skipped == 0
        assert len(s.creds) == 2

    @pytest.mark.asyncio
    async def test_幂等_重复同步不重复插入(self):
        s = AdminFakeStore()
        row = {"consumer_id": "consumer-a8238936cb114765be9a1c4efc6eac39",
               "apikey_config": {"credentials": [{"apiKey": "apikey-<your-api-key>"}]}}
        await sync_credentials(s, [row])
        await sync_credentials(s, [row])
        assert len(s.creds) == 1, "重复同步应幂等"

    @pytest.mark.asyncio
    async def test_非法consumer_id_跳过并记录(self):
        s = AdminFakeStore()
        r = await sync_credentials(s, [
            {"consumer_id": "not-a-consumer", "apikey_config": {"apiKey": "apikey-x"}},
        ])
        assert r.upserted == 0
        assert r.skipped == 1
        assert r.errors and "consumer_id 非法" in r.errors[0]

    @pytest.mark.asyncio
    async def test_无法解析apikey_跳过并记录(self):
        s = AdminFakeStore()
        r = await sync_credentials(s, [
            {"consumer_id": "consumer-a8238936cb114765be9a1c4efc6eac39",
             "apikey_config": {"unknown": "structure"}},
        ])
        assert r.upserted == 0
        assert r.skipped == 1
        assert r.errors and "无法解析 apikey" in r.errors[0]

    @pytest.mark.asyncio
    async def test_部分成功_部分跳过(self):
        s = AdminFakeStore()
        r = await sync_credentials(s, [
            {"consumer_id": "consumer-a8238936cb114765be9a1c4efc6eac39",
             "apikey_config": {"apiKey": "apikey-good0000000000000000"}},
            {"consumer_id": "bad", "apikey_config": {"apiKey": "apikey-x"}},
        ])
        assert r.received == 2
        assert r.upserted == 1
        assert r.skipped == 1

    @pytest.mark.asyncio
    async def test_空列表_不报错(self):
        s = AdminFakeStore()
        r = await sync_credentials(s, [])
        assert r.received == 0 and r.upserted == 0


# ══════════════════════════════════════════════════════════════════════════════
# ⭐ is_primary 解析 —— 安全关键（实测事故：系统账号继承真人授权 → 越权）
# ══════════════════════════════════════════════════════════════════════════════

class TestParseIsPrimary:
    """
    若把系统账号（ai-llm）与真人（牛昆亮）当作同一人，
    系统账号会**继承真人的全部授权** → 越权。

    所以：认不出就当作"非主账号"（宁可少归并，不可多归并）。
    """

    def test_int_1_is_primary(self):
        from wiki_auth.cred_sync import parse_is_primary
        assert parse_is_primary(1) is True

    def test_int_0_not_primary(self):
        from wiki_auth.cred_sync import parse_is_primary
        assert parse_is_primary(0) is False

    def test_none_not_primary(self):
        """⭐ HiMarket 的系统账号 is_primary = NULL → 必须当作非主账号。"""
        from wiki_auth.cred_sync import parse_is_primary
        assert parse_is_primary(None) is False

    @pytest.mark.parametrize("v", [True, "1", "true", "TRUE", "yes"])
    def test_truthy_forms(self, v):
        from wiki_auth.cred_sync import parse_is_primary
        assert parse_is_primary(v) is True

    @pytest.mark.parametrize("v", [False, 2, -1, "", "0", "no", "maybe", [], {}])
    def test_unknown_is_false(self, v):
        """⭐ 认不出的一律 False（fail-safe，不 fail-open）。"""
        from wiki_auth.cred_sync import parse_is_primary
        assert parse_is_primary(v) is False


class TestSyncCarriesIsPrimary:
    """同步时必须把 is_primary 传到 store。"""

    @pytest.mark.asyncio
    async def test_is_primary_passed_through(self):
        calls = []

        class FakeStore:
            async def upsert_credential(self, **kw):
                calls.append(kw)

        rows = [
            {"consumer_id": "consumer-a8238936cb114765be9a1c4efc6eac39",
             "username": "corp-sso_niukunliang", "is_primary": 1,
             "apikey_config": {"credentials": [{"apiKey": "apikey-" + "a" * 32}]}},
            {"consumer_id": "consumer-50310ba860004a328cb8f1d38c84af0e",
             "username": "corp-sso_niukunliang", "is_primary": None,
             "apikey_config": {"credentials": [{"apiKey": "apikey-" + "b" * 32}]}},
        ]
        await sync_credentials(FakeStore(), rows)

        assert len(calls) == 2
        assert calls[0]["is_primary"] is True
        # ⭐ 系统账号：None → False（不参与归并，避免越权）
        assert calls[1]["is_primary"] is False
